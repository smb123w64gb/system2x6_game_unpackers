
# FILE LOAD ADDRESS: 0x1100000
import struct
import argparse
from collections import defaultdict

def ror16(v, n):
    return ((v >> n) | (v << (16 - n))) & 0xFFFF
def rol16(v, n):
    return ((v << n) | (v >> (16 - n))) & 0xFFFF

# keys for main game binary of SoulCalibur3. the dongle/media match crypto validation uses the same encryption but different keys
KEYBUF = (
    struct.pack("<H", 0xEBD7) +
    struct.pack("<H", 0xA21F) +
    struct.pack("<H", 0x000D) +
    b"VersionA\x00"
)

def decrypt_sc3(data):
    size = len(data)
    payload_size = size - 0x0B
    trailer = data[payload_size] | (data[payload_size + 1] << 8)
    key0 = 0xEBD7
    key1 = 0xA21F
    key2 = 0x000D
    state = key0 ^ ror16(trailer, 3)
    checksum = key1
    for i in range(payload_size):
        tmp = data[i] ^ state
        state = ((ror16(state, 1) * 5) + 1) & 0xFFFF
        checksum = (checksum + ((tmp & 0xFF) * key2)) & 0xFFFF

    stored = trailer
    expected = key0 ^ ror16(stored, 3)

    if expected != checksum:
        raise Exception(
            f"checksum mismatch stored={expected:04X} calc={checksum:04X}"
        )

    state = key0 ^ ror16(stored, 3)
    out = bytearray(payload_size)
    for i in range(payload_size):
        out[i] = data[i] ^ (state & 0xFF)
        state = ((ror16(state, 1) * 5) + 1) & 0xFFFF

    return bytes(out)

def encrypt_sc3(plain):

    key0 = 0xEBD7
    key1 = 0xA21F
    key2 = 0x000D
    checksum = key1

    for b in plain:
        checksum = (checksum + b * key2) & 0xFFFF

    trailer = rol16(key0 ^ checksum, 3)
    print(f"checksum={checksum:04X}")
    print(f"trailer ={trailer:04X}")
    print(f"verify  ={key0 ^ ror16(trailer,3):04X}")
    state = key0 ^ ror16(trailer, 3)
    out = bytearray(len(plain))
    for i, b in enumerate(plain):
        out[i] = b ^ (state & 0xFF)
        state = ((ror16(state, 1) * 5) + 1) & 0xFFFF

    out += struct.pack("<H", trailer)
    out += b"VersionA\x00"

    return bytes(out)

def unpack_sc3game(src):
    src_pos = 0
    dst = bytearray()

    while True:
        flags = src[src_pos]
        src_pos += 1

        if flags == 0:
            break

        while flags > 1:
            if flags & 1:
                dst.append(src[src_pos])
                src_pos += 1
            else:
                token = (src[src_pos] << 8) | src[src_pos + 1]
                src_pos += 2
                offset = token & 0x7FF
                if offset == 0:
                    offset = 0x800
                length = (token >> 11) & 0x1F
                if length == 0:
                    length = 0x20
                pos = len(dst) - offset
                if pos < 0:
                    raise Exception(
                        f"invalid backref offset={offset} length={length} dstlen={len(dst)}"
                    )
                for _ in range(length):
                    dst.append(dst[pos])
                    pos += 1
            flags >>= 1

    return bytes(dst)


def find_match(data, pos, index):

    if pos + 3 > len(data):
        return None

    key = bytes(data[pos:pos + 3])

    candidates = index.get(key)
    if not candidates:
        return None

    best_len = 0
    best_off = 0

    for candidate in reversed(candidates):

        offset = pos - candidate

        if offset > 2048:
            break

        length = 3

        while (
            length < 32
            and pos + length < len(data)
            and data[candidate + length] == data[pos + length]
        ):
            length += 1

        if length > best_len:
            best_len = length
            best_off = offset

            if length == 32:
                break

    if best_len < 3:
        return None

    return best_off, best_len


def pack_sc3game(data):
    data = memoryview(data)
    index = defaultdict(list)
    out = bytearray()
    pos = 0
    while pos < len(data):
        print(f"\r  {pos / len(data) * 100:.1f}%", end="")
        ops = []
        while len(ops) < 7 and pos < len(data):
            match = find_match(data, pos, index)
            if match:
                offset, length = match
                assert 1 <= offset <= 2048
                assert 3 <= length <= 32
                ops.append(("ref", offset, length))
                advance = length
            else:
                ops.append(("lit", data[pos]))
                advance = 1

            for i in range(advance):
                p = pos + i
                if p + 3 <= len(data):
                    key = bytes(data[p:p + 3])
                    index[key].append(p)
            pos += advance

        flags = 1 << len(ops)
        for i, op in enumerate(ops):
            if op[0] == "lit":
                flags |= (1 << i)

        out.append(flags & 0xFF)

        for op in ops:
            if op[0] == "lit":
                out.append(op[1])
            else:
                _, offset, length = op
                if offset == 2048:
                    off_field = 0
                else:
                    off_field = offset
                if length == 32:
                    len_field = 0
                else:
                    len_field = length
                token = (len_field << 11) | off_field
                out.append((token >> 8) & 0xFF)
                out.append(token & 0xFF)
    out.append(0)
    return bytes(out)

def rd3(A, a, B):
    return (B * a) / A

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("unpack")
    p1.add_argument("input")
    p1.add_argument("output")
    p1.add_argument("--encrypted", action="store_true", help="decrypt the payload before unpacking. needed for DVD binaries, dongle binaries are not encrypted")

    p2 = sub.add_parser("pack")
    p2.add_argument("input")
    p2.add_argument("output")
    p2.add_argument("--encrypted", action="store_true", help="encrypt after packing. needed for DVD binaries, dongle binaries are not encrypted")

    args = ap.parse_args()

    if args.cmd == "unpack":
        data = open(args.input, "rb").read()
        if args.encrypted:
            print("decrypting...")
            data = encrypt_sc3(data)
        print("unpacking...")
        out = unpack_sc3game(data[4:])
        open(args.output, "wb").write(out)
        print("unpack:")
        print(f"  input: 0x{len(data):X}")
        print(f"  output 0x{len(out):X}")
        print(f"  ratio: {(len(data)/len(out))*100:.1f}%")

    elif args.cmd == "pack":
        data = open(args.input, "rb").read()
        # compressed payload begins with 00 00 10 00 and it gets ignored by the unpacker... replicate it otherwise game will skip 4 bytes of gamedata
        print("packing...")
        out = b"\x00\x00\x10\x00" + pack_sc3game(data)
        if args.encrypted:
            print("encrypting...")
            out = encrypt_sc3(out)
        open(args.output, "wb").write(out)
        print("pack:")
        print(f"  input: 0x{len(data):X}")
        print(f"  output 0x{len(out):X}")
        print(f"  ratio: {(len(out)/len(data))*100:.1f}%")


if __name__ == "__main__":
    main()
