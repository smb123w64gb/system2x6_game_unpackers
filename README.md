# SYSTEM 246/256 Game Unpackers

a bunch of scripts to unpack and repack the main game binaries of several games

these binaries are in most cases headerless blobs of code, that get unpacked into a specific ram address, then that address is executed as a `void fun(void)` function

unless explicitly mentioned on a comment amongst the first lines of the script, the load address of these files is always `0x1000000`
