# MPack source snapshot

Source: `https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz`

Version: 1.1.1

SHA-256: `24ef7a4b967751740b739bc3a8065d9cd0ca2fb2628bcfedab192c1b4e9df777`

The upstream amalgamation's `mpack.c` and `mpack.h` are retained. A local
`MPACK_NO_PRAGMAS` conditional in `mpack.h` keeps Zig's C translation from
ingesting compiler-only warning pragmas.
