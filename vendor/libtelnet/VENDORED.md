# libtelnet source snapshot

Source: `https://github.com/seanmiddleditch/libtelnet`

Commit: `5f5ecee776b9bdaa4e981e5f807079a9c79d633e` (the 0.23 line, 2020-08-14)

License: public domain (`COPYING`).

`libtelnet.c`, `libtelnet.h` and `COPYING`, unmodified. It is a codec: it parses the
bytes it is given into events and hands back the bytes to send, and does no I/O.
Built without zlib, so MCCP2 (COMPRESS2) is not supported.
