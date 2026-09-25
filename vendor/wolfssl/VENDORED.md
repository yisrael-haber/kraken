# wolfSSL source snapshot

Source: `https://github.com/wolfSSL/wolfssl`

Tag: `v5.9.2-stable`

Commit: `ac01707f552c611fbd135cc723b2682b3e7f80f2`

License: GPLv3 (`LICENSING`, `COPYING`), the same license wolfIP already
places on Kraken.

Upstream files are unchanged. Only what the build uses is kept: the sources
listed in `build.zig`, the `src/*.c` files that `src/ssl.c` includes into
itself, `wolfcrypt/src/misc.c` (included inline), and the headers those
sources include on Linux and Windows. `protocols/tls` uses the TLS API
(`wolfSSL_*`) with Kraken's I/O callbacks.

## Kraken files

- `kraken/user_settings.h` is the whole configuration, selected with
  `-DWOLFSSL_USER_SETTINGS`: TLS 1.2 and 1.3, client and server, SNI, ALPN,
  no filesystem, no OS sockets. It replaces `./configure`.
- `kraken/wolfssl/options.h` is empty. wolfSSL's headers include
  `<wolfssl/options.h>`, which `./configure` normally generates.

## Updating

Replace the kept files with the new release's copies, then add any file the
new release's sources include that is missing. The build fails with the name
of each missing file.
