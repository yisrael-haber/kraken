# libetpan source snapshot

Source: `https://github.com/dinhvh/libetpan`

Commit: `cf904f9de7bbafe5fabf44ec01818e20044b4e3b`

License: BSD 3-clause (`COPYRIGHT`).

Only what the SMTP, POP3 and IMAP clients link is kept: found by linking a program that
uses every API `protocols/smtp`, `protocols/pop3` and `protocols/imap` call. Upstream keeps
its sources in `src/data-types`, `src/low-level/{smtp,pop3,imap}`; here the 57 `.c` files are in
`src/` and every header from those directories is in `include/libetpan/`, the layout the
headers expect (`#include <libetpan/...>`). Left out: the socket and TLS streams, the
engine, the drivers, IMF and MIME message parsing, SASL, iconv and the cache databases.
`win_etpan.h` and `time_r.c` are upstream's Windows shim (`src/windows`), also unmodified.

The sources are unmodified except for one patch, `kraken/hostname.patch`, already applied.
libetpan puts the host's own name in HELO and EHLO, which a lab identity must not do; the
patch adds a `smtp_hostname` field to `struct mailsmtp` that `get_hostname` uses when set.

## Kraken files

- `kraken/etpan_shim.c` copies out the mailbox information after a SELECT, because Zig's C
  translation cannot read libetpan's selection struct (it has bitfields).
- `kraken/config.h` is what libetpan's `configure` would generate, for both platforms, with
  `LIBETPAN_REENTRANT` since scripts run on several threads. `include/libetpan/libetpan-config.h`
  is upstream's `libetpan-config.h.in` with its `@` lines turned into `#`.
- libetpan reaches its connection through a `mailstream_low` driver, which `protocols/smtp`,
  `pop3` and `imap` give a Kraken TCP socket or TLS session, so none of the socket code is
  built. Its Windows idle and cancel code, which Kraken never runs, is not 64-bit clean, so
  the build passes `-Wno-int-conversion`. On Windows the global string table's critical section
  is initialized at startup.
