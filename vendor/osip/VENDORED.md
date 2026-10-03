# GNU oSIP source snapshot

Source: `https://ftp.gnu.org/gnu/osip/libosip2-5.3.2.tar.gz` (sha256
`16186f6f5540936b62c3aaca6e8409e1af25cd22abc3882b393be215f49d3b00`)

License: LGPL-2.1-or-later (`COPYING`).

Only the parser library, `osipparser2`, is kept, with no source changes: `src/*.c` (the
parser, the header types, the SDP parser and MD5) and `include/osipparser2`. The transaction
layer (`osip2`) is not vendored; it needs threads and timers, and `protocols/sip` needs only
the message parser.

## Kraken files

`kraken/osip-config.h` is what oSIP's `configure` would generate for the parser: header
availability for Linux, with the POSIX-only ones left out on Windows. `build.zig` defines
`HAVE_CONFIG_H` so oSIP includes it. oSIP's `parser_init` must run once before parsing; the
runtime calls it at startup.
