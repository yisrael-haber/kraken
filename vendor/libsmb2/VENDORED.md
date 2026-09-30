# libsmb2

- Source: <https://github.com/sahlberg/libsmb2>
- Revision: `3360c9f9b2bc5cd3b1ea963e4306e18bd3e452f3`
- Retrieved: 2026-09-27
- License: LGPL-2.1-or-later (`lib/`), BSD-2-Clause (`libdcerpc/`)
- Included: `include/`, `lib/`, `libdcerpc/`, and upstream license files

## Kraken changes

- `kraken/config.h`: fixed Linux/MinGW feature configuration; full libdcerpc,
  no Kerberos/GSSAPI.
- Namespaced full-libdcerpc security, registry and endpoint-map declarations
  that collide with the Windows SDK.
- Added a borrowed connected-stream API to libsmb2. It has explicit I/O
  results and no wait, connect or close ownership.
- Split libdcerpc's RPC/NDR client from SMB with a borrowed byte-channel API,
  independent errors, bind negotiation, request fragmentation, response
  reassembly, call-ID validation, and generic JSON procedure calls.
- Added local-only release functions for DCERPC contexts and SMB pipe handles;
  collection never performs protocol I/O.
- Added MinGW compatibility definitions and prefixed new full-libdcerpc symbols
  in libsmb2's embedded minimal DCERPC copy.
- Treat an SMB `READ` end-of-file reply as a zero-byte result without
  dereferencing its absent reply body.
