# libsmb2

- Source: <https://github.com/sahlberg/libsmb2>
- Revision: `3360c9f9b2bc5cd3b1ea963e4306e18bd3e452f3`
- Retrieved: 2026-09-27
- License: LGPL-2.1-or-later (`lib/`), BSD-2-Clause (`libdcerpc/`)
- Included: `include/`, `lib/`, `libdcerpc/`, and upstream license files

## Kraken changes

- `kraken/config.h`: fixed Linux/MinGW feature configuration; full libdcerpc,
  no Kerberos/GSSAPI.
- Namespaced the libdcerpc security, LSA, srvsvc and registry declarations
  that collide with the Windows SDK (identifier-only changes).
- Added a borrowed connected-stream API to libsmb2. It has explicit I/O
  results and no wait, connect or close ownership.
- Added `dcerpc_set_stream` to libdcerpc: an optional caller-owned byte stream
  (`send`/`recv`) used instead of an SMB pipe, for DCE/RPC over TCP. Bind, call
  and further-fragment reads send the PDU on the stream and feed the bytes read
  to upstream's own reply code (bind-ack, reassembly, faults, NDR). A request
  larger than the server's `max_recv_frag` is sent as several fragments, each
  header re-encoded by the PDU coder. The SMB path and every codec are unchanged.
- Added `smb2_release_fh`, a local-only release of a borrowed-transport handle;
  collection never performs protocol I/O.
- Added MinGW compatibility definitions and a symbol prefix for the new
  libdcerpc function in libsmb2's embedded minimal DCERPC copy.
- Treat an SMB `READ` end-of-file reply as a zero-byte result without
  dereferencing its absent reply body.
