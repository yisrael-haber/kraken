# Application Protocols

This document plans the application-layer protocols Kraken aims to support, the
library chosen for each, why, and what alternatives to keep in reserve. It is a
research summary and a roadmap, not an implementation guide.

Kraken gives a researcher full, direct control over each identity's traffic. The
protocols below are capabilities — each can be driven as a client, a server, or
both. What a researcher builds with them, and how, is theirs to decide; this
document only concerns getting the protocol wire formats onto Kraken's stacks.

## Integration principle

Kraken runs its own IPv4 identities on wolfIP, not on the host's sockets. Any
protocol library we embed must therefore avoid opening OS sockets. Only two
shapes qualify:

- **Codec** — the library only encodes and decodes bytes; Kraken owns all I/O.
  This is the cleanest fit and the default preference.
- **I/O seam** — the library does its own protocol I/O but exposes a documented
  hook (an I/O callback, or a file-descriptor plus event model) that we point at
  a wolfIP socket descriptor.

A library that opens its own sockets with no seam is disqualified, regardless of
other merits. A small, contained patch that adds such a seam is acceptable when
the library is otherwise the best choice. Secondary priorities, in order: low
build/embedding friction (few files, no heavy build system), then binary size.
Size is a budget, not a goal: the whole binary should stay under 10 MB, so pick
the library that gives the most capability for its cost.

## Script interface

Each protocol is a Lua module over the C library, loaded with
`require("protocols/<name>")`, for example `require("protocols/tls")`. A module
takes an identity name and runs on that identity's wolfIP sockets. The API is
kept small and direct: the calls a researcher needs to drive the protocol as a
client or server, and no more.

## Already provided by wolfIP

Use these before adding anything; they cost no extra binary and already run on
wolfIP's own sockets.

- **DNS** — A and PTR lookups (`wolfIP_dns_*`). Enough for basic name resolution.
- **DHCP** client.
- **IPsec / ESP.**
- **TFTP** — gated behind a `WOLFIP_ENABLE_TFTP` build flag.

wolfIP does **not** provide NTP/SNTP, despite earlier assumptions. NTP is dropped
from scope (see below).

## Protocol summary

Priority reflects how foundational a protocol is and how common it is in lab
work, not any particular use for it.

| Protocol | Client / Server | Best option | Integration | Priority |
| --- | --- | --- | --- | --- |
| TLS | Both | wolfSSL | I/O callback | Foundational |
| HTTP(S) | Both | picohttpparser + own I/O | Codec | Foundational |
| HTTP/2 | Both | Own frames + nghttp2 HPACK | Codec | Foundational (after TLS) |
| DNS (rich records) | Both | c-ares record API (patched) | Codec | Directory services |
| LLMNR / mDNS / NBT-NS | Both | c-ares (reuse); NBT-NS names by hand | Codec | Directory services |
| LDAP | Both | OpenLDAP liblber / libldap | Codec + `ber_sockbuf` | Directory services |
| SMB / DCERPC | Both | libsmb2 | Patched I/O seam | Directory services |
| Kerberos | Both | Heimdal | Awkward; scope first | Directory services |
| Modbus/TCP | Both | nanomodbus | Codec / transport hooks | Industrial / IoT |
| MQTT | Both | Paho embedded (MQTTPacket) | Codec | Industrial / IoT |
| CoAP | Both | microcoap | Codec | Industrial / IoT |
| SNMP | Both | Reuse BER layer | Codec | Industrial / IoT |
| SSH | Both | wolfSSH | I/O callback | Remote access |
| SMTP / FTP / Telnet / POP3 / IMAP | Both | None (line-based) | Own I/O | Text protocols |
| TFTP | Both | wolfIP flag | Built in | Text protocols |

## Foundational

These underpin other protocols and should come first.

### TLS — wolfSSL
- **Status:** implemented as `protocols/tls` (see
  [SCRIPTING.md](SCRIPTING.md#tls)): TLS 1.2 and 1.3, client and server, SNI,
  ALPN, optional certificate verification. wolfSSL v5.9.2 is vendored in
  `vendor/wolfssl` with a Kraken `user_settings.h` and no upstream changes. Its
  I/O callbacks call Kraken's TCP socket operations on the script's thread.
- **Why best:** the only candidate whose I/O callbacks (`wolfSSL_SetIORecv` /
  `SetIOSend`, per-session context) exist specifically to run TLS over a
  non-socket transport. Same vendor as wolfIP, so pairing them via
  `WOLFSSL_USER_IO` and a wolfIP descriptor is the documented path. Client and
  server.
- **Alternatives:** mbedTLS — also has I/O callbacks (`mbedtls_ssl_set_bio`),
  slightly smaller crypto footprint if wolfSSL's cert breadth is unneeded.
  BearSSL — smallest, but no server-side X.509 chain building, so more work as a
  TLS server.

### HTTP(S) — picohttpparser plus Kraken-owned I/O
- **Status:** HTTP/1.x is implemented as `protocols/http` (see
  [SCRIPTING.md](SCRIPTING.md#http)). HTTPS is `protocols/http` over a
  `protocols/tls` session.
- **Model:** HTTP/1.1 requests and responses are trivial to emit by hand;
  the only real work is parsing what arrives. picohttpparser is a stateless,
  zero-allocation, roughly single-file parser that points into a caller-owned
  buffer and never touches I/O. Server parses requests, client parses responses,
  same library. Over TLS it parses the stream decrypted by wolfSSL.
- **Why best:** an embeddable full server (Mongoose, civetweb) would be less
  work but each brings its own network layer — the thing we reject.
  picohttpparser brings none.
- **Alternative:** llhttp (Node's parser) — streaming, with built-in handling of
  keep-alive and chunked edge cases, but larger (generated state machine) and
  stateful. Worth it only if those edges become a problem.

### HTTP/2 — own frame codec plus nghttp2 HPACK (after TLS)
- **Status:** planned after TLS. Not started.
- **Why it is bigger than HTTP/1.x:** HTTP/2 is binary and has three layers:
  frames (a 9-byte header and a payload, in ten types); HPACK header
  compression (a static table, a dynamic table both sides must keep in sync,
  and Huffman coding); and connection state (many streams, per-stream state,
  flow-control windows, settings). The frame layer is simple. HPACK is subtle
  enough that it should not be hand-rolled. The connection state is what makes
  HTTP/2 stateful across calls, unlike `protocols/http`.
- **Why after TLS:** real servers offer HTTP/2 only over TLS, negotiated with
  ALPN, which wolfSSL supports. Cleartext HTTP/2 where both sides assume it up
  front ("prior knowledge": nghttpd, Go, h2o,
  `curl --http2-prior-knowledge`) lets lab testing start before TLS, but it is
  not the main target.
- **Library: nghttp2 (MIT).** It is the standard C implementation (curl uses
  it) and fits the codec rule: its session takes received bytes
  (`nghttp2_session_mem_recv2`) and hands back bytes to send
  (`nghttp2_session_mem_send2`), and it never touches sockets. Its HPACK
  encoder and decoder are also public on their own (`nghttp2_hd_deflate_*`,
  `nghttp2_hd_inflate_*`). Plain C plus one generated version header;
  roughly 150–200 KB compiled.
- **The research catch:** nghttp2's session enforces protocol correctness, so it
  cannot send invalid frames. Research often needs exactly those: rapid reset,
  `CONTINUATION` floods, bad window sizes, stream-state violations. So the work
  is split into two layers.
- **Approach:**
  1. **Frame and HPACK codec (first; small to medium).** Kraken's own Zig
     encoder and decoder for any frame, valid or not
     (`encode_frame` / `decode_frame`), plus HPACK through nghttp2's
     standalone functions. The script drives the protocol. This mirrors
     `protocols/http`: bytes to tables and back, no I/O, full control. About
     the size of the HTTP/1.x step.
  2. **Session (only when needed; medium to large).** A stateful object over
     nghttp2's session for correct HTTP/2 without driving frames by hand. The
     work is mapping nghttp2's callbacks onto a small Lua API. It runs in
     global scripts only, since transport scripts get a fresh Lua state for
     each frame.
- **Alternative:** hand-rolled HPACK. Rejected: the dynamic-table and Huffman
  logic is where interoperability bugs live, and nghttp2 already exposes it on
  its own.

## Directory services

Enterprise environments run on DNS, LDAP, SMB/DCERPC and Kerberos, over TLS and
HTTP. Together these let an identity participate in a directory environment as a
full peer — resolving names, binding, and exchanging authenticated requests.

### DNS, mDNS, LLMNR — c-ares record API
- **Status:** implemented as `protocols/dns` (see
  [SCRIPTING.md](SCRIPTING.md#dns)).
- **Why best:** c-ares (MIT, maintained, used by curl) has a record codec
  (`ares_dns_parse` / `ares_dns_write`) separate from its resolver. Only that
  part is vendored; it calls no sockets and adds about 50 KB. Each record type
  is described by keys with datatypes (`ares_dns_rr_get_keys`,
  `ares_dns_rr_key_datatype`), so one generic binding covers every type it
  parses, including SVCB/HTTPS, TLSA, CAA, URI and the DNSSEC types. Unknown
  types, and whole sections on request, come back as raw records.
- **Patch:** its parser was built for a resolver and rejected valid local
  name-resolution traffic: zero or several questions, the mDNS class top bit
  in questions, and opcodes other than the standard five. A small vendored
  patch (`vendor/c-ares/kraken/records.patch`) removes those checks.
- **Rejected:** SPCDNS decodes each record type into its own struct and drops
  the raw bytes, so the binding would need per-type conversion and could not
  show anything its structs do not model. ldns and sldns are resolver and
  DNSSEC toolkits, poor size fits.

### LLMNR / mDNS / NBT-NS
- **LLMNR and mDNS** use the DNS wire format and work through `protocols/dns`
  directly: numeric classes keep the mDNS cache-flush and unicast-response
  bits, and messages may carry any number of questions.
- **NBT-NS** is DNS-like but not DNS: it encodes NetBIOS names into 32-letter
  labels, uses opcodes 5-8, and its NBSTAT record type is 33, SRV's number. The
  header, questions and NB records carry through `protocols/dns` using raw
  records. A NetBIOS name encoder and NBSTAT parser are small and can be added
  when needed.

### LDAP — OpenLDAP liblber (with libldap)
- **Why best:** LDAP is ASN.1/BER, which we do not want to hand-roll. liblber
  BER-encodes into an in-memory `BerElement` (`ber_alloc_t`, `ber_printf`,
  `ber_flush2`) with no sockets, and libldap redirects I/O through `ber_sockbuf`
  I/O handlers — a documented substitution point for a wolfIP descriptor. It is
  the one mature C package that exposes the BER layer separately from transport.
- **Note:** "aldap" (an OpenBSD/Go component) was considered and rejected — there
  is no established portable standalone C library by that name.
- **Alternative:** use libldap's higher-level API with a custom `Sockbuf_IO`
  handler — same library, less code, if default sockbuf redirection suffices.

### SMB / DCERPC — libsmb2
- **Why best:** the only small, maintained C implementation of SMB2/3 with
  both client and server code. It includes NTLMSSP, signing and SMB3
  encryption with its own MD4/MD5/HMAC/SHA/AES, so it needs no crypto
  library. Kerberos (GSSAPI) is optional and stays off. libdcerpc, in the same
  repository, runs DCE/RPC over SMB named pipes (srvsvc, lsa, winreg, wkssvc,
  epm).
- **No I/O seam as shipped.** libsmb2 does its own socket I/O on `smb2->fd`:
  `getaddrinfo`/`socket`/`connect` in `smb2_connect_async` (`lib/socket.c`),
  `writev` in `smb2_write_to_socket`, `readv` in `smb2_readv_from_socket`,
  `getsockopt(SO_ERROR)` in `smb2_service_fd`, `close` in `init.c` and
  `libsmb2.c`, `poll` in the sync wait loops (`lib/sync.c`,
  `libdcerpc/dcerpc.c`), and `select`/`accept` in the server loop.
  `smb2_get_fd` / `smb2_which_events` / `smb2_fd_event_callbacks` only report
  which fd to watch; they do not move bytes. The lwIP ports work through
  `lib/compat.h`, which `#define`s the POSIX names to `lwip_*`, one call to one
  call. wolfIP's API has the same BSD shape (`wolfIP_sock_socket`, `_connect`,
  `_recv`, and so on), but every call takes a `struct wolfIP *` and
  descriptors are per instance. Upstream's drop-in shims don't fit Kraken:
  `src/port/posix/bsd_socket.c` is an `LD_PRELOAD` interposer over one global
  stack and is Linux-only, and `src/port/freeRTOS/bsd_socket.c` binds the plain
  names to one stack. Kraken also can't call wolfIP from a script thread,
  because each stack is owned by the manager thread and reached through
  commands. So the lwIP precedent doesn't carry over directly. Macros scoped to
  libsmb2's compile step (through its `config.h`) would work, but they can only
  rename OS calls. Kraken would then have to mimic POSIX socket behavior on
  Linux and winsock behavior on Windows, across about 11 calls each. A transport
  that hooks libsmb2's own read, write and wait points is smaller and
  cross-platform. It was chosen for that reason.
- **Integration: a small vendored patch that adds a transport** (about 40
  lines across 6 files). Keep the patched source in `vendor/libsmb2` and list
  every edit in its `VENDORED.md`. The patch is not offered upstream, so it is
  re-applied on each libsmb2 update.
  1. `include/smb2/libsmb2.h`: add `struct smb2_transport { readv, writev,
     wait, close, ctx }` and `smb2_set_transport(smb2, transport)`. The context
     in `libsmb2-private.h` stores a copy and a `has_transport` flag.
  2. `lib/socket.c`, `smb2_connect_async`: with a transport set, mark the
     context connected and call the connect callback immediately. Kraken has
     already opened the TCP connection, so name lookup, `socket` and `connect`
     are skipped, and the stock `smb2_connect_share_async` continues with
     negotiate and session setup unchanged. Verify that libsmb2 tolerates the
     callback running inside `smb2_connect_async`.
  3. `lib/socket.c`: route `writev` in `smb2_write_to_socket` and `readv` in
     `smb2_readv_from_socket` through the transport. `readv` returns -1 with
     `errno = EAGAIN` when no data is buffered and 0 when the peer closed;
     `smb2_read_data` already handles both.
  4. `lib/init.c` and `lib/libsmb2.c`: route the three `close(smb2->fd)` sites
     through `transport.close`.
  5. `lib/sync.c` (`wait_for_reply`) and `libdcerpc/dcerpc.c`
     (`dcerpc_wait_for_reply`): replace `poll` with `transport.wait`, which
     returns the ready events. Every `smb2_*_sync` call goes through these two
     loops, so the whole sync API then works on wolfIP.
  The transport bypasses `compat.h`, so the same shim serves Linux and Windows.
- **Kraken side.** The shim runs on the calling script's VM thread and uses the
  existing socket commands, so the manager needs no new machinery. `wait`
  blocks in a TCP receive with a timeout, into a shim buffer. `readv` drains
  that buffer, then polls with a zero timeout. `writev` gathers the vectors
  into one send-all.
- **Script API (client first):**
  `smb.connect(identity, address, share, {user, password, domain, timeout})`
  returns a session with `list`, `stat`, `read`, `write`, `remove`, `mkdir`,
  `shares` and `close`. DCE/RPC calls come later, on the same session.
- **Server: second phase.** `smb2_serve_port` owns a `select`/`accept` loop.
  Kraken would accept on wolfIP, create a context with the transport attached
  (the same thing `accept_cb` does with `smb2->fd`), and replicate the
  server's per-connection setup. The server code is younger than the client
  code, so it needs testing before it is exposed.
- **Build:** compile `lib/*.c` plus `libdcerpc/*.c` with a Kraken `config.h`,
  without krb5/GSSAPI and without the platform-specific AES backends. The
  Windows `compat.h` path still pulls in winsock headers; verify that it
  builds with Zig's mingw target.
- **License:** `lib/` is LGPL-2.1-or-later and `libdcerpc/` is BSD-2-Clause.
  Both are compatible with GPLv3, which wolfIP already imposes on Kraken.
- **Alternative:** none worth it. Samba's libsmbclient is far heavier, assumes a
  full OS and has no transport seam.

### Kerberos — Heimdal (scope before committing)
- **Status:** the weakest fit here, and flagged as such. Both Heimdal and MIT own
  their KDC transport and assume a lot of OS; neither has a clean I/O seam, so
  redirecting the KDC exchange onto wolfIP is real surgery.
- **Why Heimdal over MIT:** it has a standalone ASN.1 compiler and runtime, so
  the DER message building can be used more independently of its network code.
- **Recommendation:** first decide whether full Kerberos is needed, or only the
  construction of AS-REQ / TGS-REQ / AP-REQ. If the latter, build those messages
  with Heimdal's ASN.1 layer and do the KDC round trip over wolfIP directly —
  far less pain than embedding the whole stack.
- **Alternative:** MIT krb5 only if its GSSAPI/ecosystem compatibility is later
  required; its transport is even more baked in.

## Industrial / IoT

Field-bus and IoT protocols, useful wherever a lab includes device controllers,
sensors, or their management planes. Each can run as the device side or the
controller side.

### Modbus/TCP — nanomodbus
- **Why best:** a common OT/ICS lab protocol, with dead-simple fixed binary
  framing (7-byte MBAP header plus PDU). Both the server (device) side and the
  client (controller) side are small. nanomodbus is transport-agnostic by design
  — the caller provides read/write functions — so it never owns a socket.
- **Alternative:** libmodbus is more established but opens its own sockets;
  usable only if a redirection seam is added, which nanomodbus avoids entirely.

### MQTT — Eclipse Paho embedded (MQTTPacket)
- **Why best:** a ubiquitous IoT protocol with simple binary framing. Kraken can
  run either side — a broker or a client — over its own transport. Paho's
  MQTTPacket is serialization-only, so Kraken owns the transport, matching the
  codec model exactly.
- **Alternative:** MQTT-C — also transport-agnostic, single-pair of files; a
  reasonable fallback if Paho's layering proves awkward.

### CoAP — microcoap
- **Why best:** the UDP IoT counterpart to HTTP, with a simple 4-byte header plus
  options. microcoap is tiny and transport-agnostic.
- **Alternative:** libcoap is more complete but manages its own sockets; only
  worth it if CoAP features beyond basic request/response are needed.

### SNMP — reuse the BER layer
- **Why this shape:** common in network-gear and IoT labs, as an agent (device
  side) or a manager (polling side). SNMP is ASN.1/BER, so it reuses the LDAP BER
  work rather than pulling in net-snmp, which is heavy and owns its transport.
- **Alternative:** net-snmp only if its full MIB tooling is genuinely required.

## Remote access

### SSH — wolfSSH
- **Status:** implemented as `protocols/ssh` (see
  [SCRIPTING.md](SCRIPTING.md#ssh)): exec (one command per session), client and
  server, over Kraken's I/O callbacks. wolfSSH v1.5.0 is vendored in
  `vendor/wolfssh` (no upstream changes) and built against the vendored wolfSSL.
  Interactive shells and SFTP/SCP are out of scope for now; client auth is
  password only.
- **Why best:** the standard remote-access protocol, needed as a client or a
  server. wolfSSH reuses the same I/O-callback shim as wolfSSL, so once the TLS
  seam exists, SSH is low integration risk and shares the wolfSSL crypto already
  linked.
- **Alternative:** libssh2 (client-oriented) exposes an abstract transport, but
  wolfSSH's shared vendor and callback model make it the better fit here.

## Text protocols

SMTP, FTP, Telnet, POP3 and IMAP are line-based text. No library is needed — a
small reader over a wolfIP socket suffices, so no dependency is justified. Any of
them can be implemented as a client or a server directly on top of Kraken's
sockets. Add opportunistically.

TFTP is already available behind wolfIP's build flag; trivial UDP, common in OT
and boot-infrastructure labs. Near-free to enable.

## Out of scope

- **NTP / SNTP** — no small, buffer-only library exists; real NTP libraries are
  daemons that own their sockets. Dropped.
- **RDP** — enormous, no clean embeddable stack; poor size-to-effort ratio.
- **Full database wire protocols (Postgres, MySQL)** — very application-specific;
  add only when a specific piece of work calls for one. Redis RESP is the
  exception: trivially simple, and worth adding if it comes up.
- **DNP3, BACnet** — real OT value but niche; add only on demand.

## Suggested order

1. **TLS (wolfSSL) shim** — done; the shared foundation that HTTPS and every
   TLS-wrapped protocol build on, and the proof of the I/O-callback pattern.
2. **HTTP(S) via picohttpparser** — done; HTTP/1.x as a codec, and HTTPS over a
   TLS session.
3. **DNS rich records and the LLMNR / mDNS family** — done, through the c-ares
   record codec; NBT-NS names and NBSTAT come later on top of it.
4. **Modbus and MQTT** — open the OT/IoT surface cheaply, in both directions.
5. **SSH (wolfSSH)** — done; exec sessions (client and server) over the same
   I/O-callback shim as TLS.
6. **LDAP, SMB, Kerberos, SNMP** and the text protocols, as directory and
   device work calls for them.
