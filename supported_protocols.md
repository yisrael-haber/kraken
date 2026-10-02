# Application Protocols

This document plans the application-layer protocols Kraken aims to support, the
library chosen for each, why, and what alternatives to keep in reserve. It is a
research summary and a roadmap, not an implementation guide.

Kraken gives a researcher full, direct control over each identity's traffic. The
protocols below are capabilities — each can be driven as a client, a server, or
both. What a researcher builds with them, and how, is theirs to decide; this
document only concerns getting the protocol wire formats onto Kraken's network path.

## Integration principle

Kraken runs its IPv4 identities on lwIP, not on the host's sockets. Any
protocol library we embed must therefore avoid opening OS sockets. Only two
shapes qualify:

- **Codec** — the library only encodes and decodes bytes; Kraken owns all I/O.
  This is the cleanest fit and the default preference.
- **I/O seam** — the library does its own protocol I/O but exposes a documented
  hook (an I/O callback, or a file-descriptor plus event model) that we point at
  Kraken's socket operations.

A library that opens its own sockets with no seam is disqualified, regardless of
other merits. A small, contained patch that adds such a seam is acceptable when
the library is otherwise the best choice. Secondary priorities, in order: low
build/embedding friction (few files, no heavy build system), then binary size.
Size is a budget, not a goal: the whole binary should stay under 10 MB, so pick
the library that gives the most capability for its cost.

## Script interface

Each protocol is a Lua module over the C library, loaded with
`require("protocols/<name>")`, for example `require("protocols/tls")`. A module
takes an identity name and runs on that identity's sockets. The API is
kept small and direct: the calls a researcher needs to drive the protocol as a
client or server, and no more.

## Network stack scope

lwIP supplies Ethernet, ARP, IPv4, TCP, UDP, and raw sockets. Its optional DNS,
DHCP, and TFTP code is vendored but not wired into Kraken. The application-layer
modules below use Kraken's socket interface or operate on bytes directly.

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
| SMB / DCERPC | Client | libsmb2 + libdcerpc | Patched I/O seams | Directory services |
| Kerberos | Both | Heimdal | Awkward; scope first | Directory services |
| Modbus/TCP | Both | nanomodbus | Codec / transport hooks | Industrial / IoT |
| MQTT | Both | Paho embedded (MQTTPacket) | Codec | Industrial / IoT |
| CoAP | Both | microcoap | Codec | Industrial / IoT |
| SNMP | Both | Reuse BER layer | Codec | Industrial / IoT |
| SSH | Both | wolfSSH | I/O callback | Remote access |
| SMTP / FTP / Telnet / POP3 / IMAP | Both | None (line-based) | Own I/O | Text protocols |
| TFTP | Both | lwIP TFTP app | Planned | Text protocols |

## Foundational

These underpin other protocols and should come first.

### TLS — wolfSSL
- **Status:** implemented as `protocols/tls` (see
  [SCRIPTING.md](SCRIPTING.md#tls)): TLS 1.2 and 1.3, client and server, SNI,
  ALPN, optional certificate verification. wolfSSL v5.9.2 is vendored in
  `vendor/wolfssl` with a Kraken `user_settings.h` and no upstream changes. Its
  I/O callbacks call Kraken's TCP socket operations on the script's thread.
- **Why best:** its I/O callbacks (`wolfSSL_SetIORecv` / `SetIOSend`, per-session
  context) let Kraken provide transport through its own socket interface.
  Client and server.
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
  I/O handlers — a documented substitution point for Kraken's socket I/O. It is
  the one mature C package that exposes the BER layer separately from transport.
- **Note:** "aldap" (an OpenBSD/Go component) was considered and rejected — there
  is no established portable standalone C library by that name.
- **Alternative:** use libldap's higher-level API with a custom `Sockbuf_IO`
  handler — same library, less code, if default sockbuf redirection suffices.

### SMB / DCERPC — libsmb2 and libdcerpc
- **Status:** implemented as `protocols/smb` for SMB files and directories and
  `protocols/dcerpc` for client RPC over direct TCP and SMB named pipes;
  live-peer interoperability remains to be verified.
- **Scope:** client-only SMB2/3 file operations and DCE/RPC over SMB named
  pipes or connection-oriented TCP. No server runtime.
- **Why these libraries:** libsmb2 supplies SMB2/3 negotiation, NTLMSSP,
  signing and sealing. Its sibling libdcerpc supplies NDR and procedure tables
  for srvsvc, lsa, winreg, wkssvc and EPM. Kerberos/GSSAPI stays off.
- **Upstream limitation:** libsmb2 owns an OS socket. libdcerpc is not a
  transport-neutral RPC library: its context stores `smb2_context`, errors and
  NDR settings live there, and bind/call are hard-coded to
  `SMB2_FSCTL_PIPE_TRANSCEIVE`. It therefore has no TCP transport today.

#### Required seams

1. **libsmb2 borrows a connected byte stream.** Add an explicit external-stream
   API with `readv`, `writev` and `opaque`. Results report byte count, closed,
   retry and failure directly; do not emulate `errno`. Split share negotiation
   from socket connection so Kraken can attach its already-connected stream and
   start SMB negotiation without a fake descriptor or a re-entrant synthetic
   connect callback. Keep libsmb2's async state machine and let Kraken pump it.
   There is no `wait` or `close` callback: Kraken owns both.
2. **libdcerpc becomes transport-neutral.** Its context owns RPC/NDR state,
   call IDs, negotiated fragment sizes, reassembly and its own error buffer. It
   borrows only `{ read, write, opaque }`; it never owns or reaches through an
   SMB context. Bind and call use that channel for both transports.
3. **SMB adapter.** This owns the SMB context and named-pipe handle. DCE channel
   reads and writes map directly to SMB READ and WRITE. Pipe open/close is
   outside the DCE core.
4. **TCP adapter.** This forwards `read` and `write` directly to the existing
   `stream.Transport`. It reads the 16-byte RPC header first, validates
   `frag_length`, then reads exactly the rest of that fragment.

The DCE core must fragment requests to negotiated `max_xmit_frag`, reassemble
responses until `PFC_LAST_FRAG`, and reject mismatched call IDs, invalid fragment
lengths, unexpected PDU types, truncated auth trailers and oversized replies.
One implementation serves both adapters.

#### Ownership and failure

One Lua session is the sole lifecycle owner. It retains the TCP userdata and
owns the DCE context; an SMB session additionally owns its SMB context, pipe and
adapter. Every library reference points downward and is borrowed. Destruction
is DCE state, pipe, SMB state, then TCP. No child retains the session and no
manager object knows about protocol state.

Explicit `close` may perform bounded pipe/logoff shutdown. Collection performs
no protocol I/O. A timeout, cancellation, malformed reply or partial failed
write poisons the session and closes it; continuing could associate a late
reply with the wrong call. Only one call may be in flight.

#### Lua surface

```lua
dcerpc.smb(tcp445, options [, timeout_ms])
dcerpc.tcp(tcp_endpoint, options [, timeout_ms])
rpc:call(procedure, request_json [, timeout_ms]) -- response JSON
rpc:close()
```

`options` selects the service and, for SMB, server/user/password/domain plus
signing and sealing policy. Constructors consume the connected TCP socket.
Service/procedure lookup uses libdcerpc's tables; the Lua layer remains generic.
Unknown services, procedures and JSON fields fail before network I/O.

RPC-over-TCP authentication is a separate protocol feature, not a transport
detail. The first delivery supports `auth_type=none` and must say so plainly;
NTLM connection/integrity/privacy requires bind/auth3 tokens and per-PDU
verifiers and is not implied by SMB's NTLM support.

#### Delivery gates

1. Pin one upstream commit in `vendor/libsmb2`; record license, source and every
   local patch in `VENDORED.md`.
2. Compile selected libsmb2 and full libdcerpc sources for both Linux and
   Windows before writing Lua bindings. Upstream does not normally build full
   libdcerpc on Windows, so symbol/header conflicts are a stop gate.
3. Test SMB NTLM, signing and sealing; bind/call on both transports; EPM on TCP
   135; request and response fragmentation; partial I/O; peer close; malformed
   lengths; timeout, cancellation, identity stop, explicit close and GC.
4. Prove library code makes no OS socket, poll or close calls on Kraken's path,
   and check both release binaries against the size budget.

- **License:** libsmb2 is LGPL-2.1-or-later and libdcerpc is BSD-2-Clause.
- **Alternative:** Samba is much larger and owns more platform machinery; it
  does not improve this seam.

### Kerberos — Heimdal (scope before committing)
- **Status:** the weakest fit here, and flagged as such. Both Heimdal and MIT own
  their KDC transport and assume a lot of OS; neither has a clean I/O seam, so
  redirecting the KDC exchange onto Kraken's sockets is real surgery.
- **Why Heimdal over MIT:** it has a standalone ASN.1 compiler and runtime, so
  the DER message building can be used more independently of its network code.
- **Recommendation:** first decide whether full Kerberos is needed, or only the
  construction of AS-REQ / TGS-REQ / AP-REQ. If the latter, build those messages
  with Heimdal's ASN.1 layer and do the KDC round trip over Kraken's sockets —
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
small reader over a Kraken socket suffices, so no dependency is justified. Any of
them can be implemented as a client or a server directly on top of Kraken's
sockets. Add opportunistically.

lwIP includes optional TFTP code, which Kraken does not currently build.

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
