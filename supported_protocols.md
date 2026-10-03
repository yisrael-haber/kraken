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
| HTTP/2 | Both | Own frames + nghttp2 HPACK | Codec | Future work |
| DNS (rich records) | Both | c-ares record API (patched) | Codec | Directory services |
| LLMNR / mDNS / NBT-NS | Both | c-ares (reuse); NBT-NS names by hand | Codec | Directory services |
| LDAP | Client | OpenLDAP libldap / liblber | Sockbuf handler, pumped async API | Directory services |
| SMB / DCERPC | Client | libsmb2 + libdcerpc | Patched I/O seams | Directory services |
| Kerberos | Both | Heimdal | Awkward; scope first | Deferred |
| Modbus/TCP | Both | nanomodbus | Codec / transport hooks | Not planned |
| MQTT | Both | Paho embedded (MQTTPacket) | Codec | Not planned |
| CoAP | Both | microcoap | Codec | Not planned |
| SNMP | Both | liblber BER layer (v1, v2c) | Codec | Industrial / IoT |
| SSH | Both | wolfSSH | I/O callback | Remote access |
| Telnet | Both | libtelnet | Codec | Text protocols |
| SMTP / POP3 / IMAP | Both | libetpan (to be checked) | Stream seam | Text protocols |
| FTP | Both | None found | Own I/O | Text protocols |
| TFTP | Both | Own codec (RFC 1350, 2347) | Codec | Text protocols |
| SIP | Both | GNU oSIP parser | Codec | Text protocols |
| NTP | Both | Own codec | Codec | Planned |
| Syslog | Both | Own codec | Codec | Planned |
| RADIUS | Both | To be researched | To be researched | Planned |
| NFS | Client | libnfs | To be researched | Future work |

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

### LDAP — OpenLDAP libldap and liblber
- **Status:** implemented as `protocols/ldap` (see
  [SCRIPTING.md](SCRIPTING.md#ldap)): LDAPv3 client with simple bind, search, add,
  modify, delete, rename, compare and extended operations over a TCP socket or a TLS
  session (LDAPS).
  OpenLDAP 2.6.15 is vendored in `vendor/openldap` with no source changes.
- **Why best:** LDAP is ASN.1/BER, which we do not want to hand-roll, and libldap
  carries the whole protocol: requests, message IDs, result parsing, controls.
  OpenLDAP is the reference implementation, and it exposes a documented seam for a
  caller-supplied transport.
- **Integration:** `ldap_init_fd` with `LDAP_PROTO_EXT` creates a session that
  expects the caller to install a `Sockbuf_IO` handler. Kraken's handler reads and
  writes the TCP socket. libldap waits for replies with `poll()` on a descriptor,
  which Kraken's sockets lack, so Kraken pumps libldap's asynchronous API instead:
  send an operation, block on the socket until bytes arrive, then take one result
  message at a time with a zero-timeout `ldap_result`. The handler's read returns
  exactly the bytes libldap asks for, so a message is never half-read.
- **Build:** liblber and the 36 libldap files the module needs, built without
  threads, TLS or SASL. The configuration headers are what OpenLDAP's own
  `configure` generates, once for Linux and once for Windows.
- **LDAPS:** `ldap.connect` also accepts a `protocols/tls` session, so LDAPS works
  the way HTTPS does: TLS is a layer under the protocol, which stays unaware of it.
- **Future work:** StartTLS. The client sends the StartTLS extended operation on a
  plain connection and then runs the TLS handshake on the same socket, so the session
  needs a way to switch its stream to a new TLS session after the server accepts
  (libldap's own `ldap_start_tls_s` is unavailable, since libldap is built without
  TLS). Also SASL and Kerberos binds, and request controls such as paged results.
  Referrals are returned and never followed, since libldap would open its own
  connections.

### SMB / DCERPC — libsmb2 and libdcerpc
- **Status:** implemented as `protocols/smb` for SMB files and directories and
  `protocols/dcerpc` for client RPC over direct TCP and SMB named pipes; verified
  against a Windows 10 peer (SMB files, srvsvc over SMB, endpoint mapper over TCP).
- **Scope:** client-only SMB2/3 file operations and DCE/RPC over SMB named
  pipes or connection-oriented TCP. No server runtime.
- **Why these libraries:** libsmb2 supplies SMB2/3 negotiation, NTLMSSP,
  signing and sealing. Its sibling libdcerpc supplies NDR and procedure tables
  for srvsvc, lsa, winreg, wkssvc and EPM. Kerberos/GSSAPI stays off. libyaml (MIT,
  parser only) turns libdcerpc's YAML replies into Lua tables.
- **Upstream limitation:** libsmb2 owns an OS socket, and libdcerpc's bind and
  call are hard-coded to SMB named-pipe commands. It has no TCP transport.

#### Required seams

1. **libsmb2 borrows a connected byte stream.** Add an explicit external-stream
   API with `readv`, `writev` and `opaque`. Results report byte count, closed,
   retry and failure directly; do not emulate `errno`. Split share negotiation
   from socket connection so Kraken can attach its already-connected stream and
   start SMB negotiation without a fake descriptor or a re-entrant synthetic
   connect callback. Keep libsmb2's async state machine and let Kraken pump it.
   There is no `wait` or `close` callback: Kraken owns both.
2. **libdcerpc gets an optional byte stream.** `dcerpc_set_stream` takes
   `{ send, recv, opaque }`. At the three points where the SMB path sends an
   IOCTL or READ and handles the reply (bind, call, further fragments), the
   stream path sends the PDU and feeds the bytes it reads to the same reply
   code. Bind-ack handling, fragment completion and reassembly, faults and NDR
   stay upstream's; Kraken adds no RPC protocol code. The context borrows an
   unconnected `smb2_context` for configuration and error text.
3. **SMB.** Kraken opens the pipe and binds with libdcerpc's own
   `dcerpc_connect_context_async` and `dcerpc_call_async` on the SMB session,
   pumped by Kraken's SMB transport.
4. **TCP.** `send` and `recv` forward to the existing `stream.Transport`; the
   call completes before `dcerpc_call_async` returns.

A request larger than the server's `max_recv_frag` (Windows advertises 5840) is
split into fragments, each header encoded by libdcerpc's PDU coder; responses of
any fragment count are reassembled by libdcerpc.

#### Ownership and failure

One Lua session is the sole lifecycle owner. It retains the TCP userdata and
owns the DCE context and the `smb2_context` beside it (connected for SMB, only
configuration and errors for TCP). Every library reference points downward and is borrowed. Destruction
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
rpc:call(opnum, stub [, timeout_ms])      -- raw NDR stub, any interface
rpc:call(procedure, yaml [, timeout_ms])  -- named procedure: reply table, YAML text
rpc:template(procedure)                   -- request YAML skeleton
rpc:close()
```

`options` selects the interface (a libdcerpc `service`, or any `interface` UUID
and `version`), the NDR syntax, and, for SMB, server/user/password/domain plus
signing and sealing policy. Constructors consume the connected TCP socket.
A raw call passes the stub through untouched. A named call uses libdcerpc's own
coders and its built-in YAML text format; the reply is parsed into a Lua table with
libyaml.
Unknown services and procedures fail before network I/O.

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
   135; response fragmentation; partial I/O; peer close; malformed
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

Not planned for now; the research below is kept in case it comes up.

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

### SNMP — codec over the BER layer
- **Status:** v1 and v2c implemented as `protocols/snmp` (see [SCRIPTING.md](SCRIPTING.md#snmp)):
  messages as tables, typed values, every PDU type including v1 traps and getbulk, with
  escape hatches for raw tags, raw OIDs and raw bodies. Managers, walkers, agents and trap
  senders are scripts over `kraken/socket` UDP sockets.
- **How:** liblber, OpenLDAP's BER codec vendored for LDAP, builds the BER structure and converts
  object IDs; the SNMP message grammar on top is Kraken's. net-snmp was passed over: it is heavy
  and owns its transport.
- **Not lwIP's SNMP:** lwIP's agent is device-side only, global to the stack, and its MIB is
  C structures, so it cannot be a manager or a codec for scripts.
- **Not yet:** v3. The module carries a v3 message as a version and a raw `payload`; the user
  security model (engine discovery, key localization, authentication and privacy) is not built.

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

Common line-based protocols, vendored from a library where a good one fits the I/O
rules, rather than written or scripted by hand.

### Telnet — libtelnet
- **Status:** implemented as `protocols/telnet` (see [SCRIPTING.md](SCRIPTING.md#telnet)):
  a session over a TCP socket that separates Telnet's commands from the data. Client and
  server. libtelnet (public domain) is vendored in `vendor/libtelnet`, unmodified.
- **Why best:** a codec. It parses the bytes it is given into events and hands back the bytes
  to send, with RFC 1143 option negotiation, so Kraken owns all I/O. Built without zlib, so
  MCCP2 is not supported.
- **Model:** the `us` and `them` lists make the library answer negotiation itself, and `proxy`
  turns that off so a script can drive it by hand. Terminal type, window size, environment and
  the rest arrive as raw subnegotiations.

### SMTP, POP3, IMAP — libetpan (to be checked)
- **Status:** not started. libetpan covers all three, and I believe its `mailstream_low`
  driver can carry a caller-supplied transport. Check that seam, the build, and the size
  before vendoring. libcurl was rejected: it needs real file descriptors, which Kraken's
  identities do not have.

### FTP
- **Status:** not started. No embeddable client or server library with a transport seam
  was found; decide between an own implementation and skipping it.

### TFTP — own codec
- **Status:** implemented as `protocols/tftp` (see [SCRIPTING.md](SCRIPTING.md#tftp)):
  encode and decode of the six packet types, with the option extension. Both roles run
  from scripts over `kraken/socket` UDP sockets, which own the lock-step transfer.
- **Why not lwIP's TFTP app:** it is callback-driven and runs inside lwIP's own network
  thread on raw UDP control blocks, so using it would mean calling scripts from that
  thread. No small maintained library with an I/O seam was found, and the protocol is
  five packet types, so the codec is Kraken's own, in the style of `protocols/dns`.

### SIP — GNU oSIP parser
- **Status:** implemented as `protocols/sip` (see [SCRIPTING.md](SCRIPTING.md#sip)):
  `encode` and `decode` between SIP messages and tables, over `osip_message_parse` and
  `osip_message_to_str`. Both roles run from scripts over `kraken/socket`. oSIP 5.3.2 (LGPL-2.1)
  is vendored in `vendor/osip` with no source changes: the parser library only, not its
  transaction layer, which uses threads and timers.
- **Why best:** the SIP grammar is large and exacting (Via, From/To, URIs, digest challenges,
  SDP), and oSIP is the established small C parser that does no I/O.
- **Behavior to know:** oSIP writes a message in its own normal form (its header order and
  capitalization, one Via per line), refuses what it cannot parse, and discards a body without
  a `Content-Type`. So `protocols/sip` cannot send malformed messages or reproduce the exact
  bytes received.
- **Not yet:** oSIP's parsers for the values inside headers (URIs, Via, digest challenges,
  SDP) and its MD5, which digest authentication needs, are compiled in but not exposed.

## Planned

- **NTP and syslog** — tiny wire formats over UDP. No library worth vendoring was found for
  NTP (the real ones are daemons that own their sockets), so these are codecs of Kraken's own,
  in the style of `protocols/tftp`.
- **RADIUS** — research first: which library, and whether it has a transport seam.

## Future work

- **NFS** — libnfs, by libsmb2's author, so the seam is probably patchable the same way.
- **HTTP/2** and **Kerberos**, described above.
- **LDAP StartTLS**, described under LDAP.

## Out of scope

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
4. **Telnet** — done, with libtelnet.
5. **SSH (wolfSSH)** — done; exec sessions (client and server) over the same
   I/O-callback shim as TLS.
6. **SMB and LDAP** — done, as clients, then **SNMP** and **TFTP**, also done.
7. **Telnet** and **SIP**, done. **Next:** mail protocols (libetpan, once its seam is
   checked), **NTP**, **syslog**, then **RADIUS**.
