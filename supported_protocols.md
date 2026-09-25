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
other merits. Secondary priorities, in order: small binary-size impact, and low
build/embedding friction (single file or few files, no heavy build system).

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
| DNS (rich records) | Both | SPCDNS | Codec | Directory services |
| LLMNR / mDNS / NBT-NS | Both | SPCDNS (reuse) | Codec | Directory services |
| LDAP | Both | OpenLDAP liblber / libldap | Codec + `ber_sockbuf` | Directory services |
| SMB / DCERPC | Both | libsmb2 | fd + event seam | Directory services |
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

## Directory services

Enterprise environments run on DNS, LDAP, SMB/DCERPC and Kerberos, over TLS and
HTTP. Together these let an identity participate in a directory environment as a
full peer — resolving names, binding, and exchanging authenticated requests.

### DNS, rich records — SPCDNS
- **Why best:** `dns_encode` / `dns_decode` are pure buffer codecs that never
  allocate (memory is passed in; roughly 1.3k LOC, one directory). Needed only
  for record types beyond the A/PTR that wolfIP already resolves — SRV, TXT, MX,
  which the directory, Kerberos and LDAP workflows depend on. DNS-over-TCP is the
  same output with a 2-byte length prefix.
- **Alternatives:** sldns (Unbound's `sldns_buffer` codec) — similar philosophy,
  slightly heavier. ldns — only if full DNSSEC validation is later required; it
  is a large, resolver-oriented toolkit and a poor size fit otherwise.

### LLMNR / mDNS / NBT-NS — SPCDNS (reused)
- **What it is:** the link-local name-resolution protocols that sit alongside
  DNS on a segment. An identity may need to answer them to be reachable by name,
  or to query them, the same as any other host on the LAN.
- **Why cheap:** LLMNR and mDNS use the DNS wire format and NBT-NS is DNS-like,
  so this reuses the SPCDNS codec with little new code. Both the query and answer
  sides fall out of the same encoder/decoder.

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
- **Why best:** fully async and non-blocking, and it exposes its socket through
  `smb2_get_fd` / `smb2_get_fds` / `smb2_which_events` plus fd-change callbacks.
  Kraken drives it from its own loop and hands it a wolfIP descriptor. Decisive
  evidence it works: it has already been built against lwIP userspace stacks on
  embedded targets — Kraken's exact pattern. The seam is an fd/event model, not
  compile-time macro swaps, which is cleaner to maintain.
- **Alternative:** none worth it. Samba's libsmbclient is far heavier and
  assumes a full OS.

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

1. **TLS (wolfSSL) shim** — the shared foundation; HTTPS and every TLS-wrapped
   protocol depend on it, and it is the smallest piece that proves the I/O-seam
   pattern.
2. **HTTP(S) via picohttpparser** — the most common protocol in lab work, and
   the first real payload on top of the TLS seam.
3. **DNS rich records and the LLMNR / mDNS / NBT-NS family** — one SPCDNS codec
   covers all of them, cheaply, and unlocks the directory workflows.
4. **Modbus and MQTT** — open the OT/IoT surface cheaply, in both directions.
5. **SSH (wolfSSH)** — a large protocol with minimal integration risk, since it
   reuses the same I/O-callback shim as TLS.
6. **LDAP, SMB, Kerberos, SNMP** and the text protocols, as directory and
   device work calls for them.
