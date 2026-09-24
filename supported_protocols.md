# Application Protocols

This document plans the application-layer protocols Kraken aims to support, the
library chosen for each, why, and what alternatives to keep in reserve. It is a
research summary and a roadmap, not an implementation guide.

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

| Protocol | Client / Server | Best option | Integration | Priority |
| --- | --- | --- | --- | --- |
| TLS | Both | wolfSSL | I/O callback | Foundational |
| HTTP(S) | Both | picohttpparser + own I/O | Codec | Foundational |
| DNS (rich records) | Both | SPCDNS | Codec | AD / enterprise |
| LLMNR / mDNS / NBT-NS | Server | SPCDNS (reuse) | Codec | Tier 1 |
| LDAP | Both | OpenLDAP liblber / libldap | Codec + `ber_sockbuf` | AD / enterprise |
| SMB / DCERPC | Both | libsmb2 | fd + event seam | AD / enterprise |
| Kerberos | Both | Heimdal | Awkward; scope first | AD / enterprise |
| Modbus/TCP | Both | nanomodbus | Codec / transport hooks | Tier 1 |
| MQTT | Both | Paho embedded (MQTTPacket) | Codec | Tier 1 |
| SSH | Both | wolfSSH | I/O callback | Tier 2 |
| SNMP | Both | Reuse BER layer | Codec | Tier 2 |
| CoAP | Both | microcoap | Codec | Tier 2 |
| SMTP / FTP / Telnet / POP3 / IMAP | Both | None (line-based) | Own I/O | Tier 3 |
| TFTP | Both | wolfIP flag | Built in | Tier 3 |

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

## Active Directory / enterprise

Kerberos, LDAP, SMB/DCERPC, DNS, HTTP and TLS together cover most of the
enterprise attack surface.

### DNS, rich records — SPCDNS
- **Why best:** `dns_encode` / `dns_decode` are pure buffer codecs that never
  allocate (memory is passed in; roughly 1.3k LOC, one directory). Needed only
  for record types beyond the A/PTR that wolfIP already resolves — SRV, TXT, MX,
  which the AD, Kerberos and LDAP workflows depend on. DNS-over-TCP is the same
  output with a 2-byte length prefix.
- **Alternatives:** sldns (Unbound's `sldns_buffer` codec) — similar philosophy,
  slightly heavier. ldns — only if full DNSSEC validation is later required; it
  is a large, resolver-oriented toolkit and a poor size fit otherwise.

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

## LAN spoofing and discovery

Kraken's strongest niche: being an arbitrary, spoofed host on the segment.

### LLMNR / mDNS / NBT-NS responder — SPCDNS (reused)
- **Why high value:** name-resolution spoofing (Responder-style) is core to AD
  labs and works only because the tool is a host on the segment answering
  broadcast/multicast queries — exactly Kraken. The server (responder) side is
  the prize; the client side is trivial.
- **Why cheap:** LLMNR and mDNS use the DNS wire format and NBT-NS is DNS-like,
  so this reuses the SPCDNS codec with little new code.

## IoT / OT

### Modbus/TCP — nanomodbus
- **Why best:** the default OT/ICS lab protocol, with dead-simple fixed binary
  framing (7-byte MBAP header plus PDU). Both a fake-PLC server and an attacking
  client are small. nanomodbus is transport-agnostic by design — the caller
  provides read/write functions — so it never owns a socket.
- **Alternative:** libmodbus is more established but opens its own sockets;
  usable only if a redirection seam is added, which nanomodbus avoids entirely.

### MQTT — Eclipse Paho embedded (MQTTPacket)
- **Why best:** ubiquitous IoT protocol, simple binary framing, and a classic
  fuzz target (auth bypass, topic injection, malformed packets). A fake broker
  catches misbehaving clients; a client exercises real brokers. Paho's
  MQTTPacket is serialization-only — Kraken owns the transport — matching the
  codec model exactly.
- **Alternative:** MQTT-C — also transport-agnostic, single-pair of files; a
  reasonable fallback if Paho's layering proves awkward.

### CoAP — microcoap
- **Why best:** the UDP IoT counterpart to HTTP, with a simple 4-byte header plus
  options. microcoap is tiny and transport-agnostic.
- **Alternative:** libcoap is more complete but manages its own sockets; only
  worth it if CoAP features beyond basic request/response are needed.

### SNMP — reuse the BER layer
- **Why this shape:** high value for network-gear and IoT labs (a fake agent is a
  good fuzz surface; a manager enumerates real gear), and SNMP is ASN.1/BER, so
  it reuses the LDAP BER work rather than pulling in net-snmp, which is heavy and
  owns its transport.
- **Alternative:** net-snmp only if its full MIB tooling is genuinely required.

## Text protocols (Tier 3)

SMTP, FTP, Telnet, POP3 and IMAP are line-based text. No library is needed — a
small reader over a wolfIP socket suffices, so no dependency is justified. Useful
sides: SMTP server (open-relay / spoofing tests), FTP server (fuzz clients),
Telnet client (embedded gear). Add opportunistically.

TFTP is already available behind wolfIP's build flag; trivial UDP, common in OT
and boot-infrastructure labs. Near-free to enable.

## Out of scope

- **NTP / SNTP** — no small, buffer-only library exists; real NTP libraries are
  daemons that own their sockets. Dropped.
- **RDP** — enormous, no clean embeddable stack; poor size-to-effort ratio.
- **Full database wire protocols (Postgres, MySQL)** — very application-specific;
  only for a targeted engagement. Redis RESP is the exception: trivially simple
  and a good fuzz target if it comes up.
- **DNP3, BACnet** — real OT value but niche; add only on demand.

## Suggested order

1. **TLS (wolfSSL) shim** — the shared foundation; HTTPS and every TLS-wrapped
   protocol depend on it, and it is the smallest piece that proves the I/O-seam
   pattern.
2. **LLMNR / mDNS / NBT-NS responder** — highest value, nearly free via SPCDNS,
   and the task Kraken is uniquely suited to.
3. **Modbus and MQTT** — open the OT/IoT surface cheaply, in both directions.
4. **SSH (wolfSSH)** — a large target with minimal integration risk, since it
   reuses the same I/O-callback shim as TLS.
5. **SNMP via the BER layer**, and the text protocols, opportunistically.
