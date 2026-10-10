# Scripting Kraken

Kraken runs Lua in two ways. Both get the same environment and modules; they
differ only in when they run and what they receive.

| | Transport script | Global script |
| --- | --- | --- |
| Runs | Once for each frame of the identity that selects it | Once when Run is pressed |
| Entry point | `transport(bytes, identity, direction)` | The script body |
| Lua state | New for each frame | One per run |
| Memory | 500 KiB | 64 MiB |

Scripts are trusted Lua with the full standard library; Kraken does not sandbox
file, process, or host access. `print(...)` writes to the session log (up to
8 KiB per message). Scripts are limited to 50 KiB of source.

## Environment

| Module | Provides |
| --- | --- |
| `kraken/packet` | Decode, edit, encode, and fragment Ethernet frames |
| `kraken/transmit` | `transmit(identity, bytes, direction)` |
| `kraken/socket` | TCP, UDP, and raw IPv4 sockets through an identity |
| `kraken/identities` | Create, start, stop, and configure identities |
| `kraken/globals` | A table shared by every script |
| `kraken/std` | `sleep(milliseconds)` |
| `protocols/http` | Encode and parse HTTP/1.x messages |
| `protocols/dns` | Encode and decode DNS, mDNS and LLMNR messages |
| `protocols/tls` | TLS 1.2 and 1.3 client and server sessions over a TCP socket |
| `protocols/ssh` | SSH exec: run one command as client or serve one as server |
| `protocols/smb` | SMB2/3 file and directory client over a TCP socket |
| `protocols/dcerpc` | DCERPC client over TCP or SMB named pipes |
| `protocols/ldap` | LDAPv3 client over a TCP socket |
| `protocols/tftp` | Encode and decode TFTP packets |
| `protocols/snmp` | Encode and decode SNMP v1 and v2c messages |
| `protocols/telnet` | Telnet session over a TCP socket: data and commands separated |
| `protocols/sip` | Encode and decode SIP messages (GNU oSIP) |
| `protocols/smtp` | SMTP client over a TCP socket or TLS session (libetpan) |
| `protocols/pop3` | POP3 client over a TCP socket or TLS session (libetpan) |
| `protocols/imap` | IMAP client over a TCP socket or TLS session (libetpan) |

Save scripts in `scripts/global/`, `scripts/transport/`, and helper modules in
`scripts/helpers/`. Helpers load with `require`:

```lua
local flow = require("flow") -- loads helpers/flow.lua
```

Each transport callback has a budget of about 1,000,000 Lua instructions;
sleeping and waiting on sockets do not consume it. Global scripts have no
budget and run until they finish or are stopped. Each run has a fixed memory
arena, 500 KiB for a transport callback and 64 MiB for a global script, and the
Lua garbage collector reclaims memory within it. `collectgarbage("stop")` works
as usual.

Errors raise Lua errors and can be caught with `pcall`. Uncaught errors are
logged. Blocking host calls such as `os.execute` cannot be interrupted.

## Transport scripts

A transport script defines `transport(bytes, identity, direction)`. `identity`
is the identity's name; `direction` is `"inbound"` (from the interface toward
the identity) or `"outbound"` (from the identity toward the interface).

```lua
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    local frame = packet.decode(bytes)
    if frame.ip then print(direction, packet.ipv4(frame.ip.src), packet.ipv4(frame.ip.dst)) end
    transmit(identity, bytes, direction)
end
```

With no transport selected, frames pass through unchanged. With one selected,
the script decides: a frame is dropped unless the script sends it. It may send
it modified, several times, or send different frames entirely.

- Each frame starts from a fresh Lua state. Keep state across frames in
  `kraken/globals`.
- Up to 100 transport callbacks run at once across all identities. Further
  frames are dropped and logged. Sleeping or waiting on a socket holds a slot.
- Callbacks run in parallel, so frames can leave in a different order than
  they arrived. This is by design. Kraken does not preserve, restore, or
  defend frame order, and does not intend to.
- A failing script does not fall back to forwarding. Fix it or clear the
  selection to restore traffic.
- The source is loaded when the transport is selected or the identity starts.
  Saving the file does not change the running copy; select it again.
- Stopping an identity does not interrupt callbacks already running.
- Socket traffic passes through the identity's transport too. A transport must
  forward ARP and every packet the socket workflow needs.

The included `transport/ipv4_fragment.lua` fragments outbound IPv4 datagrams.

## Global scripts

A global script runs the current editor contents when Run is pressed; it does
not need to be saved. One global script runs at a time. Cancel interrupts Lua,
`sleep`, and pending socket calls. It does not undo identity changes, so stop
identities explicitly when an experiment ends.

```lua
local identities = require("kraken/identities")

identities.create({
    name = "researcher",
    ip = "192.0.2.10",
    prefix = "24",
    interface = "eth0",
    mac = "02:11:22:33:44:55",
})
identities.set_transport("researcher", "filter.lua")
identities.start("researcher")
```

The included `global/identity_window.lua` runs an identity for a timed window.

## Sending frames

`transmit(identity, bytes, direction)` injects a raw Ethernet frame into a
running identity. Inbound frames enter its IPv4 stack; outbound frames go out
its interface. It bypasses that identity's transport script, and does not
parse, repair checksums, or confirm delivery.

Forward within a transport by passing the callback's own `identity` and
`direction`, or target another identity or direction. Frames are limited to
2,048 bytes. The identity's MTU controls stack-generated IPv4 fragmentation;
inbound frames pass to lwIP without an additional MTU check.

## Packets

| Function | Result |
| --- | --- |
| `packet.decode(bytes)` | A packet table parsed from an Ethernet frame |
| `packet.encode(frame [, fix_checksums])` | Frame bytes; checksum repair defaults to `true` |
| `packet.fragment(frame, mtu [, fix_checksums])` | A list of IPv4 fragment tables |
| `packet.ipv4(value)`, `packet.mac(value)` | Text to address integer, or address integer to canonical text |

| Table | Fields |
| --- | --- |
| `frame.eth` | `src`, `dst` (48-bit address integers), `type` |
| `frame.vlan[i]` | `priority`, `dei` (0 or 1), `id`, `etype` (encapsulated EtherType) |
| `frame.arp` | `hw_type`, `hw_size`, `proto_type`, `proto_size`, `opcode`, `src_hw_mac`, `src_proto_ipv4`, `dst_hw_mac`, `dst_proto_ipv4`, `data` |
| `frame.ip` | `version`, `hdr_len`, `dsfield`, `len`, `id`, `flags`, `frag_offset`, `ttl`, `proto`, `checksum`, `src`, `dst` (32-bit address integers), `options` |
| `frame.tcp` | `srcport`, `dstport`, `seq`, `ack`, `hdr_len`, `flags`, `window_size_value`, `checksum`, `urgent_pointer`, `options`, `payload` |
| `frame.udp` | `srcport`, `dstport`, `length`, `checksum`, `payload` |
| `frame.icmp` | `type`, `code`, `checksum`, `rest_of_header`, `data` |

- Header fields are unsigned integers with their wire widths. `hdr_len` is
  exposed in bytes and must be a multiple of four up to 60; `frag_offset` is
  in eight-byte units. Options, payloads and unparsed data are byte strings.
- IPv4 `flags` is three bits: RB=`4`, DF=`2`, MF=`1`. TCP `flags` is twelve
  bits: reserved=`0xe00`, AE=`0x100`, CWR=`0x80`, ECE=`0x40`, URG=`0x20`,
  ACK=`0x10`, PSH=`0x08`, RST=`0x04`, SYN=`0x02`, FIN=`0x01`.
  IPv4 `dsfield` is the complete byte: DSCP is the upper six bits and ECN the
  lower two. Use Lua bit operations to inspect or change any of these bits.
- `vlan` is always present, empty when untagged.
- IPv4 and MAC addresses are unsigned 32-bit and 48-bit integers in wire
  order. `packet.ipv4("10.0.0.1")` returns `0x0a000001`; passing that integer
  returns `"10.0.0.1"`. `packet.mac` behaves the same way with colon-separated
  hexadecimal text (input also accepts `-`). Equality uses Lua's integer
  comparison. Addresses no longer use userdata, byte indexing or `tostring`
  formatting; use the conversion helpers and bit operations instead:

  ```lua
  frame.ip.src = (frame.ip.src & 0xffffff00) | 42
  frame.ip.flags = frame.ip.flags | 2 -- set DF
  frame.tcp.flags = frame.tcp.flags & ~0x02 -- clear SYN
  ```

- Unparsed data stays raw: `frame.data` after Ethernet, or `frame.ip.data`
  after IPv4 (including non-initial fragments). When encoding, `data` is the
  bytes that follow the last header you gave: `{data = bytes}` alone is exactly
  those bytes, `eth` with `data` follows the Ethernet and VLAN headers, and `ip`
  with `data` (and no `tcp`, `udp` or `icmp`) follows the IPv4 header and
  options. `data` can hold any protocol or any bytes.

`encode` writes every field as given: it never checks `options`,
`rest_of_header`, `payload` or `data` against `hdr_len`, `len` or `length`, so
inconsistent and truncated packets can be built deliberately. It repairs IPv4,
TCP, UDP, and ICMP checksums; pass `false` to keep the table's values as-is,
including deliberately incorrect ones. Repair needs a consistent IPv4 packet and
raises an error for one whose lengths disagree, and it also fixes the IPv4
header of `{data = bytes}` when those bytes are an Ethernet IPv4 frame, so pass
`false` to get exact bytes. It never repairs lengths. After resizing a payload
or options, update them yourself:

- UDP: `udp.length = 8 + #udp.payload`, `ip.len = ip.hdr_len + udp.length`
- TCP: `ip.len = ip.hdr_len + tcp.hdr_len + #tcp.payload`
- Options: `hdr_len = 20 + #options`, with the options padded to a multiple of 4 bytes.

`fragment` splits an IPv4 packet so each fragment's IPv4 size fits `mtu`
(20–65535). It keeps Ethernet/VLAN headers and DF, sets lengths, offsets, MF,
copied options, and IPv4 checksums. It does not send anything. Transport scripts
see inbound fragments individually; lwIP handles reassembly after injection.

## Sockets

`kraken/socket` opens sockets on a running identity's interface in the shared
lwIP stack, not the host's.

```lua
local socket = require("kraken/socket")
local client = socket.tcp.connect("researcher", "192.0.2.20", 8080, 3000)
client:send("request")
local reply = client:receive(2, 3000)
client:close()
```

| Call | Result |
| --- | --- |
| `socket.tcp.connect(name, address, port [, timeout_ms])` | Connected TCP socket |
| `socket.tcp.bind(name, address, port)` | Bound TCP socket; call `listen()` |
| `socket.udp.connect(name, address, port)` | Connected UDP socket |
| `socket.udp.bind(name, address, port)` | Bound UDP socket |
| `socket.raw.open(name, protocol)` | Raw IPv4 socket; protocol 0–255 |
| `tcp:listen([backlog])` | Start listening; backlog defaults to 1 |
| `tcp:accept([timeout_ms])` | Peer socket, source address, source port |
| `socket:send(data [, timeout_ms])` | Send all TCP or connected-UDP data |
| `udp:send(data, address, port [, timeout_ms])` | Send one datagram from a bound socket |
| `raw:send(data, address [, timeout_ms])` | Send one IPv4 payload to the supplied destination; lwIP builds the IPv4 header |
| `tcp:receive(count [, timeout_ms])` | Up to `count` bytes (1–32768) once any arrive; `nil` after the peer closes |
| `udp:receive([timeout_ms])` | One datagram, source address, source port |
| `raw:receive([timeout_ms])` | One IPv4 packet (no Ethernet) and its source address |
| `socket:close()` | Release the socket |

- Addresses are numeric IPv4 strings. No hostname lookup. TCP and UDP binds
  to `0.0.0.0` use the selected identity's address.
- No timeout waits indefinitely; `0` polls. Timeouts raise an error.
- A TCP send that fails partway raises an error without reporting how much
  was sent.
- UDP and raw receives can hold a full IPv4 datagram.
- All identities share lwIP's 256-slot socket table.
- Sockets are closed when the script ends or is cancelled. Restarting an
  identity invalidates its sockets.
- Raw sockets receive copies; the stack still answers normally. Raw sends
  supply the payload and destination; lwIP builds the IPv4 header. Transport
  checksums are the caller's responsibility. lwIP handles IPv4 fragmentation.
- On virtual links, checksum offload can leave captured packets with bad
  checksums. A transport forwarding `packet.encode(packet.decode(bytes))`
  repairs complete frames; raw forwarding can make socket calls time out.

## Identities

| Call | Effect |
| --- | --- |
| `identities.create({ name, ip, prefix, interface, gateway, mac, mtu })` | Save a new identity; the name must be unused |
| `identities.delete(name)` | Delete a stopped identity |
| `identities.start(name)` / `identities.stop(name)` | Start or stop it |
| `identities.set_transport(name, script)` | Select a saved transport file (with `.lua`), or `nil` to clear |
| `identities.set_bpf(name, expression)` | Replace a running identity's capture filter; `nil` or `""` restores the default |

Calls return once applied. Fields use the UI's text format and are limited to
128 bytes; an empty prefix means `/24`, an empty MTU `1500`. Starting needs an
interface, IPv4 address, and MAC.

A BPF expression replaces the whole capture filter, e.g. `"tcp"` captures all
TCP regardless of destination. It only affects inbound capture. An invalid
expression is logged and the previous filter stays. BPF lasts until the
identity stops and is never saved.

## Globals

`kraken/globals` holds one table shared by every script until Kraken exits.

```lua
local globals = require("kraken/globals")
local state = globals.get()
state.frames = (state.frames or 0) + 1
globals.set(state)
```

- `get()` returns a copy; `set(table)` replaces it. A `get`/`set` pair is not
  atomic.
- Keys: booleans, numbers, strings. Values: those plus nested tables (up to 32
  levels). Store address integers directly, or format them with
  `packet.ipv4`/`packet.mac`.
- Up to 3 MiB encoded. A failed `set` clears the table. `get()` must fit the
  calling script's memory.

## Protocols

`protocols/http` and `protocols/dns` convert between bytes and tables and do no
I/O: move the bytes with `kraken/socket` or `transmit`, so they work for
clients, servers, and transport scripts alike. `protocols/tls` wraps a TCP
socket in a session with the same `send`/`receive` shape, so the codecs run over
it unchanged; HTTPS is `protocols/http` over a TLS session. `protocols/ssh`
is a session of the same shape that runs a single command over SSH, and `protocols/telnet` one
that strips Telnet's commands from the stream and reports them as events.

### HTTP

```lua
local http = require("protocols/http")
local socket = require("kraken/socket")

local client = socket.tcp.connect("researcher", "192.0.2.20", 80, 3000)
client:send(http.request({
    method = "GET",
    path = "/",
    headers = { { "Host", "192.0.2.20" }, { "Connection", "close" } },
}))
local data, head, length = ""
repeat
    data = data .. (client:receive(4096, 3000) or error("closed before the head"))
    head, length = http.parse_response(data)
until head
print(head.status, head.reason, #data - length .. " body bytes so far")
client:close()
```

| Function | Result |
| --- | --- |
| `http.request({ method, path [, version, headers, body] })` | Request bytes |
| `http.response({ status [, reason, version, headers, body] })` | Response bytes |
| `http.parse_request(bytes)` | `{ method, path, version, headers }` and the head length, or `nil` |
| `http.parse_response(bytes)` | `{ status, reason, version, headers }` and the head length, or `nil` |
| `http.dechunk(bytes)` | The decoded body and the bytes after it, or `nil` |

- `headers` is an ordered list of `{ name, value }` pairs, so order, case and
  duplicates are kept exactly.
- `version` is the text after `HTTP/`, `"1.1"` by default. `reason` and `body`
  default to `""`.
- Encoding emits every field as given. It does not validate, add
  `Content-Length`, or reject CR/LF, so malformed and smuggling-style messages
  can be built deliberately. Set `Content-Length` or `Transfer-Encoding`
  yourself.
- Parsing reads only the head, up to 64 headers. `nil` means the head is
  incomplete: read more and parse again from the start. A malformed head raises
  an error. The body starts after the returned head length; frame it with the
  message's `Content-Length`, `Transfer-Encoding`, or connection close.
- A folded continuation line comes back as its own entry: an empty name and the
  line as its value.
- `dechunk` takes the bytes after the head. It returns `nil` until the final
  chunk and trailer have arrived, and raises an error on malformed chunking.

### DNS

```lua
local dns = require("protocols/dns")
local socket = require("kraken/socket")

local udp = socket.udp.connect("researcher", "192.0.2.53", 53)
udp:send(dns.encode({
    id = 0x1234,
    flags = { rd = true },
    questions = { { name = "example.com", type = dns.types.MX } },
}))
local reply = dns.decode((udp:receive(3000))) -- only the datagram
for _, record in ipairs(reply.answers) do
    print(record.name, record.ttl, record.preference, record.exchange)
end
udp:close()
```

| Function | Result |
| --- | --- |
| `dns.encode(message)` | Message bytes |
| `dns.decode(bytes [, raw])` | A message table; with `raw = true` every record is left raw |
| `dns.types` | Record type numbers by name, e.g. `dns.types.SRV == 33` |

A message table has `id`, `opcode`, `rcode`, `flags` (booleans `qr`, `aa`,
`tc`, `rd`, `ra`, `ad`, `cd`), `questions`, `answers`, `authority`, and
`additional`. Numbers default to `0` and flags to `false` when encoding.

- A question is `{ name, type [, class] }`. A record is
  `{ name, type [, class, ttl], ...fields }`. `class` defaults to `1` (IN) and
  `ttl` to `0`. Types and classes are numbers, so any value can be used,
  including the mDNS top bit (`class = 0x8001`).
- Names are in presentation form without the trailing dot, e.g.
  `"_ldap._tcp.example.com"`; `""` is the root.
- A record with a `raw` field is sent as-is: `raw` holds its RDATA bytes and
  `type` its type number. Decoding produces the same shape for types Kraken
  does not parse, and for every record when `raw` is true. Use it for record
  types without fields below, deliberately malformed RDATA, and types that
  reuse a known number with another meaning (NBT-NS NBSTAT is type 33, SRV's
  number).
- Messages may have any number of questions, including none (mDNS responses),
  and any opcode (NBT-NS uses 5-8). Rcodes above 15 need an OPT record.
- Encoding validates field types and ranges and raises an error; decoding
  raises an error on a malformed message. The header's reserved Z bit is not
  exposed.

Fields by record type:

| Type | Fields |
| --- | --- |
| A, AAAA | `addr` (IPv4 or IPv6 text) |
| NS | `nsdname` |
| CNAME | `cname` |
| PTR | `dname` |
| SOA | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` |
| MX | `preference`, `exchange` |
| TXT | `data` (list of strings) |
| SRV | `priority`, `weight`, `port`, `target` |
| HINFO | `cpu`, `os` |
| NAPTR | `order`, `preference`, `flags`, `services`, `regexp`, `replacement` |
| OPT | `udp_size`, `version`, `flags`, `options` |
| CAA | `critical`, `tag`, `value` |
| URI | `priority`, `weight`, `target` |
| SVCB, HTTPS | `priority`, `target`, `params` |
| TLSA | `cert_usage`, `selector`, `match`, `data` |
| SSHFP | `algorithm`, `fp_type`, `fingerprint` |
| DS | `key_tag`, `algorithm`, `digest_type`, `digest` |
| DNSKEY | `flags`, `protocol`, `algorithm`, `public_key` |
| SIG, RRSIG | `type_covered`, `algorithm`, `labels`, `original_ttl`, `expiration`, `inception`, `key_tag`, `signers_name`, `signature` |
| NSEC | `next_domain`, `type_bit_maps` |
| NSEC3 | `hash_algorithm`, `flags`, `iterations`, `salt`, `next_hashed_owner`, `type_bit_maps` |
| NSEC3PARAM | `hash_algorithm`, `flags`, `iterations`, `salt` |

`options` and `params` are lists of `{ code, value }` pairs. Binary fields
(keys, digests, signatures, salts, bit maps) are byte strings.

### TLS

```lua
local socket = require("kraken/socket")
local tls = require("protocols/tls")
local http = require("protocols/http")

local tcp = socket.tcp.connect("researcher", "192.0.2.20", 443, 3000)
local session = tls.connect(tcp, {
    server_name = "example.com",
    alpn = { "http/1.1" },
}, 3000)
session:send(http.request({
    method = "GET",
    path = "/",
    headers = { { "Host", "example.com" }, { "Connection", "close" } },
}))
local data, head, length = ""
repeat
    data = data .. (session:receive(4096, 3000) or error("closed before the head"))
    head, length = http.parse_response(data)
until head
print(head.status, session:info().version)
session:close()
```

| Call | Result |
| --- | --- |
| `tls.connect(tcp [, options [, timeout_ms]])` | Client session over a connected TCP socket, after the handshake |
| `tls.accept(tcp, options [, timeout_ms])` | Server session over an accepted TCP socket; needs `certificate` and `key` |
| `session:send(data [, timeout_ms])` | Encrypt and send all of `data` |
| `session:receive(count [, timeout_ms])` | Up to `count` (1–32768) decrypted bytes once any arrive; `nil` after the peer closes |
| `session:info()` | `{ version, cipher, alpn, server_name, peer_certificates }` |
| `session:close()` | Send close_notify, end the session, and close the TCP socket |

| Option | Meaning |
| --- | --- |
| `server_name` | Client: the SNI name, also checked against the certificate when `verify` is set. Server: the name it answers to; a client asking for another name is refused, one sending no name is accepted, and `info().server_name` reports the client's request |
| `alpn` | Protocols in preference order, e.g. `{ "h2", "http/1.1" }`; no match does not fail the handshake |
| `verify` | `true` verifies the peer's certificate against `ca`; default `false` accepts any certificate. On a server it requests a client certificate and verifies it if one is sent |
| `ca` | PEM CA certificates; required with `verify` |
| `certificate`, `key` | PEM certificate chain and private key; required by `accept`, optional client certificate for `connect` |
| `version` | `"1.2"` or `"1.3"` to allow only that version; by default either is negotiated |

- The handshake timeout is the trailing argument, like every socket call; by
  default the handshake waits indefinitely, and `0` polls.
- The session takes over its TCP socket; use only the session afterwards. The
  socket's limits still apply, and `session:close()` closes it.
- A receive timeout raises `socket call timed out` and leaves the session
  usable. A send timeout or any other TLS error ends the session.
- `info().alpn` is absent when no protocol was agreed. `peer_certificates` is
  the peer's certificate chain as DER strings, empty when the peer sent none.
- TLS 1.2 and 1.3 only, with RSA, ECDSA and Ed25519 certificates and AES-GCM or
  ChaCha20-Poly1305 ciphers.

The [HTTP experiment](examples/http/README.md) runs the same HTTP code over TCP
and over TLS, in both directions, against Python's `ssl` module.

### SMB

`protocols/smb` is a client over an already-connected TCP socket on port 445.
The session owns that socket. Paths are relative to the connected share. Each
read returns up to 32 KiB; write sends all supplied bytes. Use offsets to read
larger files.

```lua
local socket = require("kraken/socket")
local smb = require("protocols/smb")
local tcp = socket.tcp.connect("researcher", "192.0.2.20", 445, 5000)
local share = smb.connect(tcp, {
    server = "server.example", share = "test", username = "user",
    password = "secret", domain = "EXAMPLE", sign = true,
}, 5000)
share:write("probe.txt", "hello", 0, 5000)
assert(share:read("probe.txt", 5, 0, 5000) == "hello")
share:remove("probe.txt", 5000)
share:close()
```

`session:list(path [, timeout_ms])` returns entries with `name` and `stat`.
`session:stat(path [, timeout_ms])` returns `size`, `type`, `attributes`, and
`mtime`. Other methods are `read(path, count [, offset, timeout_ms])`,
`write(path, bytes [, offset, timeout_ms])`, `remove(path)`, `mkdir(path)`,
`rmdir(path)`, `rename(from, to)`, and `close()`; mutation methods also accept
a final timeout. `write` creates a missing file but does not truncate an
existing one. The [SMB and DCERPC experiment](examples/smb_dcerpc/README.md)
exercises this API against a Windows peer.

### DCERPC

`protocols/dcerpc` is a client over either a connected RPC/TCP endpoint or an
SMB connection on port 445. The session owns the supplied TCP socket. A call is
either a raw NDR stub for any interface, or a named procedure of a libdcerpc
service, written and read as libdcerpc's YAML.

```lua
local socket = require("kraken/socket")
local dcerpc = require("protocols/dcerpc")

local tcp = socket.tcp.connect("researcher", "192.0.2.20", 445, 5000)
local rpc = dcerpc.smb(tcp, {
    server = "server.example",
    service = "srvsvc",
    username = "user",
    password = "secret",
    domain = "EXAMPLE",
    sign = true,
}, 5000)
local reply = rpc:call("NetrShareEnum", [[
NetrShareEnum: Request
  InfoStruct:
    Level: 1
    ShareInfo:
  PreferedMaximumLength: 0xffffffff
]], 5000)
print(reply.NetrShareEnum.Status)
rpc:close()
```

| Call | Result |
| --- | --- |
| `dcerpc.tcp(tcp, options [, timeout_ms])` | Bind over an already-connected RPC/TCP endpoint |
| `dcerpc.smb(tcp445, options [, timeout_ms])` | Negotiate SMB, open the pipe, and bind it |
| `session:call(opnum, stub [, timeout_ms])` | Send a raw NDR stub for an opnum; returns the reply stub |
| `session:call(procedure, yaml [, timeout_ms])` | Call a named procedure; returns the reply as a table, then its YAML text |
| `session:template(procedure)` | The request as YAML with every field zero, to fill in |
| `session:close()` | Close protocol state and the TCP socket |

Options choose the interface: `service` (`srvsvc`, `lsarpc`, `wkssvc`, `winreg`,
`epmapper`) or `interface` (a UUID) with `version` (`"major.minor"`, default
`"1.0"`). `ndr` (`"32"`, `"64"` or `"both"`) sets the transfer syntax offered at
bind; libdcerpc's default is `"32"`. SMB also accepts `server`, `username`,
`password`, `domain`, `pipe` (required with `interface`), `sign`, and `seal`.
Direct TCP has no RPC authentication; connect to the service's resolved TCP
endpoint before calling `dcerpc.tcp`.

A raw call sends exactly the stub you give, in the negotiated transfer syntax,
and returns the reply stub with nothing decoded; `string.pack` and
`string.unpack` build and read NDR. Responses of any number of fragments are
reassembled, and a request larger than the server's fragment size is split. A
server fault raises an error with its status.

Named calls use libdcerpc's coders, so only its five services' procedures are
available. The request is YAML text whose top key is the procedure name; fields
must appear in the order of the procedure's struct, which `template` prints.
`NetrFileEnum`, `NetrServerSetInfo` and `NetrWkstaSetInfo` have no template;
use the `dcerpc-examples` YAML in libsmb2. libdcerpc reports a request decode
problem (such as a field out of order) on standard output.

The reply is a table keyed by procedure name: a mapping is a table, a sequence
an array, a plain integer (decimal or `0x` hex) a Lua integer, and any other
value a string; an empty value is absent. The second result is the reply's
exact YAML text. If libyaml cannot parse a reply, the first result is `nil`, the
second is still the text, and the third is the reason.

The [SMB and DCERPC experiment](examples/smb_dcerpc/README.md) checks SMB files,
DCERPC over SMB, and named and raw DCERPC over TCP port 135 against a Windows
peer.

### LDAP

`protocols/ldap` is an LDAPv3 client over an already-connected TCP socket, usually
port 389, or over a `protocols/tls` session for LDAPS, usually port 636. The session
owns the socket or TLS session. OpenLDAP's libldap does the protocol; the session is
anonymous until `bind`.

```lua
local socket = require("kraken/socket")
local ldap = require("protocols/ldap")

local tcp = socket.tcp.connect("researcher", "192.0.2.20", 389, 5000)
local conn = ldap.connect(tcp)
conn:bind("cn=admin,dc=example,dc=com", "secret", 5000)
local entries = conn:search({
    base = "dc=example,dc=com", scope = "sub", filter = "(cn=alice)", attributes = { "mail" },
}, 5000)
print(entries[1].dn, entries[1].attributes.mail[1])
conn:close()
```

| Call | Result |
| --- | --- |
| `ldap.connect(tcp)` or `ldap.connect(tls_session)` | A session over the connected socket or TLS session; sends nothing yet |
| `conn:bind(dn, password [, timeout_ms])` | Simple bind; empty strings bind anonymously |
| `conn:search(options [, timeout_ms])` | Entries as `{ dn = "...", attributes = { name = { value, ... } } }`, then referral URLs if any |
| `conn:add(dn, entry [, timeout_ms])` | `entry` maps attribute names to a string or an array of strings |
| `conn:modify(dn, changes [, timeout_ms])` | `changes` is an array of `{ op = "add" \| "delete" \| "replace", attribute = "...", values = { ... } }`, applied in order |
| `conn:delete(dn [, timeout_ms])` | Delete an entry |
| `conn:rename(dn, new_rdn [, options] [, timeout_ms])` | Rename or move; `options` is `{ parent = "...", keep_old = false }` |
| `conn:compare(dn, attribute, value [, timeout_ms])` | `true` or `false` |
| `conn:extended(oid [, value [, timeout_ms]])` | The response value, or `nil` |
| `conn:close()` | Unbind, then close the TLS session if any, and the socket |

`search` options are `base`, `scope` (`"base"`, `"one"`, `"sub"` by default, or
`"children"`), `filter` (default `"(objectClass=*)"`), `attributes` (an array; all
attributes when omitted), `limit` (entries, 0 for no limit) and `types_only`. A
search that hits the size limit returns the entries received. Values are strings
and may be binary. Attribute names keep the case the server returned.

An operation the server refuses raises an error naming the LDAP result, for
example `LDAP bind failed: Invalid credentials (49)`, and the session stays
usable. A timeout, a closed socket or a malformed reply raises and closes the
session. Referrals are returned, never followed.

For LDAPS, wrap the socket in a TLS session and hand that to `ldap.connect`; the LDAP
module does not know the traffic is encrypted. Certificate checks, the CA and the
server name are options of `tls.connect`, as for HTTPS:

```lua
local tls = require("protocols/tls")
local conn = ldap.connect(tls.connect(socket.tcp.connect("researcher", "192.0.2.20", 636, 5000), {
    server_name = "dc.example.com", verify = true, ca = ca_pem,
}, 5000))
```

There is no StartTLS or SASL yet; plain simple bind sends the password in clear text,
so use it only on a trusted lab network or over LDAPS.

### TFTP

`protocols/tftp` encodes and decodes TFTP packets (RFC 1350, with the option extension of
RFC 2347). Like `protocols/dns` it is only the codec: the script owns the UDP sockets and
runs the lock-step transfer, so every step stays under its control. A request goes to the
server's port, and the transfer then continues from the port the server answers on.

```lua
local socket = require("kraken/socket")
local tftp = require("protocols/tftp")

local udp = socket.udp.bind("researcher", "0.0.0.0", 6971)
udp:send(tftp.encode({ op = "rrq", filename = "boot.img", options = { blksize = 1024 } }), "192.0.2.69", 69)
local bytes, server, port = udp:receive(3000)
local packet = tftp.decode(bytes)        -- an oack, or the first data block
if packet.op == "oack" then
    udp:send(tftp.encode({ op = "ack", block = 0 }), server, port)
end
```

| Function | Result |
| --- | --- |
| `tftp.encode(packet)` | Packet bytes |
| `tftp.decode(bytes)` | A packet table; raises if there are fewer than 2 bytes |
| `tftp.ops` | Opcode numbers by name, e.g. `tftp.ops.oack == 6` |

A packet table has `op`, a name (`"rrq"`, `"wrq"`, `"data"`, `"ack"`, `"error"`, `"oack"`)
or a number, and:

| `op` | Fields |
| --- | --- |
| `rrq`, `wrq` | `filename`, `mode` (default `"octet"`), `options` |
| `data` | `block`, `data` |
| `ack` | `block` |
| `error` | `code`, `message` |
| `oack` | `options` |

`options` maps names to values (strings or numbers). Decoding always returns strings. When
encoding, `options` may instead be an array of `{ name, value }` pairs, which keeps their
order and any repeats. `block`, `code` and `op` are 0 to 65535, and `data` may be any
length, so oversized blocks, wrong block numbers and odd modes can be sent. When encoding,
`payload` replaces the fields: it is the whole body after the opcode, for opcodes this
module does not know or bytes you want exactly. Decoding turns an unknown opcode, or a
body that does not parse, into `{ op = name or number, payload = body }`.

The [TFTP experiment](examples/tftp/README.md) runs both roles against a Python peer.

### SNMP

`protocols/snmp` encodes and decodes SNMP v1 and v2c messages. Like `protocols/dns` it is only the
codec: the script owns the UDP sockets and decides what to send and how to read the answers, so
managers, walkers, agents and trap senders are all scripts. Nothing in the module limits what a
packet may contain.

```lua
local socket = require("kraken/socket")
local snmp = require("protocols/snmp")

local udp = socket.udp.bind("researcher", "0.0.0.0", 40161)
udp:send(snmp.encode({
    pdu = "get", request_id = 1,
    varbinds = { { oid = "1.3.6.1.2.1.1.1.0" } },       -- sysDescr.0
}), "192.0.2.1", 161)
local reply = snmp.decode((udp:receive(3000)))
for _, varbind in ipairs(reply.varbinds) do
    print(varbind.oid, varbind.type, varbind.value)
end
```

| Function | Result |
| --- | --- |
| `snmp.encode(message)` | Message bytes |
| `snmp.decode(bytes)` | A message table; what does not parse is left as `payload` |
| `snmp.pdus` | PDU type numbers by name, e.g. `snmp.pdus.getbulk == 5` |

A message table has `version` (`"v1"`, `"v2c"` by default, `"v3"` or a number), `community`
(`"public"`), `pdu`, and the PDU's fields:

| `pdu` | Fields |
| --- | --- |
| `get`, `getnext`, `response`, `set`, `inform`, `trapv2`, `report` | `request_id`, `error_status`, `error_index`, `varbinds` |
| `getbulk` | `request_id`, `non_repeaters`, `max_repetitions`, `varbinds` |
| `trap` (v1) | `enterprise`, `agent_address`, `generic_trap`, `specific_trap`, `timestamp`, `varbinds` |

`pdu` is a name or a number from 0 to 30. Numbers default to 0. `varbinds` is an array of
`{ oid, type, value }`. When encoding, `type` can be omitted: a number is an integer, a string an
octet string, and no value a null, which is what a request needs. The types are `integer`,
`octet_string`, `null`, `oid`, `ip_address`, `counter32`, `gauge32`, `time_ticks`, `opaque`,
`counter64`, `no_such_object`, `no_such_instance` and `end_of_mib_view`. Object IDs and IP
addresses are dotted strings. A `counter64` above 2^63 appears as a negative Lua integer; compare
it with `math.ult`. Anything else can be sent with `tag` (0 to 255) and `value`, the raw content
of that tag, and an object ID can be given as `oid_raw`, its raw BER content.

When encoding, `payload` replaces everything after the version with raw bytes, for v3 or for
anything this module does not build. Decoding returns what it could not parse as `payload`: a
v3 message after its version (the module does no v3 security), a PDU body that does not parse
(with the version, community and `pdu`), or a whole packet that is not SNMP. Values that do not fit
their type decode as `{ oid, tag, value }`.

The [SNMP experiment](examples/snmp/README.md) runs a manager, traps and an agent against net-snmp.

### Telnet

`protocols/telnet` wraps a connected TCP socket or TLS session in a session with the `send`/`receive` shape of
`protocols/tls`, using libtelnet. It removes Telnet's commands from the byte stream: what
`receive` returns is application data, and the commands arrive beside it as events. Telnet has
no handshake and is the same in both directions, so one constructor serves clients and servers.

```lua
local socket = require("kraken/socket")
local telnet = require("protocols/telnet")

local session = telnet.session(socket.tcp.connect("researcher", "192.0.2.20", 23, 3000), {
    us = { "terminal_type" },      -- options this side will perform when the peer asks
    them = { "echo", "sga" },      -- options it lets the peer perform
})
local data, events = session:receive(4096, 3000)
for _, event in ipairs(events) do
    if event.type == "subnegotiation" and event.option == telnet.options.terminal_type and event.data == "\1" then
        session:subnegotiate("terminal_type", "\0XTERM")
    end
end
session:send("root\r\n")
session:close()
```

| Call | Result |
| --- | --- |
| `telnet.session(tcp_or_tls [, options])` | Session over a connected TCP socket or a TLS session |
| `session:send(data [, timeout_ms])` | Send `data`, doubling any 255 byte |
| `session:receive(count [, timeout_ms])` | Once any bytes arrive, the application data (possibly empty) and a list of events; `nil` after the peer closes |
| `session:negotiate(command, option [, timeout_ms])` | Send `"will"`, `"wont"`, `"do"` or `"dont"` |
| `session:subnegotiate(option, data [, timeout_ms])` | Send IAC SB, the option, `data` with 255 bytes doubled, IAC SE |
| `session:command(command [, timeout_ms])` | Send IAC and a command |
| `session:close()` | End the session, then close the TLS session if any, and the TCP socket |
| `telnet.options`, `telnet.commands` | Option and command numbers by name, e.g. `telnet.options.naws == 31`, `telnet.commands.nop == 241` |

Options and commands are given as numbers or as the names in those tables. An event is a table:

| `type` | Fields |
| --- | --- |
| `will`, `wont`, `do`, `dont` | `option` |
| `subnegotiation` | `option`, `data` |
| `command` | `command` (a command other than a negotiation, e.g. NOP or GA) |
| `warning`, `error` | `message` (a protocol violation libtelnet recovered from, or could not) |

- The `us` and `them` lists make the library answer negotiation by itself (RFC 1143): a
  request for an option on a list is accepted and reported as an event, and any other
  is refused with no event. A refusal of a request the script made with `negotiate` is
  not reported either.
- `proxy = true` turns that off: every WILL, WONT, DO and DONT is reported, nothing is
  answered, and `negotiate` sends exactly what it is given. Use it to drive or observe
  negotiation by hand.
- `count` bounds the raw bytes read, so the data returned is never longer. A receive
  timeout raises `socket call timed out` and leaves the session usable; a send timeout or
  any other failure ends the session.
- Subnegotiations arrive as raw bytes whatever the option (terminal type, window size,
  environment). Data is not translated: CR and LF are the script's to send as it wishes.
  Compression (MCCP2) is not supported.

The [Telnet experiment](examples/telnet/README.md) connects to GNU inetutils' telnetd and serves
the host's telnet client.

### SIP

`protocols/sip` turns SIP messages into tables and back with GNU oSIP, and does no I/O. The sockets
(UDP, TCP or TLS), the transactions, the dialogs and the retransmissions are the script's, so user
agents, proxies and scanners are all scripts.

```lua
local socket = require("kraken/socket")
local sip = require("protocols/sip")

local udp = socket.udp.bind("researcher", "192.0.2.10", 5060)
udp:send(sip.encode({
    method = "OPTIONS", uri = "sip:192.0.2.20",
    headers = {
        { "Via", "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1" }, { "Max-Forwards", "70" },
        { "From", "<sip:me@192.0.2.10>;tag=1" }, { "To", "<sip:192.0.2.20>" },
        { "Call-ID", "1@192.0.2.10" }, { "CSeq", "1 OPTIONS" },
    },
}), "192.0.2.20", 5060)
local reply = sip.decode((udp:receive(3000)))
print(reply.status, reply.reason)
```

| Function | Result |
| --- | --- |
| `sip.encode(message)` | Message bytes |
| `sip.decode(bytes)` | A message table |

A request is `{ method, uri, version, headers, body }` and a response `{ status, reason, version,
headers, body }`; `headers` is a list of `{ name, value }` pairs. When encoding, `version` is the
text after `SIP/` (`"2.0"` by default) and `reason` and `body` default to nothing; a table with
`status` is a response. When decoding, `version` is `"SIP/2.0"`.

- oSIP parses each header into its own structure and writes it back in its own order and
  spelling. So `decode` returns oSIP's normal form of the message, not the bytes that arrived:
  compact names (`v`, `f`, `t`, ...) are expanded, each Via is its own header, and a header's
  name is capitalized as oSIP writes it (`Max-forwards`). `encode` does the same to what it is
  given, and adds `Content-Length` when there is none.
- oSIP refuses what it cannot parse, so `decode` and `encode` raise an error for a message it
  rejects (a bad start line, a malformed Via or From), and malformed messages cannot be built.
- A body needs a `Content-Type` header: oSIP discards one that has none when it parses a message.
- The module does not frame a stream. On UDP a datagram is a message; over TCP, find the end of
  the head and use `Content-Length` before calling `decode`.

The [SIP experiment](examples/sip/README.md) runs a client and a server against SIPp.

### SMTP

`protocols/smtp` is an SMTP client, from libetpan, over a connected TCP socket. It reads the
greeting, says EHLO, authenticates with AUTH PLAIN or LOGIN, sends messages and quits. SMTPS is
the same client over a `protocols/tls` session.

```lua
local socket = require("kraken/socket")
local smtp = require("protocols/smtp")

local mail = smtp.connect(socket.tcp.connect("researcher", "192.0.2.25", 25, 3000), { hostname = "lab.example" }, 3000)
mail:login("user", "password")
mail:send({ from = "a@lab.example", to = { "b@example.test" },
    message = "From: a@lab.example\r\nTo: b@example.test\r\nSubject: hi\r\n\r\nbody\r\n" })
mail:close()
```

| Call | Result |
| --- | --- |
| `smtp.connect(tcp [, options [, timeout_ms]])` | Session, after the greeting and EHLO |
| `smtp.connect(tls_session [, options [, timeout_ms]])` | The same over SMTPS |
| `session:login(user, password [, timeout_ms])` | AUTH PLAIN or LOGIN, whichever the server offers |
| `session:send({ from, to, message } [, timeout_ms])` | MAIL FROM, RCPT TO for each address, DATA |
| `session:info()` | `{ code, response, size, extensions, auth }` |
| `session:close()` | QUIT, end the session and close the socket |

- `options.hostname` is what EHLO announces, `"localhost"` by default; libetpan would use the
  host's own name, so a patch to the vendored library lets the script choose.
- `to` is an address or a list of addresses; `message` is the whole message, headers included.
  libetpan stuffs the dots and ends the data. Addresses longer than about 500 bytes are cut.
- `info()` reports the server's last response and what its EHLO offered: `extensions`
  (`size`, `starttls`, `8bitmime`, `pipelining`, `dsn`, ...) and `auth` (`plain`, `login`,
  `cram_md5`, ...) are tables of the names the server listed; `size` is its size limit.
- Only PLAIN and LOGIN are built in, and STARTTLS is not offered: use a TLS session for SMTPS.
- A server's refusal raises an error with its reply (`SMTP login failed: 535 ...`) and leaves
  the session usable. A timeout or a lost connection ends the session.

### POP3

`protocols/pop3` is a POP3 client, from libetpan, over a connected TCP socket or a TLS session
(POP3S).

```lua
local pop3 = require("protocols/pop3")

local mail = pop3.connect(socket.tcp.connect("researcher", "192.0.2.25", 110, 3000), 3000)
mail:login("user", "password")
for _, message in ipairs(mail:list()) do
    print(message.index, message.size, message.uidl)
end
print(mail:retrieve(1))
mail:close()
```

| Call | Result |
| --- | --- |
| `pop3.connect(tcp_or_tls [, timeout_ms])` | Session, after the greeting |
| `session:login(user, password [, timeout_ms])` | USER and PASS |
| `session:apop(user, password [, timeout_ms])` | APOP, using the greeting's timestamp |
| `session:stat([timeout_ms])` | Message count and total size |
| `session:list([timeout_ms])` | `{ { index, size, uidl }, ... }` |
| `session:retrieve(index [, timeout_ms])` | The whole message |
| `session:top(index, lines [, timeout_ms])` | Its headers and first `lines` lines |
| `session:delete(index [, timeout_ms])` | DELE; the server removes it when the session quits |
| `session:reset([timeout_ms])` | RSET |
| `session:info()` | `{ response }`, the server's last response line |
| `session:close()` | QUIT, end the session and close the socket |

- The first `list` asks the server (LIST, then UIDL; `uidl` is absent without UIDL) and keeps the
  answer; `retrieve`, `top` and `delete` find their message in it, so an index outside it
  fails before anything is sent.
- A refusal raises an error with the server's response and leaves the session usable. A timeout
  or a lost connection ends the session.

### IMAP

`protocols/imap` is an IMAP client, from libetpan, over a connected TCP socket or a TLS session
(IMAPS). libetpan builds each command from typed structures and parses the responses, so the
calls are the IMAP commands with their arguments checked first.

```lua
local imap = require("protocols/imap")

local box = imap.connect(socket.tcp.connect("researcher", "192.0.2.25", 143, 3000), 3000)
box:login("user", "password")
print(box:select("INBOX").exists .. " messages")
for _, message in ipairs(box:fetch("1:*", { "uid", "flags", "header" })) do
    print(message.number, message.uid, message.header:match("Subject: [^\r\n]*"))
end
box:store(1, "add", { "\\Seen" })
box:close()
```

| Call | Result |
| --- | --- |
| `imap.connect(tcp_or_tls [, timeout_ms])` | Session, after the greeting |
| `session:login(user, password [, timeout_ms])` | LOGIN |
| `session:list([reference [, pattern [, timeout_ms]]])` | `{ { name, delimiter, flags }, ... }`; `""` and `"*"` by default |
| `session:select(mailbox [, readonly [, timeout_ms]])` | SELECT (EXAMINE if `readonly`): `{ exists, recent, uidnext, uidvalidity, unseen, flags }` |
| `session:search(criteria [, timeout_ms])` | The numbers of the matching messages |
| `session:fetch(set, items [, timeout_ms])` | `{ { number, ... }, ... }`, one table per message |
| `session:store(set, mode, flags [, timeout_ms])` | STORE, silently |
| `session:copy(set, mailbox [, timeout_ms])` | COPY |
| `session:uid_search`, `uid_fetch`, `uid_store`, `uid_copy` | The same with UIDs in place of message numbers |
| `session:expunge([timeout_ms])` | Remove the messages flagged `\Deleted` |
| `session:create(mailbox)`, `delete(mailbox)`, `rename(mailbox, new_name)` | Mailbox management |
| `session:append(mailbox, message [, timeout_ms])` | APPEND the whole message |
| `session:noop()` | NOOP |
| `session:info()` | `{ state, response }`: `"non-authenticated"`, `"authenticated"` or `"selected"`, and the last tagged response |
| `session:close()` | LOGOUT, end the session and close the socket |

- A message `set` is a number or a string such as `"3"`, `"1:5"` or `"2,4:*"`, where `*` is the
  last message.
- `items` for `fetch` is a list of `"flags"`, `"uid"`, `"size"`, `"header"`, `"text"` and
  `"body"` (the whole message). Each message table has its `number` and the items asked for;
  `flags` is a list of names such as `"\\Seen"`. Reading uses BODY.PEEK, so it does not set `\Seen`.
- `criteria` for `search` is a table, all of whose fields must match: strings for `from`, `to`,
  `cc`, `bcc`, `subject`, `body`, `text`, `keyword` and `unkeyword`; `header = { name, value }`;
  numbers for `larger` and `smaller`; `true` for `all`, `seen`, `unseen`, `answered`,
  `unanswered`, `deleted`, `undeleted`, `flagged`, `unflagged`, `draft`, `undraft`, `recent`,
  `new` and `old`. An unknown field raises. An empty table is `all`.
- `mode` for `store` is `"add"`, `"remove"` or `"set"`, and a flag is `"\\Seen"`, `"\\Answered"`,
  `"\\Flagged"`, `"\\Deleted"`, `"\\Draft"` or a keyword.
- A failed `select` leaves no mailbox selected, as in IMAP.
- Arguments are checked before anything is sent. A refusal raises an error with the server's
  response (`IMAP LOGIN failed: ...`) and leaves the session usable; a timeout or a lost
  connection ends it.
- Not covered: IDLE, quota, ACL and the other extensions libetpan parses, SASL logins, STARTTLS
  and mailbox names in modified UTF-7 (names are sent as given).

### SSH

`protocols/ssh` runs one command per session (no interactive shell), as a client
or a server, over a connected TCP socket.

```lua
local socket = require("kraken/socket")
local ssh = require("protocols/ssh")

-- Client: run a command on a server and read its output.
local tcp = socket.tcp.connect("researcher", "192.0.2.20", 22, 5000)
local session = ssh.connect(tcp, {
    username = "user",
    password = "secret",
    command = "uname -a",
}, 5000)
local output = ""
for chunk in function() return session:receive(4096, 5000) end do output = output .. chunk end
print(output, session:exit_status())
session:close()
```

| Call | Result |
| --- | --- |
| `ssh.connect(tcp, options [, timeout_ms])` | Client session running `options.command`, after auth |
| `ssh.accept(tcp, options [, timeout_ms])` | Server session, after auth and the client's command request |
| `session:send(data [, timeout_ms])` | Send command input (client stdin, server stdout) |
| `session:receive(count [, timeout_ms])` | Up to `count` (1–32768) output bytes; `nil` at end of stream |
| `session:command()` | The command the client requested (server sessions) |
| `session:exit_status()` | The command's exit status (client sessions, after output ends) |
| `session:close([exit_status])` | End the session; a server sends `exit_status` (0–255, default 0) first |

Client options: `username`, `password`, `command` (all required), and
`host_key_check` — a `function(der)` returning whether to trust the server's
host key (default: accept any). Server options: `host_key` (a DER private key)
and `authorize` — a `function(username, method, secret)` returning whether to
allow the login — both required. The handshake timeout is the trailing argument
of `connect`/`accept`, like every socket call.

- `authorize` is called during `accept`. `method` is `"password"` or
  `"publickey"`; `secret` is the password, or the offered public key in SSH wire
  format. `authorize` only decides policy — whether that user with that password
  or key is allowed. For a public key it never bypasses cryptography: wolfSSH
  verifies the client's signature itself, and a key `authorize` approves still
  fails the login unless that signature checks out. A client may offer a key
  twice (an unsigned probe, then the signed request), so `authorize` can run
  more than once per key; keep it free of side effects.
- Client authentication is password only for now.
- `send` and `receive` move the command's data either way; a client reads the
  command's output with `receive` and a server reads its input.
- A receive timeout raises `socket call timed out` and leaves the session
  usable; other failures end it.
- The session takes over its TCP socket, and `close` closes it.

The [SSH experiment](examples/ssh/README.md) serves a command to the host's
OpenSSH client.
