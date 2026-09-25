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
    if frame.ip then print(direction, frame.ip.src, frame.ip.dst) end
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
2,048 bytes; inbound frames must also fit the identity's MTU plus its Ethernet
header.

## Packets

| Function | Result |
| --- | --- |
| `packet.decode(bytes)` | A packet table parsed from an Ethernet frame |
| `packet.encode(frame [, fix_checksums])` | Frame bytes; checksum repair defaults to `true` |
| `packet.fragment(frame, mtu [, fix_checksums])` | A list of IPv4 fragment tables |
| `packet.ipv4(text)`, `packet.mac(text)` | Mutable address values |

| Table | Fields |
| --- | --- |
| `frame.eth` | `src`, `dst` (MAC values), `type` |
| `frame.vlan[i]` | `priority`, `dei`, `id`, `etype` (encapsulated EtherType) |
| `frame.arp` | `hw={type,size}`, `proto={type,size}`, `opcode`, `src={hw_mac,proto_ipv4}`, `dst={hw_mac,proto_ipv4}`, `data` |
| `frame.ip` | `version`, `hdr_len`, `dsfield={dscp,ecn}`, `len`, `id`, `flags={rb,df,mf}`, `frag_offset`, `ttl`, `proto`, `checksum`, `src`, `dst` (IPv4 values), `options` |
| `frame.tcp` | `srcport`, `dstport`, `seq`, `ack`, `hdr_len`, `flags={ae,res,fin,syn,reset,push,ack,urg,ece,cwr}`, `window_size_value`, `checksum`, `urgent_pointer`, `options`, `payload` |
| `frame.udp` | `srcport`, `dstport`, `length`, `checksum`, `payload` |
| `frame.icmp` | `type`, `code`, `checksum`, `rest_of_header` (4 bytes), `data` |

- Header lengths are in bytes; `frag_offset` is in 8-byte units. Flags are
  booleans except TCP `res`, a 3-bit integer. Numbers must fit their wire width.
- `vlan` is always present, empty when untagged.
- Addresses must be `packet.ipv4(...)`/`packet.mac(...)` values. They support
  `tostring`, `==`, `#`, and byte indexing from 1. MACs accept `:` or `-`.
- Unparsed data stays raw: `frame.data` after Ethernet, or `frame.ip.data`
  after IPv4 (including non-initial fragments). Use `{data = bytes}` to encode
  arbitrary bytes.

`encode` repairs IPv4, TCP, UDP, and ICMP checksums; pass `false` to keep the
table's values as-is, including deliberately incorrect ones. It never repairs
lengths. After resizing a
payload, update them yourself:

- UDP: `udp.length = 8 + #udp.payload`, `ip.len = ip.hdr_len + udp.length`
- TCP: `ip.len = ip.hdr_len + tcp.hdr_len + #tcp.payload`
- Options must be padded to a multiple of 4 bytes with `hdr_len = 20 + #options`.

`fragment` splits an IPv4 packet so each fragment's IPv4 size fits `mtu`
(20–65535). It keeps Ethernet/VLAN headers and DF, sets lengths, offsets, MF,
copied options, and IPv4 checksums. It does not send anything. Kraken does not
reassemble inbound fragments, so fragment outbound traffic when the peer should
reassemble.

## Sockets

`kraken/socket` opens sockets on a running identity's own IPv4 stack, not the
host's.

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
| `socket.raw.open(name, protocol [, {header = false}])` | Raw IPv4 socket; protocol 0–255, 0 receives all |
| `tcp:listen()` | Start listening |
| `tcp:accept([timeout_ms])` | Peer socket, source address, source port |
| `socket:send(data [, timeout_ms])` | Send all TCP or connected-UDP data |
| `udp:send(data, address, port [, timeout_ms])` | Send one datagram from a bound socket |
| `raw:send(data, address [, timeout_ms])` | Send one IPv4 payload, or a full IPv4 packet with `header = true` |
| `tcp:receive(count [, timeout_ms])` | Up to `count` bytes (1–32768) once any arrive; `nil` after the peer closes |
| `udp:receive([timeout_ms])` | One datagram, source address, source port |
| `raw:receive([timeout_ms])` | One IPv4 packet (no Ethernet) and its source address |
| `socket:close()` | Release the socket |

- Addresses are numeric IPv4 strings. No hostname lookup.
- No timeout waits indefinitely; `0` polls. Timeouts raise an error.
- A TCP send that fails partway raises an error without reporting how much
  was sent.
- UDP datagrams over 32 KiB fail rather than truncate.
- Each identity has 15 TCP, 15 UDP, and 5 raw sockets, shared by all scripts.
- Sockets are closed when the script ends or is cancelled. Restarting an
  identity invalidates its sockets.
- Raw sockets receive copies; the stack still answers normally. With
  `header = true` you supply the IPv4 header and checksum. Neither mode computes
  transport checksums or fragments.
- On virtual links, checksum offload can leave captured packets with bad
  checksums. A transport forwarding `packet.encode(packet.decode(bytes))`
  repairs them; raw forwarding can make socket calls time out.

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
  levels). Store addresses as `tostring(...)`.
- Up to 3 MiB encoded. A failed `set` clears the table. `get()` must fit the
  calling script's memory.

## Protocols

`protocols/http` and `protocols/dns` convert between bytes and tables and do no
I/O: move the bytes with `kraken/socket` or `transmit`, so they work for
clients, servers, and transport scripts alike. `protocols/tls` wraps a TCP
socket in a session with the same `send`/`receive` shape, so the codecs run over
it unchanged; HTTPS is `protocols/http` over a TLS session. `protocols/ssh`
is a session of the same shape that runs a single command over SSH.

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
- A folded header line joins the previous value with one space.
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
