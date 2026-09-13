# Scripting Kraken

Kraken has two Lua execution models. Use a **transport script** to control the
packet path of one identity. Use a **global script** to run a network workflow
through one or more identities. Both provide `print`, helper modules,
`kraken/packet`, and `kraken.sleep`.

| | Transport | Global |
| --- | --- | --- |
| Runs | Once for each inbound or outbound frame | Once when Run is pressed |
| Scope | One identity | The Kraken application |
| Main input | Raw bytes and a transmitter | Lua state and explicit API calls |
| Main output | `tx.send(bytes)` | Identity commands, sockets, raw frames |
| State lifetime | While selected for that identity | One Run invocation |

Both execute trusted Lua with the standard Lua environment. Kraken does not
sandbox filesystem, process, or host access. `print(...)` is written to the
current session log, with up to 8 KiB per message. The script editor and
transport/global source loading support up to 50 KiB per script.

## Shared foundations

Save global scripts in `scripts/global/`, transport scripts in
`scripts/transport/`, and helpers in `scripts/helpers/`. Both script types can
load helpers with Lua's normal module contract:

```lua
local flow = require("flow") -- loads helpers/flow.lua
```

A helper should return its public value or table. `require` caches it in that
Lua state: a transport helper persists with its selected transport, while a
global helper persists only for one global-script run.

Lua failures are logged. The instruction budget is approximately 100,000:
per initialization and callback for transport, and per complete run for global
scripts. Sleeping or waiting on sockets does not reset it. Global runs also
have a 1 MiB Lua allocation arena; freed allocations are not reclaimed until
the run ends, so long-running or allocation-heavy scripts can exhaust it even
after garbage collection. Transport uses dynamically allocated Lua memory.

`kraken.sleep(milliseconds)` accepts a non-negative integer. In global scripts
it pauses the script thread; in transport it pauses the identity's packet
handling and stack timers. Global Cancel or identity Stop, respectively,
interrupts it. Standard host calls such as `os.execute` are not interruptible
by Kraken and can delay shutdown or cancellation.

## Transport scripts

A transport script must define `transport(bytes, tx)`. It runs in the
identity's packet path, where `tx.direction` is `"inbound"` from the capture
interface to the identity, or `"outbound"` toward the interface.

```lua
local packet = require("kraken/packet")

function transport(bytes, tx)
    local frame = packet.decode(bytes)
    if frame.ip then
        print(tx.direction, frame.ip.src, frame.ip.dst)
    end
    tx.send(bytes)
end
```

With no selected transport, Kraken forwards frames unchanged. With a selected
transport, the script owns forwarding: a frame is dropped unless it is sent.
Use this for observation, mutation, drops, duplicates, raw-frame injection,
and packet ordering within a single callback. Returning sends nothing implicitly.
A callback error does not undo earlier sends or Lua state changes; subsequent
frames still invoke the script. A script that fails initialization does not
fall back to forwarding: replace it or clear the selection to restore traffic.

### Packet tables and sending

`require("kraken/packet")` is available in both script types. Its API is:

| Function | Result |
| --- | --- |
| `packet.decode(bytes)` | A packet table parsed from an Ethernet frame |
| `packet.encode(frame [, fix_checksums])` | Serialized bytes; checksum repair defaults to `true` |
| `packet.fragment(frame, mtu [, fix_checksums])` | Independent packet tables; checksum repair defaults to `true` |
| `packet.ipv4(text)`, `packet.mac(text)` | Mutable address values |

Invalid arguments raise Lua errors. Parsed tables expose these fields:

| Table | Fields |
| --- | --- |
| `frame.eth` | `src`, `dst` (MAC values), `type` |
| `frame.vlan[i]` | `priority`, `dei`, `id`, `etype` (encapsulated EtherType) |
| `frame.arp` | `hw={type,size}`, `proto={type,size}`, `opcode`, `src={hw_mac,proto_ipv4}`, `dst={hw_mac,proto_ipv4}`, `data` |
| `frame.ip` | `version`, `hdr_len`, `dsfield={dscp,ecn}`, `len`, `id`, `flags={rb,df,mf}`, `frag_offset`, `ttl`, `proto`, `checksum`, `src`, `dst` (IPv4 values), `options` |
| `frame.tcp` | `srcport`, `dstport`, `seq`, `ack`, `hdr_len`, `flags={ae,res,fin,syn,reset,push,ack,urg,ece,cwr}`, `window_size_value`, `checksum`, `urgent_pointer`, `options`, `payload` |
| `frame.udp` | `srcport`, `dstport`, `length`, `checksum`, `payload` |
| `frame.icmp` | `type`, `code`, `checksum`, `rest_of_header` (4 bytes), `data` |

TCP and UDP use `payload`; ICMP uses `data` and `rest_of_header`; IPv4 and TCP
options are binary strings. IPv4 and MAC values support `tostring`, equality,
length, and mutable byte indexing from 1 through 4 or 6. MAC constructors accept
colon or hyphen separators. Header lengths are bytes; IPv4 fragment offsets
are 8-byte units. Flags are booleans except TCP `res`, which is a 3-bit integer.
Numeric fields must fit their wire widths. VLANs form a dense array, empty
when absent. Use address constructors rather than strings or byte arrays in
packet tables.

Unsupported or incomplete headers remain raw data: `frame.data` after Ethernet
(or the whole frame when Ethernet is incomplete), or `frame.ip.data` after IPv4.
Noninitial IPv4 fragments use `ip.data`. Parsing is not protocol validation.

`packet.encode(frame)` repairs IPv4, TCP, UDP, and ICMP checksums by default.
`packet.encode(frame, false)` preserves checksum fields for fuzzing.
Recalculation changes serialized bytes, not the Lua table, and does not repair
lengths. When resizing UDP payloads, set `udp.length = 8 + #udp.payload` and
`ip.len = ip.hdr_len + udp.length`; for TCP use
`ip.len = ip.hdr_len + tcp.hdr_len + #tcp.payload`. IPv4/TCP options must be
padded to a multiple of four bytes and match `hdr_len = 20 + #options`.
Even with checksum repair disabled, tables must contain all required fields
and valid field sizes. Use `{data = bytes}` for arbitrary raw serialization.
Incomplete checksum inputs or lengths outside available data are errors.
A fragmented IPv4 packet receives only an IPv4 header checksum because its
transport checksum cannot be rebuilt.

`tx.send(bytes)` forwards bytes immediately, without parsing or checksum repair.
Use it directly for exact replay, or send `packet.encode(frame)` after editing.
It feeds inbound bytes to the identity stack and outbound bytes to the capture
interface. It accepts only a binary Lua string, and may be called multiple times.
Use dot syntax: `tx.send(bytes)`. Changing `tx.direction` does not redirect the
transmitter. Frames are limited to 2,048 bytes; inbound frames must also fit
the identity's configured MTU plus its Ethernet header. A successful call does
not acknowledge delivery or guarantee that the receiving stack accepted the packet.
The transmitter expires when its callback returns or errors; using it later
raises an error. Packet tables and byte strings can be retained normally.
Constructed tables use the same shape as decoded ones, with `packet.ipv4(...)`
and `packet.mac(...)` for addresses.

### Fragmentation

`packet.fragment(frame, mtu)` returns editable IPv4 packet tables; it
does not send or modify its input. MTU counts IPv4 bytes, not Ethernet/VLAN.

```lua
local packet = require("kraken/packet")

function transport(bytes, tx)
    local frame = packet.decode(bytes)
    if tx.direction == "outbound" and frame.ip then
        for _, fragment in ipairs(packet.fragment(frame, 576)) do
            tx.send(packet.encode(fragment))
        end
    else
        tx.send(bytes)
    end
end
```

The helper returns one packet if it already fits and can split an existing
fragment again. It preserves Ethernet/VLAN headers and DF, sets length, offset,
MF, copied options, and checksums. Pass `false` as its third argument to preserve
supplied checksum fields instead, including the IPv4 checksum despite the changed
fragment header. Use `packet.encode(fragment, false)` to retain those values when
serializing. Clear `frame.ip.flags.df` yourself when the experiment requires it.
Input lengths must be valid; bytes beyond `ip.len` are not fragmented. Editing
a fragment's payload afterward makes its complete-datagram transport checksum your
responsibility. Invalid headers/options, an unaligned too-small MTU, or an
overflowing offset raise Lua errors. MTU must be between 20 and 65535;
nonfinal payload chunks are rounded down to multiples of eight bytes.

Fragments can be emitted in either direction, but the identity stack does not
reassemble inbound IPv4 fragments. Use outbound fragmentation when you need
the destination to reassemble the datagram.

### Transport rough edges

- Transport scripts cannot open Kraken sockets or directly create/control
  identities. Use a global script for those operations.
- Sleeping delays socket progress and can lose traffic if capture buffers fill.
  Script replacement waits for the callback to finish. There is no deferred send API.
- Replacing or clearing the selected script resets its globals and helpers.
- Socket traffic from a global script passes through the identity's selected
  transport too. A transport must forward ARP and every TCP/UDP packet needed
  for the socket workflow.

The included `transport/ipv4_fragment.lua` and `transport/fixed_isn.lua`
examples show outbound fragmentation and bidirectional TCP sequence translation.
The fixed-ISN example does not translate SACK blocks; use peers without SACK.
Its state clears on RST or script replacement, not FIN.

## Global scripts

A global script runs in its own thread when Run is pressed. Run is available
while idle and Cancel while it is running. It is suited to
setting up an identity, opening a real connection through its wolfIP stack,
and coordinating an experiment.

```lua
create_identity({
    name = "researcher",
    ip = "192.0.2.10",
    prefix = "24",
    interface = "eth0",
    mac = "02:11:22:33:44:55",
})
set_identity_transport("researcher", "filter.lua")
start_identity("researcher")
```

### Identity and raw-frame API

| Call | Effect |
| --- | --- |
| `create_identity({ name, ip, prefix, interface, gateway, mac, mtu })` | Creates a saved identity; the name must be unused. Fields use the UI's text format. |
| `delete_identity(name)` | Deletes a stopped identity. |
| `start_identity(name)` / `stop_identity(name)` | Starts or stops it. |
| `set_identity_transport(name, script_name)` | Selects a saved transport filename, including `.lua`. |
| `set_identity_transport(name, nil)` | Clears the selected transport. |
| `set_identity_bpf(name, expression)` | Replaces a running identity's capture BPF for this run only. `nil` or `""` restores its default filter. |
| `send_raw(name, bytes)` | Queues a raw Ethernet frame through a running identity. |

These calls queue commands in script order and return before completion.
Argument and queue-full errors raise Lua errors; later execution failures are
logged, so a successful `pcall(start_identity, name)` does not confirm startup.
The queue holds 64 commands: avoid submitting large bursts without allowing
them to drain. Names and configuration fields are limited to 128 bytes.
`send_raw` requires a running identity, accepts up to 2,048 bytes, and enters
its outbound transport callback. The transport can modify or drop that frame.
Starting requires a valid interface, IPv4 address, and MAC address. An empty
prefix defaults to `24`, an empty MTU to `1500`, and an empty gateway means none.

BPF expressions are limited to 128 bytes and replace the entire capture filter.
They control which captured frames reach the inbound transport callback and wolfIP;
outbound sending is unaffected. For example, `set_identity_bpf("researcher", "tcp")`
captures TCP regardless of its destination. Invalid expressions leave the existing
filter in place and log libpcap's error. Updates run when the identity worker next
handles commands; a busy or sleeping transport callback delays them. Already buffered
packets may reflect the previous filter. Restarting the identity restores its default
MAC/IPv4/ARP destination filter. BPF changes are never saved.

### Sockets through an identity

Require `kraken/socket` to use TCP, UDP, or raw IPv4 through a running identity. The host
does not create a host socket: the selected identity's IPv4 stack owns it.

```lua
local socket = require("kraken/socket")
local client = socket.tcp.connect("researcher", "192.0.2.20", 8080, 3000)
client:send("request")
local reply = client:receive(2, 3000)
client:close()
```

| Call | Result |
| --- | --- |
| `socket.tcp.connect(name, address, port [, timeout_ms])` | Connected TCP socket. |
| `socket.tcp.bind(name, address, port)` | Bound TCP socket; call `listen()`. |
| `socket.udp.connect(name, address, port)` | Connected UDP socket. |
| `socket.udp.bind(name, address, port)` | Bound UDP socket. |
| `socket.raw.open(name, protocol [, {header = false}])` | Raw IPv4 socket; protocol is an integer from 0 through 255 (0 receives all protocols). |
| `raw:send(data, address [, timeout_ms])` | Sends one IPv4 payload, or a complete IPv4 packet with `header = true`. |
| `raw:receive([timeout_ms])` | Returns one complete IPv4 packet and its source IPv4 address, without Ethernet. |
| `tcp:listen()` | Starts listening on a bound TCP socket. |
| `tcp:accept([timeout_ms])` | Returns a peer socket, source IPv4 string, and source port. |
| `socket:send(data [, timeout_ms])` | Sends complete TCP or connected-UDP data. |
| `udp:send(data, address, port [, timeout_ms])` | Sends one datagram from bound UDP. |
| `tcp:receive(count [, timeout_ms])` | Returns exactly `count` bytes. |
| `udp:receive([timeout_ms])` | Returns one datagram, source IPv4 address, source port. |
| `socket:close()` | Releases the socket. |

Addresses are numeric IPv4 strings; ports are integers from 0 through 65535. Socket
calls are synchronous. Omit a timeout or pass `nil` to wait indefinitely, pass
`0` to poll, or use a positive millisecond timeout. Failures raise Lua errors,
so `pcall` can handle unavailable identities, rejected connections, peer close,
and timeout. There is no hostname lookup.
Timeouts do not guarantee an exact return time if the identity worker is blocked.

TCP reads accumulate until the requested count is available; UDP preserves
datagram boundaries. A timeout or peer close after partial TCP progress raises
an error without returning the partial bytes/count: a failed send may already
have sent bytes, and a failed receive may already have consumed bytes.
A run may hold 32 sockets. Unclosed sockets are closed at the end of the run.
TCP receive counts range from 1 through 32768. Receive buffers are limited to 32 KiB; a larger UDP
datagram fails instead of being truncated. Stopping/restarting an identity
invalidates its existing sockets; reconnect after restarting.

Raw sockets share these timeout, cancellation, and cleanup rules. Each identity
has five raw socket slots. They receive copies; normal stack processing still
runs, including automatic TCP/ICMP responses. They do not inject inbound packets.
Outbound packets use routing, ARP, and the identity's transport script.

By default wolfIP supplies the IPv4 header and its checksum. With `header = true`,
provide the IPv4 header yourself, including its checksum; the destination argument
must match the header's destination. Neither mode calculates transport checksums.
There is no automatic fragmentation. `send` confirms queuing, not wire delivery.
The packet module operates on Ethernet frames, so its encoded output is not
directly a raw-socket payload. `send_raw` remains the Ethernet-level alternative.

```lua
local socket = require("kraken/socket")
local probe = socket.raw.open("researcher", 253)
probe:send("probe", "192.0.2.20", 1000)
local ip_packet, source = probe:receive(3000)
print(source, #ip_packet)
probe:close()
```

This example requires a peer that replies using experimental IP protocol 253.

### Global rough edges

- Cancel interrupts Lua, `kraken.sleep`, and pending Kraken socket operations
  once the identity worker can service them. Blocking host calls can freeze
  the UI while it waits for cancellation.
- Cancellation does not undo completed identity changes. Pending identity
  commands are discarded, including cleanup queued from a Lua error handler.
- Global scripts can use `kraken/packet` to construct and edit frames, then
  `send_raw(name, bytes)` to send them through an identity's transport.
- Socket packets follow the normal identity packet path. On virtual links,
  captured checksum-offloaded packets can be incomplete; a forwarding transport
  calling `tx.send(packet.encode(packet.decode(bytes)))` repairs supported checksums.
  With raw forwarding, wolfIP can reject those packets and socket calls can time out.

The included `global/identity_window.lua` starts an existing identity for a
timed experiment. Cancelling it leaves that identity running.
