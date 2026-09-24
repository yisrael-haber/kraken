# Scripting Kraken

Kraken runs Lua in two ways. Both get the same environment and modules; they
differ only in when they run and what they receive.

| | Transport script | Global script |
| --- | --- | --- |
| Runs | Once for each frame of the identity that selects it | Once when Run is pressed |
| Entry point | `transport(bytes, identity, direction)` | The script body |
| Lua state | New for each frame | One per run |
| Memory | 500 KiB | 1 MiB |

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

Save scripts in `scripts/global/`, `scripts/transport/`, and helper modules in
`scripts/helpers/`. Helpers load with `require`:

```lua
local flow = require("flow") -- loads helpers/flow.lua
```

Each run has a budget of about 1,000,000 Lua instructions; sleeping and waiting
on sockets do not consume it. Memory freed during a run is only reclaimed when
the run ends, so keep temporary allocations small in loops.

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
- Up to ten transport callbacks run at once across all identities. Further
  frames are dropped and logged. Sleeping or waiting on a socket holds a slot.
- Callbacks run in parallel, so frames can leave in a different order than
  they arrived. Use `kraken/globals` to coordinate when order matters.
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
table's values (e.g. for fuzzing). It never repairs lengths. After resizing a
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
- Each identity has 50 TCP, 50 UDP, and 5 raw sockets, shared by all scripts.
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
