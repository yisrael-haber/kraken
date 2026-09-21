# Scripting Kraken

Kraken has two Lua execution models. Use a **transport script** to control the
packet path of one identity. Use a **global script** to run a network workflow
through one or more identities. Both provide `print`, helper modules,
`kraken/packet`, and `kraken.sleep`.

| | Transport | Global |
| --- | --- | --- |
| Runs | Once for each inbound or outbound frame | Once when Run is pressed |
| Scope | One identity | The Kraken application |
| Main input | Raw bytes, identity, direction | Lua state and explicit API calls |
| Main output | `transmit(identity, bytes, direction)` | Identity commands, sockets, raw frames |
| State lifetime | New Lua state for each frame | One Run invocation |

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
Lua state: transport callbacks reload helpers for every frame, while a global
helper persists for one global-script run.

Lua failures are logged. The instruction budget is approximately 1,000,000:
shared by initialization and callback for each transport frame, and per complete run for global
scripts. Sleeping or waiting on sockets does not reset it. Global runs have a
1 MiB Lua allocation arena; freed allocations are not reclaimed until the run
ends, so long-running or allocation-heavy scripts can exhaust it even after
garbage collection. Transport uses the same allocation strategy with 500 KiB
per frame invocation. Keep temporary allocations small, especially in loops.

`kraken.sleep(milliseconds)` accepts a non-negative integer. In global scripts
it pauses the script thread; in transport it pauses packet handling and stack
timers for all identities. Global Cancel interrupts global sleep; identity Stop
waits for a transport callback, including its sleep, to return. Standard host calls such as `os.execute` are not interruptible
by Kraken and can delay shutdown or cancellation.

Socket waits allow packet handling, identity commands, and UI updates to continue.
Cancel wakes a pending socket call. Stopping its identity makes the call fail;
restarting the identity does not revive its old sockets.

## Global storage

`require("kraken/globals")` is shared by every transport and global script.
`get()` returns a copy; `set(table)` replaces the stored table.

```lua
local globals = require("kraken/globals")
local state = globals.get()
state.frames = (state.frames or 0) + 1
globals.set(state)
```

The shared table holds up to 3 MiB of encoded data. Keys are booleans, numbers, or strings;
values are booleans, numbers, strings, or nested tables. Functions, userdata,
and threads are unsupported. Store IP/MAC userdata as `tostring(...)` and
rebuild them with `packet.ipv4(...)` or `packet.mac(...)`. Calls are serialized,
but a `get()`/`set()` pair is not atomic. Tables may nest at most 32 levels;
cyclic tables are rejected when they exceed that limit. Failed encoding clears the store;
`get()` must fit the calling VM's heap. It survives script restarts and ends
with the application.

## Transport scripts

A transport script must define `transport(bytes, identity, direction)`.
`identity` is the source identity name. `direction` is `"inbound"` from
the capture interface to its stack, or `"outbound"` toward its interface.

```lua
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    local frame = packet.decode(bytes)
    if frame.ip then
        print(direction, frame.ip.src, frame.ip.dst)
    end
    transmit(identity, bytes, direction)
end
```

With no selected transport, Kraken forwards frames unchanged. With a selected
transport, the script owns forwarding: a frame is dropped unless it is sent.
Use this for observation, mutation, drops, duplicates, raw-frame injection,
and packet ordering within a single callback. Returning sends nothing implicitly.
A callback error does not undo earlier sends; subsequent frames still invoke
the script. Every callback starts with a new Lua state. A script that fails
initialization does not fall back to forwarding: replace it or clear the
selection to restore traffic.

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

`require("kraken/transmit")` returns
`transmit(identity, bytes, direction)`. It accepts an identity name, a binary
Lua string, and `"inbound"` or `"outbound"`. It injects directly: inbound
bytes enter the named identity's stack; outbound bytes enter its capture handle.
It bypasses that target's transport script. Use it for normal forwarding by
passing the callback's `identity` and `direction`, or for cross-identity
automation by choosing another name or direction. It may be called multiple
times. Frames are limited to 2,048 bytes; inbound frames must also fit the
target identity's configured MTU plus its Ethernet header. It does not parse,
repair checksums, or acknowledge delivery. Constructed tables use the same
shape as decoded ones, with
`packet.ipv4(...)` and `packet.mac(...)` for addresses.

### Fragmentation

`packet.fragment(frame, mtu)` returns editable IPv4 packet tables; it
does not send or modify its input. MTU counts IPv4 bytes, not Ethernet/VLAN.

```lua
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    local frame = packet.decode(bytes)
    if direction == "outbound" and frame.ip then
        for _, fragment in ipairs(packet.fragment(frame, 576)) do
            transmit(identity, packet.encode(fragment), direction)
        end
    else
        transmit(identity, bytes, direction)
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
- Sleeping delays the shared runtime loop and can lose traffic if capture
  buffers fill. Script replacement takes effect on the next callback.
- Each callback executes the selected source from scratch and reloads helpers.
  Saving edits to a selected transport file does not change the active copy:
  select it again or restart the identity to apply edits.
- Recursively generated traffic can nest up to ten transport invocations; an additional frame is
  dropped and logged.
- Socket traffic from a global script passes through the identity's selected
  transport too. A transport must forward ARP and every TCP/UDP packet needed
  for the socket workflow.

The included `transport/ipv4_fragment.lua` shows outbound fragmentation.

## Global scripts

A global script executes the current editor contents when Run is pressed;
it does not need to be saved first. Only one global run is available at a time.
After completion, press Cancel to release the run before pressing Run again.
Watch Logs for completion or errors. It is suited to
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
| `send_raw(name, bytes)` | Processes a raw Ethernet frame through a running identity's outbound transport. |

These calls wait for the command to complete. Argument, startup, storage, and
unavailable-identity errors raise Lua errors and can be caught with `pcall`.
A successful `start_identity` means the identity is running. Invalid BPF is an
exception: its rejection is logged, and the old filter remains active.
Names and configuration fields are limited to 128 bytes.
`send_raw` requires a running identity, accepts up to 2,048 bytes, and enters
its outbound transport callback. The transport can modify or drop that frame.
Starting requires a valid interface, IPv4 address, and MAC address. An empty
prefix defaults to `24`, an empty MTU to `1500`, and an empty gateway means none.

BPF expressions are limited to 128 bytes and replace the entire capture filter.
They control which captured frames reach the inbound transport callback and wolfIP;
outbound sending is unaffected. For example, `set_identity_bpf("researcher", "tcp")`
captures TCP regardless of its destination. Invalid expressions leave the existing
filter in place and log libpcap's error. Updates run when the shared runtime loop
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
Timeouts do not guarantee an exact return time if the runtime loop is blocked.

TCP reads accumulate until the requested count is available; UDP preserves
datagram boundaries. A timeout or peer close after partial TCP progress raises
an error without returning the partial bytes/count: a failed send may already
have sent bytes, and a failed receive may already have consumed bytes.
Socket capacity belongs to each identity: up to 50 TCP, 50 UDP, and five raw IPv4
sockets, shared by scripts using that identity. Unclosed sockets are closed at
the end of the run; closed TCP connections can retain stack resources while
protocol teardown completes.
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
  once the runtime loop can service them. Blocking host calls can freeze
  the UI while it waits for cancellation.
- Cancellation does not undo identity changes or discard a command already
  submitted. Stop identities explicitly when the experiment is finished.
- Global scripts can use `kraken/packet` to construct and edit frames, then
  `send_raw(name, bytes)` to send them through an identity's transport.
- Socket packets follow the normal identity packet path. On virtual links,
  captured checksum-offloaded packets can be incomplete; a forwarding transport
  calling `transmit(identity, packet.encode(packet.decode(bytes)), direction)`
  repairs supported checksums.
  With raw forwarding, wolfIP can reject those packets and socket calls can time out.

The included `global/identity_window.lua` starts an existing identity for a
timed experiment. Cancelling it leaves that identity running.
