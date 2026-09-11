# Kraken

Kraken is an experimental native desktop environment for authorized network
research. It runs independent IPv4 identities directly on packet-capture
interfaces, each with its own network stack and packet path, without relying on
the host's normal sockets.

Kraken provides native Linux and Windows builds, persistent identities, packet
capture, Lua scripting, and per-identity wolfIP networking.

## Product Shape

An identity is a persistent network configuration: name, interface, IPv4
address, prefix, gateway, MAC address, MTU, and optional transport script. Each
active identity owns its wolfIP stack, packet-capture handle, and packet path.
Its selected transport script handles that identity's frames. A failure in one
identity stays local to that identity.

The application currently provides:

- An identity editor with start, stop, and runtime status controls.
- A Lua editor for global scripts, transport scripts, and reusable helper
  modules.
- Parsed Ethernet, VLAN, ARP, IPv4, TCP, UDP, and ICMP packet access.
- Live transport switching. A script can be selected before start, replaced
  while running, or removed without restarting the identity.
- Global script controls for identities, raw Ethernet frames, and wolfIP TCP
  and UDP sockets.
- A file-backed Logs workspace for the current session.
- Native x86-64 Linux and Windows builds.

Transport selection belongs to the identity and survives application restarts.
## Typical Workflow

1. Create an identity and select a packet-capture interface.
2. Give it an IPv4 address, prefix, MAC address, and any optional network
   settings.
3. Create a transport script in the script editor.
4. Select that script from the identity row, either before or after starting
   the identity.
5. Switch scripts or choose **No transport script** at any time.

Without a transport script, frames pass through unchanged. With a transport
script, the script decides which frames are sent; a frame is dropped unless the
script calls `packet:send()`.

Kraken may require elevated packet-capture permissions. Use it only on systems
and networks you are authorized to research.

## Transport Scripts

A transport script defines:

```lua
function transport(packet, direction)
    if packet.ip ~= nil then
        print(direction, tostring(packet.ip.src), tostring(packet.ip.dst))
    end

    packet:send()
end
```

`direction` is `"inbound"` for frames moving from the network interface into
the identity and `"outbound"` for frames moving from the identity toward the
interface.

Available packet tables follow familiar protocol names:

- `packet.eth`
- `packet.vlan`
- `packet.arp`
- `packet.ip`
- `packet.tcp`
- `packet.udp`
- `packet.icmp`

TCP and UDP expose `payload`. ICMP exposes `data` and `rest_of_header`. IPv4 and
TCP options are binary strings. IPv4 and MAC values
support string formatting, equality, length, and checked byte indexing.
Unsupported frames use `packet.data`; unparsed ARP and IPv4 payloads use their
own `data` field.

`packet:send()` serializes and transmits the current packet table immediately.
It recalculates IPv4 header and IPv4 TCP/UDP/ICMP checksums by default, in either direction.
Use `packet:send(false)` to preserve checksum fields for fuzzing or exact replay.
The recalculation affects the transmitted bytes, not the Lua table. Packet lengths
are not repaired. Incomplete headers or lengths outside the available bytes cause
an error during recalculation; fragmented IPv4 packets have
only their IPv4 header checksum updated. Other protocols remain unchanged.
UDP checksums are calculated even when the supplied checksum is zero (disabled).
A script may edit and send the same packet more than once.
It is also valid to construct a packet table and call `packet.send(table)`.
The same option applies: `packet.send(table, false)` preserves its checksums.
The table must use the same field shape and required values as a parsed packet;
MAC and IPv4 fields use `kraken.mac(...)` and `kraken.ipv4(...)` values.
Transport scripts are initialized when an identity starts or when its selected
script changes. Their Lua globals and loaded helper modules persist while the
script remains selected, so a script may keep state across packets. Replacing
or clearing the transport script resets that state.

Transport scripts are packet programs. They do not expose `kraken/socket`.
Researchers can construct raw Ethernet frames with `packet.send({ data = bytes
})` when they need custom protocol behavior.
Use `packet.send({ data = bytes }, false)` to send the raw bytes unchanged.
Transport and global scripts can load reusable modules from the helpers library:

```lua
local module = require("module_name")
```

Helpers use Lua's normal module contract and should return their public table.
Scripts are trusted researcher code with Lua's standard environment; Kraken
does not sandbox filesystem, process, or host access.
Lua `print(...)` output is recorded in the current session log.

## Logging

Kraken creates a new UTC-named session file at startup under `logs/` in its
configuration directory. The native logger writes directly to that file through
a small buffered writer; it keeps no in-memory log history.

The Logs workspace reads the current session file only while it is open. It
shows the selected newest portion of the file in normal FIFO order
(oldest-to-newest) and refreshes every 250 ms. Choose 50, 100, 250, 500, 1,000,
or 5,000 displayed lines and a text
size from 12 to 20 px. Older sessions and lines outside the selected view remain
available in the session files themselves.

## Global Scripts

Global scripts run in their own thread and currently receive:

- `create_identity({ name, ip, prefix, interface, gateway, mac, mtu })`
- `delete_identity(name)`
- `start_identity(name)`
- `stop_identity(name)`
- `set_identity_transport(name, script_name)` or
  `set_identity_transport(name, nil)` to clear it
- `send_raw(name, bytes)`

Global scripts can open TCP and UDP sockets through a running identity:

```lua
local socket = require("kraken/socket")

local client = socket.tcp.connect("researcher", "192.0.2.20", 8080, 3000)
client:send("request")
local reply = client:receive(2, 3000)
client:close()
```

```lua
local socket = require("kraken/socket")

local udp = socket.udp.bind("researcher", "192.0.2.10", 5353)
udp:send("query", "192.0.2.53", 53)
local data, address, port = udp:receive(1000)
udp:close()
```

The first argument is the identity name. The identity must be running. Its
IPv4 stack owns the socket, so the host operating system never creates or uses
a network socket for these calls.

| Call | Result |
| --- | --- |
| `socket.tcp.connect(name, address, port [, timeout_ms])` | Connected TCP socket. |
| `socket.tcp.bind(name, address, port)` | Bound TCP socket. Call `listen()` to accept connections. |
| `socket.udp.connect(name, address, port)` | Connected UDP socket. |
| `socket.udp.bind(name, address, port)` | Bound UDP socket. |
| `tcp:listen()` | Makes a bound TCP socket a listener. |
| `tcp:accept([timeout_ms])` | Accepted TCP socket, peer IPv4 address, peer port. |
| `socket:send(data [, timeout_ms])` | Sends the complete Lua string on TCP or connected UDP. |
| `udp:send(data, address, port [, timeout_ms])` | Sends one datagram from a bound UDP socket. |
| `tcp:receive(count [, timeout_ms])` | Returns exactly `count` bytes. |
| `udp:receive([timeout_ms])` | Returns one datagram, source IPv4 address, source port. |
| `socket:close()` | Releases the socket. |

TCP reads accumulate data until the requested byte count is available. UDP
reads preserve datagram boundaries. IPv4 addresses are strings such as
`"192.0.2.20"`; ports are integers from 0 through 65535.

Socket calls are synchronous: a call returns only after it completes, fails,
or reaches its timeout. Omit a timeout or pass `nil` to wait indefinitely;
pass `0` to poll; a positive timeout is milliseconds. Failures raise a Lua
error, so `pcall` can handle an unavailable identity, rejected connection,
closed peer, timeout, or other socket failure.

Each global script run can keep at most 32 sockets open. Sockets that remain
open when the script finishes are closed automatically. A receive call accepts
at most 32 KiB; a larger UDP datagram fails rather than being truncated.

All socket packets use the selected identity's ordinary packet path. A
transport script controls socket traffic exactly as it controls every other
frame: it must call `packet:send()` for ARP, TCP handshakes, requests, replies,
and UDP datagrams to continue. Transport scripts themselves expose packet
tables and raw Ethernet frames, not socket objects.

Checksum offloading can make a transport script necessary for sockets. On virtual
networks, including host-to-VM and VM-to-VM links, captured packets may carry
unfinished checksums: the operating system passes checksum work through device
metadata that Kraken's packet capture API does not expose. wolfIP requires complete
checksums, so it can reject these packets and socket operations can time out.

Without a transport script, Kraken passes captured bytes unchanged. Select this
transport to complete checksums before forwarding packets in either direction:

```lua
function transport(packet, direction)
    packet:send()
end
```

For checksum fuzzing, use `packet:send(false)` to preserve intentionally invalid
checksums. Recalculation repairs all supported checksums, not just offload-related
ones. Socket traffic still needs complete checksums to be accepted by wolfIP.

For example, a listener can serve one connection:

```lua
local socket = require("kraken/socket")

local listener = socket.tcp.bind("researcher", "192.0.2.10", 8080)
listener:listen()
local peer, address, port = listener:accept(5000)
peer:send("hello\n")
peer:close()
listener:close()
```

`create_identity` creates a saved identity; its network fields use the same
text values as the identity editor. `set_identity_transport` selects a saved
transport script by its `.lua` file name. Requests run in the order written;
the Logs workspace records any request that cannot be completed.

For example, a global script can prepare and start an identity:

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

Stopping a global script cancels it.

## Current Limitations

- IPv4 only.
- Ethernet packet-capture interfaces only.
- Global Lua can create, delete, start, stop, and select a transport script for
  identities, but cannot list or inspect saved identities.
- No DNS, ping, or capture-to-file API.
- No script-controlled Echo, HTTP, HTTPS, or SSH services.
- No Windows protocol or DCE/RPC tooling yet.
- Linux and Windows x86-64 are the current distribution targets.

## Design Direction

- Scripting is the primary control plane; the UI observes and orchestrates it.
- Raw packets and native facilities remain first-class.
- The native core stays small, direct, and allocation-conscious.
- Each identity owns its mutable runtime state and fails independently.
- High-level workflows are built from reusable primitives rather than fixed
  product features.
- Transitional and duplicate APIs should be removed instead of preserved for
  compatibility.

## Storage

Kraken stores its data below the platform's local configuration directory in a
`kraken` folder:

- `identities/` — JSON identity configurations.
- `scripts/global/` — global Lua scripts.
- `scripts/transport/` — transport Lua scripts.
- `scripts/helpers/` — Lua modules available through `require`.
- `logs/` — UTC-named session log files, retained for external inspection.

The resolved configuration path is shown in the application sidebar.

## Build

Kraken requires a compatible Zig toolchain. Linux builds require the X11, Xi,
Xcursor, OpenGL, and libpcap development libraries. Windows execution requires
Npcap.

```text
zig build
zig build test
```

`zig build` creates both distribution targets:

```text
dist/linux/bin/kraken
dist/windows/bin/kraken.exe
```
