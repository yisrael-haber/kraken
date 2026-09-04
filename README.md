# Kraken

Kraken is an experimental native desktop environment for authorized network
research. It runs independent IPv4 identities directly on packet-capture
interfaces, each with its own network stack and packet path, without relying on
the host's normal sockets.

Kraken is currently a functional Zig rewrite, not yet a complete replacement
for the previous application. Linux and Windows builds, identity storage, the
native UI, packet capture, wolfIP runtimes, and the first Lua scripting surfaces
are working.

## Product Shape

An identity is a persistent network configuration: name, interface, IPv4
address, prefix, gateway, MAC address, MTU, and optional transport script. Each
active identity owns its wolfIP stack, packet-capture handle, worker, queues,
and packet path. Transport VMs come from a shared fixed pool. A failure in one
identity stays local to that identity.

The application currently provides:

- An identity editor with start, stop, and runtime status controls.
- A Lua editor for global scripts, transport scripts, and reusable helper
  modules.
- Parsed Ethernet, VLAN, ARP, IPv4, TCP, UDP, and ICMP packet access.
- Live transport switching. A script can be selected before start, replaced
  while running, or removed without restarting the identity.
- Global script controls for starting identities, stopping them, and sending
  raw Ethernet frames.
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
A script may edit and send the same packet more than once.
It is also valid to construct a packet table and call `packet.send(table)`.
The table must use the same field shape and required values as a parsed packet;
MAC and IPv4 fields use `kraken.mac(...)` and `kraken.ipv4(...)` values.
Each packet runs in a fresh Lua VM with a fixed 500 KiB heap; transport globals
do not persist between packets and garbage collection is disabled.

Transport and global scripts can load reusable modules from the helpers library:

```lua
local module = require("module_name")
```

Helpers use Lua's normal module contract and should return their public table.
Scripts are trusted researcher code with Lua's standard environment; Kraken
does not sandbox filesystem, process, or host access.

## Global Scripts

Global scripts run in their own thread and currently receive:

- `start_identity(name)`
- `stop_identity(name)`
- `send_raw(name, bytes)`

Calls queue runtime actions. Each run uses a fresh Lua VM with a fixed 1 MiB
heap. Stopping the script cancels it.

## Current Limitations

- IPv4 only.
- Ethernet packet-capture interfaces only.
- No complete Lua API for creating, editing, inspecting, or removing identities.
- No high-level TCP or UDP sockets, DNS, ping, or capture-to-file API.
- No script-controlled Echo, HTTP, HTTPS, or SSH services.
- No Windows protocol or DCE/RPC tooling yet.
- Linux and Windows x86-64 are the current distribution targets.

## Future Work

The next product work should expand the Lua control plane rather than add more
UI-only workflows:

1. Expose identities and their lifecycle as direct Lua objects, including
   creation, configuration, transport attachment, state inspection, and
   removal.
2. Add composable TCP and UDP sockets, DNS, ping, and packet-capture primitives.
3. Build services such as Echo, HTTP, HTTPS, and SSH from those primitives.
4. Improve per-identity observability with structured runtime state, packet
   capture, and clearer script and network failures.
5. Expand raw packet access and protocol coverage, including IPv6.
6. Continue tightening lifecycle behavior, bounded resource use, platform
   parity, and predictable recovery.

The UI should increasingly become a workspace for writing scripts, selecting
resources, inspecting state, and recovering from failures. The same important
operations should remain available through Lua.

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
