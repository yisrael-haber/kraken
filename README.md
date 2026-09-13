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
Its selected transport script handles that identity's frames.

The application currently provides:

- An identity editor with start, stop, and runtime status controls.
- A Lua editor for global scripts, transport scripts, and reusable helper
  modules.
- Parsed Ethernet, VLAN, ARP, IPv4, TCP, UDP, and ICMP packet access.
- Live transport switching. A script can be selected before start, replaced
  while running, or removed without restarting the identity.
- Global script controls for identities, raw Ethernet frames, and wolfIP TCP,
  UDP, and raw IPv4 sockets.
- Temporary capture BPF for a running identity.
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
5. Optionally edit the identity and apply a capture BPF expression for the
   current run.

Without a transport script, frames pass through unchanged. With a transport
script, the script decides which frames are sent; a frame is dropped unless the
script calls `tx.send(bytes)`.

Capture BPF is a libpcap expression applied to a running identity. It controls
which captured frames enter its inbound path. Enter an empty expression and
press **Apply** to restore the normal identity filter. BPF is reset when the
identity stops; see [SCRIPTING.md](SCRIPTING.md) for the Lua equivalent and
filter behavior.

Kraken may require elevated packet-capture permissions. Use it only on systems
and networks you are authorized to research.

## Scripting

Kraken has two complementary Lua execution models:

- **Transport scripts** run for every frame of one identity and decide which
  packets leave the identity or its interface.
- **Global scripts** run a workflow once: create and control identities, use an
  identity's TCP/UDP/raw IPv4 sockets, and send raw Ethernet frames.

The complete [scripting guide](SCRIPTING.md) covers each model, packet tables,
sockets, helpers, checksum behavior, cancellation, and current rough edges.

This transport script observes and forwards traffic:

```lua
local packet = require("kraken/packet")

function transport(bytes, tx)
    local frame = packet.decode(bytes)
    if frame.ip then print(tx.direction, frame.ip.src, frame.ip.dst) end
    tx.send(bytes)
end
```

This global script uses a running identity's stack:

```lua
local socket = require("kraken/socket")
local client = socket.tcp.connect("researcher", "192.0.2.20", 8080, 3000)
client:send("request")
print(client:receive(2, 3000))
client:close()
```

For a runnable host/VM test, follow the [TCP and UDP experiment](examples/socket/README.md).

## Logging

Kraken creates a session log under `logs/` in its configuration directory. The
Logs workspace shows a copyable tail of the current session and pauses updates
while you select text or scroll back. Session files retain the complete output.

## Example Library

Copy [examples/scripts](examples/scripts) into your configuration's `scripts/`
directory, preserving `transport/`, `global/` and `helpers/`, or use the matching
Script Editor kinds. `require("flow")` loads `helpers/flow.lua`.

| Example | Use |
| --- | --- |
| `transport/ipv4_fragment.lua` | Split outbound IPv4 datagrams at a chosen MTU. |
| `transport/fixed_isn.lua` | Translate TCP sequence numbers in both directions; uses `flow`. |
| `global/identity_window.lua` | Start an existing identity for a timed experiment, then stop it. |

See [SCRIPTING.md](SCRIPTING.md) for the behavior and constraints behind each
example.

## Current Limitations

- IPv4 only.
- Ethernet packet-capture interfaces only.
- No built-in hostname lookup or application-protocol clients. Scripts can
  implement protocols using the packet and socket APIs.
- The identity stack does not reassemble inbound IPv4 fragments.
- Transport sleep pauses that identity's network processing. Kraken sockets
  and identity-control calls are available only to global scripts.
- Linux and Windows x86-64 are the current distribution targets.

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
