# Kraken

Kraken is an experimental native desktop environment for authorized network
research. It runs independent IPv4 identities directly on packet-capture
interfaces, each with its own network stack and packet path, without relying on
the host's normal sockets.

Kraken provides native Linux and Windows builds, persistent identities, packet
capture, Lua scripting, and per-identity wolfIP networking.

## Working with identities

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
- Scripted control of identities, raw Ethernet frames, and wolfIP TCP, UDP, and
  raw IPv4 sockets, from both script kinds.
- Temporary capture BPF for a running identity.
- A file-backed Logs workspace for the current session.
- Native x86-64 Linux and Windows builds.

Transport selection belongs to the identity and survives application restarts.

## Typical Workflow

1. Create an identity and select a packet-capture interface.
2. Give it an IPv4 address, prefix, MAC address, and any optional network
   settings.
3. Save the identity, then press its Start button. Check Logs if it fails.
4. Optionally create and save a transport script in Script Editor, then select
   it from the identity row. Selection works before or after starting.
5. Run a global script to generate traffic or open sockets through the identity.
6. Optionally set a capture BPF expression in the active identity's runtime
   row for the current run.

Use an unused IPv4 address and MAC on the selected network. An empty prefix
uses `/24`; an empty MTU uses `1500`. Set a gateway to reach other subnets.
Stop an identity before editing or deleting it. Saved identities do not start
automatically when Kraken launches.

Without a transport script, frames pass through unchanged. With a transport
script, the script decides which frames are sent.

Capture BPF is a libpcap expression applied to a running identity. It controls
which captured frames enter its inbound path. Select **Custom BPF filter**,
enter the expression, and press **Apply**. An empty expression restores the
normal identity filter. The field clears and BPF resets when the identity stops; see
[SCRIPTING.md](SCRIPTING.md) for the Lua equivalent and filter behavior.

Kraken may require elevated packet-capture permissions. Use it only on systems
and networks you are authorized to research.

## Scripting

Kraken runs Lua in two ways, with the same modules available to both:

- **Transport scripts** run for every frame of one identity and decide which
  frames are sent. Frames are handled in parallel and may leave in any order;
  Kraken does not preserve or restore frame order.
- **Global scripts** run once when you press Run, to drive an experiment.

The [scripting guide](SCRIPTING.md) covers the modules, packet tables,
sockets, and limits.

This transport script observes and forwards traffic:

```lua
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    local frame = packet.decode(bytes)
    if frame.ip then print(direction, frame.ip.src, frame.ip.dst) end
    transmit(identity, bytes, direction)
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

For runnable host/VM tests, follow the [TCP and UDP](examples/socket/README.md),
[HTTP and HTTPS](examples/http/README.md), [DNS](examples/dns/README.md), and
[SSH](examples/ssh/README.md) experiments.

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
| `global/identity_window.lua` | Start an existing identity for a timed experiment, then stop it. |

See [SCRIPTING.md](SCRIPTING.md) for the behavior and constraints behind each
example.

## Current Limitations

- IPv4 only.
- Ethernet packet-capture interfaces only.
- No built-in hostname lookup; scripts can resolve names with `protocols/dns`
  over the socket API. Application protocols are being added as `protocols/*`
  modules (HTTP/1.x, DNS, TLS and SSH so far); others can be implemented with
  the packet and socket APIs.
- The identity stack does not reassemble inbound IPv4 fragments.
- At most 100 transport callbacks run at once; extra frames are dropped.
- Windows supports up to 63 active identities at once.
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

The current build uses Zig `0.17.0-dev.93+76174e1bc` (also recorded in
`build.zig.zon`); other Zig versions may have incompatible build APIs.
Linux builds require the X11, Xi,
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

Run `./dist/linux/bin/kraken` on Linux or `dist/windows/bin/kraken.exe` on
Windows. Linux needs an X11-compatible display and permission to capture and
inject packets. On Windows, install Npcap before launching; its installation
settings determine whether administrator privileges are needed.

The default optimization is `ReleaseSmall`. Use `zig build -Doptimize=Debug`
for a debugging build. Both targets are built by either command.

If no interfaces appear, check capture permissions and the libpcap/Npcap
installation, then restart Kraken. If an identity starts but sockets time out,
check its network settings, peer reachability, capture BPF, and transport
forwarding. Clearing the transport selection restores ordinary forwarding.
