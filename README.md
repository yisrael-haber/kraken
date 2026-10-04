# Kraken

Kraken is an experimental native desktop environment for authorized network
research. It runs IPv4 identities directly on packet-capture interfaces through
one shared lwIP stack, without relying on the host's normal sockets.

Kraken provides native Linux and Windows builds, persistent identities, packet
capture, Lua scripting, and per-identity virtual network interfaces.

## Working with identities

An identity is a persistent network configuration: name, interface, IPv4
address, prefix, gateway, MAC address, MTU, and optional transport script. Each
active identity owns an lwIP interface, packet-capture handle, and packet path.
Its selected transport script handles that identity's frames.

The application currently provides:

- An identity editor with start, stop, and runtime status controls.
- A Lua editor for global scripts, transport scripts, and reusable helper
  modules.
- Parsed Ethernet, VLAN, ARP, IPv4, TCP, UDP, and ICMP packet access.
- Live transport switching. A script can be selected before start, replaced
  while running, or removed without restarting the identity.
- Scripted control of identities, raw Ethernet frames, and lwIP TCP, UDP, and
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

This global script uses a running identity's network interface:

```lua
local socket = require("kraken/socket")
local client = socket.tcp.connect("researcher", "192.0.2.20", 8080, 3000)
client:send("request")
print(client:receive(2, 3000))
client:close()
```

For runnable host/VM tests, follow the [TCP and UDP](examples/socket/README.md),
[HTTP and HTTPS](examples/http/README.md), [DNS](examples/dns/README.md),
[SSH](examples/ssh/README.md), [SMB and DCERPC](examples/smb_dcerpc/README.md),
[LDAP](examples/ldap/README.md), [TFTP](examples/tftp/README.md),
[SNMP](examples/snmp/README.md), [Telnet](examples/telnet/README.md),
[SIP](examples/sip/README.md), and [mail](examples/mail/README.md) experiments.

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

## Code reduction plan

Reduce implementation code while preserving existing features and researcher
capabilities. Feature removal requires an explicit user instruction. Kraken is
pre-alpha: backwards compatibility is not a requirement. Internal and public
APIs, data structures, and storage formats may change for a better long-term
design; update their callers, examples, and documentation together.

### Development requirements

These are requirements, not preferences. When a conflict or tradeoff leaves the
intended choice unclear, ask the user before making that choice.

- **Every line must justify itself.** Code must serve a concrete application
  need. Work towards removing code that cannot justify its presence. Moving
  code, compressing formatting, or replacing it with equivalent complexity
  does not count as reduction.
- **Kraken logic belongs in Zig.** C is for external libraries and very basic
  integration glue, such as macros and inclusion. Use separate configuration,
  shim, or inclusion files alongside library sources. Any exception for Kraken
  logic in C must be explicitly authorized.
- **Trust external libraries.** Import and use them without modifying their
  sources or protocol internals unless explicitly authorized. An adaptation
  such as DCERPC over TCP is an explicit integration exception, not permission
  to change unrelated internals. Rely on library testing for library behavior;
  test Kraken's use of the library where it adds application value.
- **Test for real stability.** Tests should establish that Kraken is sane and
  usable. Test meaningful behavior and integration, not incidental internal
  state or implementation structure. Do not contort the architecture to retain
  a test, add constraints merely to satisfy one, or substitute automated tests
  for exercising the application.
- **Make ownership apparent.** Keep ownership and lifetimes clear and direct
  in the code. Avoid scattered pointers, circular dependencies, and indirect
  ownership schemes. Necessary synchronization and cleanup must have a clear
  owner and purpose.
- **Validate at the relevant boundary.** Check incoming data once where its
  validity matters, then use those established guarantees downstream. Each
  additional check must address a distinct, real requirement. Repeated
  validation and defensive fallbacks obscure the actual contract and add cost;
  security and stability require clear boundaries, not checks everywhere.
- **Prefer a coherent struct over repeated translation.** A larger struct is
  preferable to several representations continually converted and revalidated.
  Split representations only when there is a concrete benefit beyond saving a
  small amount of space.
- **Keep performance and allocation conservative.** Prefer a direct ownership
  and allocation strategy. Reserved memory need not be perfectly utilized when
  it avoids repeated allocation, copying, or bookkeeping. Judge the overall
  cost of the design in context rather than optimizing each unused byte.
- **Make limits predictable.** Evaluate each limit against its actual purpose.
  Fixed capacities are useful when they make resource use and behavior easy to
  reason about. Reaching a limit must have a clear outcome and leave the
  application in a usable, understood state. Neither fixed limits nor
  configurability are goals in themselves.
- **Keep execution direct.** Avoid unnecessary virtualization, runtime
  indirection, and frameworks. Use tagged unions when they express a real
  distinction, and keep the surrounding control flow straightforward. A shared
  helper must remove real duplication and simplify its callers.
- **Keep capabilities and APIs coherent.** Features must make sense individually
  and together. Internal APIs must be offered and used consistently, with clear
  responsibilities and contracts.
- **Choose the long-term design.** Identify compatibility baggage and other
  obstacles to the best design explicitly, with a default intent to remove
  them. Prefer complete, stable solutions over local patches. Research the
  architecture deeply enough to resolve the actual problem, proportionately
  to its scope; keep implementation changes focused and reviewable. Existing
  features and capabilities are the constraints; the goal is the minimal
  stable design that supports them. Use deletion, simplification, or replacement
  according to that goal, rather than making replacement a separate agenda.
- **Preserve researcher control.** Restrict capabilities only for a concrete
  implementation or library limitation, and explain it. For example, a
  client-only library normally means a client-only module unless a small
  adaptation or suitable alternative supports more. Strange packet behavior
  is valid when the researcher chooses it and the API makes it clear. Do not
  reject or repair bytes, lengths, checksums, or padding merely to impose a
  preferred protocol behavior. Optional validation or repair, including any
  enabled by default, must have an explicit switch the researcher can control.

### Order

| Pass | Scope | Goal |
| --- | --- | --- |
| 1. Baseline | Build, tests, workflows, ownership and dependencies | Record the release baseline and known failures; identify concrete reductions and architectural obstacles against the requirements above. |
| 2. Leaf code | Text utilities, storage, logging, platform adapters | Remove unused helpers and redundant bookkeeping; keep persistence and diagnostics intact. |
| 3. UI | Layout, actions, editors, rendering | Reduce repeated layout/action code and duplicated state; preserve editing, selection, undo, scrolling, and idle rendering behavior. |
| 4. Protocol glue | Lua bindings and Kraken stream adapters | Simplify argument handling and connection plumbing; keep coherent capabilities and researcher controls while respecting trusted library boundaries. |
| 5. Runtime and networking | Manager, Lua workers, command queue, socket bridge, packet codec, lwIP integration | Simplify ownership, representations, validation, and execution; move Kraken logic out of C unless explicitly excepted. Keep concurrency, timeouts, packet controls, and identity isolation usable and clear. |
| 6. Build and dependencies | Build configuration, bindings, integration shims, bundled files | Remove unused build inputs and repeated configuration after proving both targets retain their capabilities. Do not trim library internals. |
| 7. Final review | Tests, examples, documentation | Check cumulative changes against existing features; remove obsolete references and proven duplicate scaffolding. |

Inspect code to establish a specific reduction or resolve an architectural
obstacle, not to satisfy a file checklist. Start with clear deletions. Runtime
changes come late because their ownership and threading affect the rest of the
application; investigate an architectural dependency earlier when another pass
requires it. Verification applies to every pass.

### Completion criteria

For each change, explain what disappears, why the remaining code is justified,
and how the resulting capabilities were verified. Report net code removed,
replacement code, any API or format changes, and validation results. There is
no deletion quota; fewer lines must also mean a simpler implementation.

Use the existing ReleaseSmall tests as the primary baseline and verify both
distribution builds for affected build or shared code. Exercise the relevant
UI workflow or protocol example when tests do not cover it. Add tests only for
meaningful behavioral coverage. Update or remove tests that no longer provide
that value, with an explicit reason; do not erase evidence of a real regression.
Keep known library Debug failures separate from Kraken regressions. They do not
authorize changes to trusted library internals.

A reduction is complete when it meets these development requirements,
simplifies the implementation, preserves existing capabilities, and passes
the relevant checks without a material performance regression. State any
unavailable platform or workflow validation explicitly and leave unverified
reductions open.
