# Kraken

Kraken is an experimental native desktop environment for authorized network
research. It creates independent IPv4 identities on packet-capture interfaces
so experiments can operate through their own network stacks instead of the
host's normal stack.

> **Status:** Kraken is undergoing a ground-up Zig rewrite. The native runtime,
> UI, identity storage, packet path, and initial Lua integration exist, but this
> branch is not yet feature-complete or a replacement for the previous Go-based
> application.

## Direction

Kraken is becoming a script-first research instrument. Lua will be the primary
control plane for identities, services, sockets, captures, packet hooks, and
protocol tooling. The UI is intended to become a focused place to write and run
scripts, inspect state, and observe results—not a second collection of forms and
product-defined workflows.

Scripts are trusted, unrestricted researcher code. Kraken deliberately exposes
Lua's standard environment and does not attempt to sandbox filesystem, process,
or host access. Raw access and composable primitives are features of the tool.

## Engineering Principles

- **Scripting is the primary interface.** Important capabilities must be usable
  without UI-specific workflows.
- **The UI observes and orchestrates.** It should focus on editing, execution,
  state, logs, and recovery rather than owning runtime behavior.
- **Expose primitives, not prescribed workflows.** High-level helpers should be
  built on composable identities, packets, sockets, services, and captures.
- **Raw access remains first-class.** Convenience APIs must not remove access to
  bytes, packets, interfaces, the host, or native facilities.
- **Resources have explicit ownership and lifecycles.** Creation, state,
  teardown, and failure should be visible and deterministic.
- **Failures stay local and observable.** One identity or script should not
  corrupt another, and drops, exhaustion, and runtime errors must not be silent.
- **Keep the native core small and direct.** Packet paths avoid unnecessary
  allocation, shared state, UI involvement, and abstraction.
- **Transitional architecture is temporary.** Duplicate UI controls and legacy
  compatibility layers should be removed once scripting replaces them.

### Zig Discipline

- **Zig owns application logic.** Use C only when required by a dependency or
  platform ABI, and keep C types and callbacks behind narrow Zig boundaries.
- **Keep domain code high-level.** Prefer named domain types, constants, tagged
  unions, optionals, and error unions. Localize raw pointers, casts, flags, and
  protocol-layout details at the boundaries that require them.
- **Allocator provenance is predictable.** Allocations come from an allocator
  owned by or explicitly passed into the subsystem. Do not quietly construct a
  new allocation strategy inside leaf code.
- **Avoid and consolidate allocations.** Reuse storage in hot paths, reserve
  capacity, and group allocations that share a lifetime. Allocate when it makes
  low-frequency control code materially clearer.
- **Keep ownership graphs acyclic.** Back-references are non-owning, documented,
  and unable to outlive their owner. Cycles require explicit justification.
- **Prefer tagged-union dispatch.** When variants are known, use an exhaustive
  `switch` instead of function pointers. Reserve callbacks for FFI boundaries,
  true extension points, and unavoidable cross-boundary dispatch.
- **Design errors and teardown together.** Use error unions, `defer`, and
  `errdefer` for deterministic partial initialization and cleanup. Use
  `unreachable` only for proven invariants.
- **Comptime earns its complexity.** Use it for genuine type safety and static
  dispatch, not where ordinary types and functions express the design better.

## What Exists Today

- A native x86-64 Linux and Windows application built with Zig, Clay, and Sokol.
- Persistent IPv4 identity configurations containing an interface, address,
  prefix, optional gateway and MAC, and MTU.
- Up to five concurrently active identities, each owning a wolfIP stack, worker,
  packet-capture handle, and transport hook.
- A native Lua editor with global, transport, and reusable helper libraries.
- Transport hooks that inspect and mutate parsed L2-L4 packet tables.
- Global Lua functions to start or stop stored identities, yield execution, and
  send raw frames through an active identity.
- Unit tests for storage, packet repair, Lua limits, worker lifecycle and
  isolation, queues, and the text editor.

Identity forms and action buttons still exist in the UI. They are transitional
while the scripting API grows.

## What Does Not Exist Yet

- A complete Lua object model for creating, configuring, injecting, and removing
  runtime resources from the global scope.
- Script-controlled Echo, HTTP, HTTPS, or SSH services.
- High-level TCP/UDP sockets, DNS, ping, or capture-to-file APIs.
- The former Windows protocol and DCE/RPC helpers.
- IPv6 support.

## Runtime Future Work

- Replace each active identity's fixed 1 ms capture/stack polling loop with
  readiness-driven capture. Configure libpcap/Npcap immediate mode, wait on
  `pcap_get_selectable_fd()` on Linux or `pcap_getevent()` on Windows, and
  combine packet readiness with command wakes and the next wolfIP timer
  deadline. Drain available packets in bounded batches per wake. wolfIP should
  expose its next required poll time so protocol maintenance remains timely
  without continuous polling.

## Lua Today

Transport scripts define `transport(packet, direction)`. `direction` is
`"inbound"` for frames moving from the NIC into the identity and `"outbound"`
for frames moving from the identity toward the NIC. Parsed headers use
Wireshark's protocol and field vocabulary: `packet.eth`, `packet.vlan`,
`packet.arp`, `packet.ip`, `packet.tcp`, `packet.udp`, and `packet.icmp`.
IPv4 and MAC addresses are fixed-size values with readable string formatting,
value equality, and checked byte indexing. TCP and UDP expose `payload`; ICMP
exposes `data` and a four-byte `rest_of_header` array. IPv4 and TCP `options`
are arrays of opaque binary strings, one raw encoded option per element. Option
contents are not decoded.

Packets are dropped unless the script explicitly sends them. Every call to
`packet:send()` serializes and transmits the current table values synchronously;
the script may edit and send the same packet repeatedly. Dependent lengths and
checksums are repaired by default, while `packet:send(false)` preserves the
supplied values:

```lua
function transport(packet, direction)
    if packet.ip == nil or packet.tcp == nil then return end

    packet.ip.ttl = 32
    packet.tcp.dstport = 8080
    packet:send()
end
```

`kraken.ipv4("192.0.2.1")` and `kraken.mac("02:11:22:33:44:55")` construct
address values. `tostring(address)` formats them, `#address` returns their fixed
byte length, and `address[index]` reads or edits a checked byte.

Global and transport scripts can load modules from the helpers library with a
plain `require("module_name")`. Helper scripts follow Lua's normal module
contract and should return their public table.

Global scripts execute at top level and currently receive:

- `start_identity(name)`
- `stop_identity(name)`
- `send_raw(name, bytes[, "automatic" | "manual"])`
- `await()`

These APIs are early foundations, not the intended final scripting surface.

## Architecture

The application is divided into a native presentation layer, persistent
repositories, an identity service, and a worker-owned runtime. Each active
identity isolates its mutable stack, link, queue, and Lua transport state. A
separate scheduler runs global Lua programs. Linux uses libpcap; Windows uses
Npcap; wolfIP supplies the embedded IPv4 stack. Each identity installs a BPF
capture filter for its MAC address, IPv4 destination, and targeted ARP traffic
before its worker begins polling.

Kraken stores its data under the platform's local configuration directory in a
`kraken` folder:

- `identities/` — JSON identity configurations.
- `scripts/global/` — global `.lua` scripts.
- `scripts/transport/` — transport `.lua` scripts.
- `scripts/helpers/` — reusable Lua modules available through `require`.

The application displays the resolved configuration path in its sidebar.

## Build

Kraken requires a compatible Zig toolchain. Linux builds also require the X11,
Xi, Xcursor, OpenGL, and libpcap development libraries. Windows execution
requires Npcap.

```text
zig build
zig build test
```

A normal build produces both distribution targets:

```text
dist/linux/bin/kraken
dist/windows/bin/kraken.exe
```

Using physical capture interfaces may require elevated packet-capture
permissions. Use Kraken only on systems and networks you are authorized to
research.
