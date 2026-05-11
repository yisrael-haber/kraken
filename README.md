# Kraken

Kraken is a Wails desktop application for lab network identity adoption, routing, capture, and protocol scripting.

It lets you stand up extra IPv4 identities on capture-capable interfaces, forward traffic between adopted identities, attach transport and application hooks, capture traffic, and run managed services from those identities.

## Current Product Shape

- `Adopted IP identities`
  Create an adopted IPv4 identity with label, interface, IP, optional MAC override, optional default gateway, and explicit MTU.
- `Saved identities`
  Store reusable identity configs and adopt them later from the UI.
- `Routing`
  Define global CIDR routes with longest-prefix match and a `via` adopted IP.
- `Transport scripting`
  Run Starlark packet hooks with `main(packet, ctx)` on outbound and routed packet flow, including fragment generation, explicit dispatch, and original-packet suppression.
- `Application scripting`
  Run a managed-service buffer hook on Echo, HTTP, HTTPS, and SSH listener traffic.
- `Packet capture`
  Record traffic for an adopted IP to `.pcap`.
- `Operations`
  DNS queries, managed services, packet recording, and per-identity actions.
- `Managed services`
  Run Echo, HTTP, HTTPS, and SSH services from an adopted IP.
- `Core live behavior`
  Use gVisor for ARP, neighbor resolution, TCP/UDP sockets, forwarding, TTL handling, and egress frame emission.
- `Runtime status`
  Show capture errors, script runtime errors, and low-overhead frame/error counters in adopted identity details.

Adoption listeners keep an inactive capture filter until an identity is bound, then narrow capture to ARP/IPv4 traffic targeting adopted IPs.

## Scripting Surfaces

- `Transport`
  UI label: `Transport`
  Entry point: `main(packet, ctx)`
  Scope: mutable L2-L4 packet access plus payload/buffer editing.
- `Application`
  UI label: `Application`
  Entry point: `main(buffer, ctx)`
  Scope: mutable managed-service connection buffers. Plain HTTP currently exposes raw payload bytes only. HTTPS runs before TLS termination, so the buffer contains TLS records rather than decrypted HTTP.

Notes:

- Surface reference docs live in the default script templates in the editor.
- Scripts are compiled when loaded or saved.
- Invalid scripts stay visible in the library but cannot be bound until fixed.
- Application scripts run on managed-service connection I/O, not on standalone packet capture.
- Application and transport hooks are independent, so managed-service traffic can hit both surfaces.
- Runtime script errors are kept as last-error status on the affected adopted identity or live managed service.
- Structured DNS/TLS buffer edits preserve the original framing fields Kraken decoded from the wire, including DNS-over-TCP length prefixes, DNS section counts and record lengths, and TLS record lengths.
- Transport scripts also expose:
  - `packet.drop()` to suppress the original outbound frame
  - `fragmentor.fragment(packet, maxPayloadSize)` to split an IPv4 packet into fragments
  - `fragmentor.dispatch(packet)` to emit fragments or reordered packets explicitly

## Routing Model

- Direct delivery wins for traffic targeting an adopted identity.
- Otherwise Kraken evaluates researcher-authored routing rules by longest-prefix match on destination CIDR.
- A route selects:
  - `label`
  - `destinationCIDR`
  - `viaAdoptedIP`
- Routed traffic is injected into the selected adopted identity. The gVisor netstack owns forwarding, next-hop resolution, ARP, TTL handling, and egress frame emission.

## Storage Layout

Kraken stores persistent data under the user config root shown in the app.

- `stored_adoption_configuration/`
  Saved identities, including MTU.
- `routing/`
  Saved routing rules.
- `scripts/Transport/`
  Transport scripts.
- `scripts/Application/`
  Application scripts for managed-service buffer hooks.
- `services/ssh/hostkeys/`
  Persistent SSH host keys used by the managed SSH service.

Packet captures default to the user downloads directory as `<ip>-<timestamp>.pcap` unless the user chooses another path.

Live service snapshots redact secret fields before returning them to the UI. The running service keeps the real in-memory value it needs to operate.

Important:

- Legacy script folders such as `scripts/packet` and `scripts/http-service` are not scanned.
- Legacy script folders such as `scripts/Application/HTTP`, `scripts/Application/TLS`, and `scripts/Application/SSH` are not scanned either.
- If you still have older scripts there, move them manually into the canonical directories above.

## Code Layout

- `main.go`, `app.go`
  Wails application shell and desktop dialogs.
- `internal/kraken/runtime.go`
  Backend binding layer exposed to the frontend.
- `internal/kraken/adoption`
  Adopted identity lifecycle, managed service lifecycle, per-identity operation dispatch, engine ownership, and detail/status DTOs. An adopted identity owns its netruntime engine and live service state.
- `internal/kraken/operations`
  Live adopted-interface operations, transport/application script execution, concrete service implementations, recording, DNS, and current packet hot path.
- `internal/kraken/netruntime`
  Low-level gVisor netstack/link endpoint primitives and pcap handle helpers with no application-protocol behavior.
- `internal/kraken/script`
  Starlark runtime, mutable transport/application surfaces, and script store.
- `internal/kraken/interfaces`
  Interface selection and capture capability filtering.
- `internal/kraken/storage`
  Filesystem and store helpers.
- `frontend/src/app`, `frontend/src/ui`
  Frontend state/actions/controller and UI modules.

## Runtime Requirements

- Go
- Node.js / npm
- Wails v2 CLI
- Linux capture support: `libpcap`
- Windows capture support: `Npcap`

`main.go` embeds `frontend/dist`, so commands that compile the desktop app require a built frontend bundle.

## Development

- `make install`
  Install frontend dependencies.
- `npm --prefix frontend run build`
  Build the embedded frontend bundle.
- `make test`
  Run Go tests with the Makefile's Linux tags.
- `go test ./...`
  Run the Go test suite directly.
- `make dev`
  Start the Wails development app.
- `make elf`
  Build the Linux desktop binary.
- `make elf-debug`
  Build the Linux desktop binary with Wails debug output.
- `make pe`
  Build the Windows desktop binary.
- `make pe-debug`
  Build the Windows desktop binary with Wails debug output.
- `make clean`
  Remove `build/bin` and `frontend/dist`.

## Project Status

Kraken is currently a UI-first beta centered on:

- adopted identities
- saved identity configs
- routing
- capture
- transport scripting
- MTU control per adopted identity
- packet fragmentation and scripted fragment dispatch
- application scripting for managed-service connection buffers
- managed services for Echo, HTTP, HTTPS, and SSH
- per-identity live service control

Not implemented yet:

- interception / MITM tooling
- application protocol surfaces beyond HTTP, TLS, and SSH
- scenario import/export and broader orchestration workflows

## Engineering Approach

Kraken is a lab pentesting tool, so the code should preserve two things at the same time: researcher control and packet-path performance. The project should feel direct to work in. A future maintainer should be able to follow ownership from UI request to adopted identity to runtime engine without finding placeholder contracts, defensive layers, or type trees that exist only because they felt tidy.

The default bias is subtraction. A new line should pay rent through behavior, correctness, performance, or a clear reduction in total complexity. Prefer removing stale contracts, duplicate state, and hand-rolled code that is already provided by the standard library or imported packages. A refactor that increases the line count should have an obvious reason.

Ownership should be explicit:

- An adopted `Identity` owns the netruntime engine for that identity.
- Runtime owns the interface listener cache needed to create or reuse live listeners.
- Adoption owns identity and managed service lifecycle, and dispatches operations through the identity it found.
- Operations own product behavior: scripts, concrete service implementations, DNS, recording, and packet policy.
- Service config is validated and normalized at the managed-service edge; concrete service starters should not repeat that work.
- Netruntime owns low-level networking primitives and should not know about scripts, services, storage, UI DTOs, or app policy.

Avoid abstractions that do not remove real complexity. Interfaces are useful at package boundaries, tests, and places where multiple real implementations exist. They are not useful as shells around one concrete type. Do not add another struct, function table, registry, or callback layer just to make code look pluggable. Static, build-time-known behavior is fine when that is what the program actually needs.

Avoid type explosion. Coalesce data into existing structs when the data shares lifecycle and ownership. Split types only when it makes mutation, ownership, or invariants clearer. Private versus public is not itself interesting inside this executable; visibility only matters when it prevents misuse or clarifies ownership.

Performance rules:

- Keep hot paths allocation-light. Do not materialize `[]byte` unless crossing a boundary that requires it.
- Prefer `gvisor.dev/gvisor/pkg/buffer.Buffer` for internal packet movement.
- Do not defensively copy by habit. Copy only when ownership actually crosses a boundary or mutation would be unsafe.
- Avoid mutexes unless concurrent ownership requires them. A mutex protecting duplicated state is a design smell.
- Cache calculations only when they happen often and invalidation is rare and obvious.
- Keep packet, service, and engine lifecycles singular per adopted identity/interface unless the product needs multiplicity.

The desired operator-facing shape is also simple: writing an operation should feel like writing a normal client or server against a listener or connection. Kraken-specific power should come from the adopted identity and runtime underneath, not from every operation knowing low-level packet plumbing.

## Long-Term Direction

The current seams are intentionally shaped around three things:

- `Identity-local operations`
  Adopt, route, script, capture, dial, listen, and serve from one adopted identity without losing the operator in a large control plane.
- `Protocol-aware hooks`
  Keep transport and application hooks distinct so each surface has the right semantics instead of a vague generic callback.
- `Engine-backed sockets`
  Managed services and clients use the adopted identity's engine-backed TCP/UDP capabilities instead of maintaining their own TCP abstraction.
- `Listener-backed operations`
  Runtime creates interface listeners, adoption binds them to identities, and operations use those identities directly.

Near-term work that fits the current architecture well:

- TLS-aware interception paths where decrypted HTTP semantics can sit above the current HTTPS buffer hook when needed.
- Richer application-layer models such as SMB, DNS, SMTP, or LDAP where Kraken can expose a meaningful protocol object instead of only raw bytes.
- Better service persistence and scenario management so researchers can save and replay service/routing/script setups across runs.
- Richer live service control, health, and fault recovery.
- More routing and interception primitives for controlled MITM and pivot-style lab workflows.
- Deeper low-level packet scripting features such as overlapping fragment synthesis, packet duplication/race injection, deliberate checksum or length corruption, and stronger TCP option surgery.

Longer-term product directions worth testing:

- Workspace/scenario export and import.
- Team sharing for identities, routes, scripts, and service setups.
- Repeatable research workflows with recordings, scripted transforms, and service orchestration.
- Better protocol emulation depth for deception, lab simulation, and adversary interaction research.

## Future Refactor Requirements

Low-level packet ownership should continue moving under `internal/kraken/netruntime`.

Important shape:

- Keep packet I/O interface-scoped, not per-identity.
  A pcap handle, capture direction, BPF filter, read loop, write lock, and health state belong to an interface runtime. A single adopted identity engine should not open its own capture loop.
- Keep per-identity gVisor stacks small.
  The current `netruntime.Engine` should stay close to a raw gVisor TCP/IP stack adapter: identity IP, MAC, routes, MTU, injected frame input, outbound frame output, TCP/UDP sockets, and close.
- Add one netruntime-owned interface packet pump.
  It should own pcap open/close, inbound reads, outbound writes, capture filter updates, frame classification, local delivery, broadcast cloning, and forwarding handoff.
- Keep packet buffers as `gvisor.dev/gvisor/pkg/buffer.Buffer`.
  The default path should be zero-copy or gVisor copy-on-write. Materialize to `[]byte` only at hard boundaries: libpcap write, libpcap borrowed read adoption, and mutable script execution.
- Keep application behavior out of netruntime.
  No scripts, services, DNS command logic, UI DTOs, storage, or app policy should move down.
- Keep protocol special cases out of netruntime.
  ICMP command behavior belongs above the engine. ARP and neighbor resolution should be whatever gVisor naturally does for injected frames and outbound routing.

Migration plan:

1. Introduce a small interface-scoped runtime in `netruntime`.
   It should take interface/device config, routes, and a minimal callback set for outbound packet policy and routed-forward lookup.
2. Continue moving pcap lifecycle from `operations`.
   `netruntime.PcapHandle` already owns pcap open/read/write edges. The next step is moving read loop, capture direction, BPF filter state, write synchronization, health, and close behavior.
3. Move raw frame dispatch from `operations`.
   Move frame target classification, local engine lookup, broadcast fan-out, direct forwarding, and packet release ownership.
4. Move packet write helpers from `operations`.
   Move buffer-to-wire writing and keep `buffer.Buffer` as the internal packet currency. Keep `[]byte` writes only as an edge helper for pcap and script-dispatched frames.
5. Keep scripting as an operations callback.
   Netruntime should ask operations to transform or drop outbound frames, then netruntime performs the actual write. This keeps script policy above the packet pump while centralizing packet ownership.
6. Keep recording lifecycle in operations for now.
   Recording is user-facing workflow state and file management. Later, only the raw capture reader/writer plumbing should be shared with netruntime if it reduces duplication.
7. Shrink `pcapAdoptionListener`.
   After the move it should mostly bind identities, scripts, recorders, DNS commands, and translate adoption-facing status.
8. Shrink `adoption.Listener`.
   Prefer narrow interfaces for identity lifecycle, packet forwarding, and recording instead of one broad listener surface.

Do not move `pcap_listener.go` as-is. Split it by responsibility and keep the new netruntime API singular and buffer-native.

Next cleanup targets after `netruntime`:

1. `internal/kraken/operations/pcap_listener.go`
   Main knot after packet plumbing moves down. It currently mixes identity orchestration, pcap lifecycle, BPF state, frame dispatch, forwarding, engine map management, recording, services, script errors, packet writes, and status.
2. `internal/kraken/operations/outbound_engine.go`
   Should reduce to outbound transport-script policy. It should not own packet writing after netruntime owns the packet pump.
3. `internal/kraken/adoption`
   Shrink `adoption.Listener` after operations is smaller. Remove broad fake generality and replace it with narrow interfaces based on real callers.
4. `internal/kraken/operations/recording.go`
   Keep user-facing recording lifecycle in operations, but share or move duplicated raw pcap handle/filter/read mechanics when the netruntime packet pump exists.
5. `internal/kraken/operations/managed_service.go`
   Keep only service catalog, config validation, and concrete startup helpers here. Service lifecycle belongs to adoption identities.
6. `internal/kraken/runtime.go`
   Keep runtime as a thin binding layer and listener cache. If listener lifecycle grows more complex, first try to make ownership simpler before adding management types.

The general rule is ground-up cleanup: stabilize the low-level skeleton first, then strip the layers above it with the new ownership boundaries visible.
