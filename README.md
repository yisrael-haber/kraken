# Kraken

Kraken is a Wails desktop application for lab network identity adoption, routing, capture, and protocol scripting.

It lets you stand up extra IPv4 identities on capture-capable interfaces, forward traffic between adopted identities, attach transport and application hooks, capture traffic, and run managed services from those identities.

## Current Product Shape

- `Adopted IP identities`
  Create an adopted IPv4 identity with label, interface, IP, subnet mask, optional MAC override, optional default gateway, and explicit MTU.
- `Saved identities`
  Store reusable identity configs and adopt them later from the UI.
- `Routing`
  Forward packets whose destination is inside an adopted identity's local IPv4 segment.
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
- Otherwise Kraken can forward IPv4 packets whose destination is inside an adopted identity's configured subnet.
- The adoption manager owns live segment selection from the adopted identities; there is no persisted global route table.
- Routed traffic is injected into the selected adopted identity. The gVisor netstack owns forwarding, TTL handling, next-hop resolution, ARP, and egress frame emission.

## Storage Layout

Kraken stores persistent data under the user config root shown in the app.

- `stored_adoption_configuration/`
  Saved identities, including subnet mask and MTU.
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
- same-segment routing from adopted identities
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

Kraken is a lab pentesting tool, so the code has to preserve two things at the same time: researcher control and packet-path performance. The code should feel direct to work in. A future maintainer should be able to follow ownership from UI request to adopted identity to runtime engine without finding placeholder contracts, defensive layers, duplicated state, or type trees that exist only because they felt tidy.

The default bias is subtraction. A new line should pay rent through product behavior, correctness, performance, or a clear reduction in total complexity. Prefer removing stale contracts, duplicate state, function-pointer plumbing, single-implementation interfaces, and hand-rolled code already provided by the standard library or imported packages. A refactor that increases the line count should have an obvious product reason, not only a test reason or an internal architecture preference.

The strongest refactors in Kraken usually make ownership more boring:

- An adopted `Identity` owns the netruntime engine for that identity.
- Runtime owns the interface listener cache needed to create or reuse live listeners.
- Adoption owns identity and managed service lifecycle, and dispatches operations through the identity it found.
- Operations own product behavior: scripts, concrete service implementations, DNS, recording, and packet policy.
- Service config is validated and normalized at the managed-service edge; concrete service starters should not repeat that work.
- Netruntime owns low-level networking primitives and should not know about scripts, services, storage, UI DTOs, interface-selection policy, or app workflow.

Avoid abstractions that do not remove real complexity. Interfaces are useful at package boundaries, tests, and places where multiple real implementations exist. They are not useful as shells around one concrete type. Do not add another struct, function table, registry, or callback layer just to make code look pluggable. Static, build-time-known behavior is fine when that is what the program actually needs.

Avoid type explosion. Coalesce data into existing structs when the data shares lifecycle and ownership. Split types only when it makes mutation, ownership, or invariants clearer. Private versus public is not itself interesting inside this executable; visibility only matters when it prevents misuse or clarifies ownership.

Avoid defensive programming that only protects impossible internal states. Validate at the edge that receives user, filesystem, or network input. After that, let prepared values stay prepared. Do not re-trim, re-normalize, re-check nil handles, or revalidate enum-like strings at every internal hop unless the value can actually become invalid there.

Do not keep production indirection to make tests convenient. If a test needs fake packet output, fake script lookup, or artificial lifecycle hooks, first ask whether the test is proving product behavior or only preserving an old architecture. Test scaffolding belongs in tests. Production code should not carry function pointers, interfaces, mutable caches, or alternate constructors solely for test orchestration.

Performance rules:

- Keep hot paths allocation-light. Do not materialize `[]byte` unless crossing a boundary that requires it.
- Prefer `gvisor.dev/gvisor/pkg/buffer.Buffer` for internal packet movement.
- Do not defensively copy by habit. Copy only when ownership actually crosses a boundary or mutation would be unsafe.
- Avoid mutexes unless concurrent ownership requires them. A mutex protecting duplicated state is a design smell.
- Cache calculations only when they happen often and invalidation is rare and obvious.
- Keep packet, service, and engine lifecycles singular per adopted identity/interface unless the product needs multiplicity.

Refactoring discipline:

- Read the caller and callee before changing a shape. A type that looks redundant may exist because ownership is elsewhere, but if ownership is elsewhere the fix is usually to move the field there, not add an adapter.
- Prefer direct data over derived mirrors. If `Services` can be derived from a service map, keep one source. If a pcap handle was opened from `PcapOptions`, do not store the same device name again unless a later product operation needs it.
- Keep names honest. A function named `prepareIdentity` should prepare the identity; a packet I/O object should not also locate scripts, choose capture policy, or own recording workflow state.
- Let package boundaries follow product boundaries. `operations` may know that an adoption listener starts with `less 1`; `netruntime` should only know that a pcap handle was opened with a filter.
- Measure refactors by total complexity, not by local neatness. Moving a callback from one struct to another is not simplification unless it removes an ownership mistake.
- Negative line diff is a useful pressure. It is not the only goal, but when behavior stays the same and the code is clearer, subtraction is usually the correct result.

The desired operator-facing shape is also simple: writing an operation should feel like writing a normal client or server against a listener or connection. Kraken-specific power should come from the adopted identity and runtime underneath, not from every operation knowing low-level packet plumbing.

## Long-Term Direction

The current seams are intentionally shaped around three things:

- `Identity-local operations`
  Adopt, script, capture, dial, listen, serve, and route through one adopted identity's local segment without losing the operator in a large control plane.
- `Protocol-aware hooks`
  Keep transport and application hooks distinct so each surface has the right semantics instead of a vague generic callback.
- `Engine-backed sockets`
  Managed services and clients use the adopted identity's engine-backed TCP/UDP capabilities instead of maintaining their own TCP abstraction.
- `Listener-backed operations`
  Runtime creates interface listeners, adoption binds them to identities, and operations use those identities directly.

Near-term work that fits the current architecture well:

- TLS-aware interception paths where decrypted HTTP semantics can sit above the current HTTPS buffer hook when needed.
- Richer application-layer models such as SMB, DNS, SMTP, or LDAP where Kraken can expose a meaningful protocol object instead of only raw bytes.
- Better service persistence and scenario management so researchers can save and replay service/script setups across runs.
- Richer live service control, health, and fault recovery.
- More routing and interception primitives for controlled MITM and pivot-style lab workflows.
- Deeper low-level packet scripting features such as overlapping fragment synthesis, packet duplication/race injection, deliberate checksum or length corruption, and stronger TCP option surgery.

Longer-term product directions worth testing:

- Workspace/scenario export and import.
- Team sharing for identities, scripts, and service setups.
- Repeatable research workflows with recordings, scripted transforms, and service orchestration.
- Better protocol emulation depth for deception, lab simulation, and adversary interaction research.

## Future Refactor Requirements

Future refactors should continue the same pressure: less architecture, clearer ownership, and no behavior loss.

Important shape:

- Keep packet I/O interface-scoped, not per-identity.
  A single interface listener owns the live capture handle and forwards frames into adopted identities. A single adopted identity engine should not open its own capture loop.
- Keep per-identity gVisor stacks small.
  `netruntime.Engine` should stay close to a raw gVisor TCP/IP stack adapter: identity IP, MAC, subnet route, MTU, injected frame input, outbound frame output, TCP/UDP sockets, and close.
- Keep `netruntime` below product policy.
  It may open pcap handles and implement gVisor link endpoints. It should not choose UI capture defaults, locate pcap devices for selected interfaces, manage recordings, resolve scripts, start services, or own routing policy.
- Keep `operations` responsible for live product workflows.
  Interface listener policy, recording workflow, DNS commands, service implementations, and script execution belong here until there is a simpler concrete reason to move them.
- Keep packet buffers as `gvisor.dev/gvisor/pkg/buffer.Buffer`.
  The default path should be zero-copy or gVisor copy-on-write. Materialize to `[]byte` only at hard boundaries: libpcap write, libpcap borrowed read adoption, and mutable script execution.
- Keep protocol special cases out of low-level runtime code.
  ARP and neighbor resolution should be whatever gVisor naturally does for injected frames and outbound routing. Application protocol behavior belongs above the engine.

When revisiting a package, use this order:

1. Remove duplicate sources of truth.
2. Remove test-only production hooks.
3. Remove single-use helpers and wrapper types.
4. Move fields to the owner that actually uses them.
5. Collapse callbacks into direct calls when there is one real implementation.
6. Delete stale tests that preserve architecture instead of behavior.
7. Run the full suite and inspect the line diff.

Likely cleanup targets after the current `netruntime` pass:

1. `internal/kraken/operations/pcap_listener.go`
   Split only when a responsibility has a clearer owner. Do not move it as-is into another package.
2. `internal/kraken/adoption`
   Shrink `adoption.Listener` if real callers prove it is too broad. Prefer narrow interfaces for identity lifecycle, packet forwarding, and recording.
3. `internal/kraken/operations/recording.go`
   Keep user-facing recording lifecycle in operations. Share raw pcap mechanics only when doing so removes duplication without hiding workflow state.
4. `internal/kraken/operations/managed_service.go`
   Keep only service catalog, config validation, and concrete startup helpers here. Service lifecycle belongs to adoption identities.
5. `internal/kraken/runtime.go`
   Keep runtime as a thin binding layer and listener cache. If listener lifecycle grows more complex, first try to make ownership simpler before adding management types.

The general rule is ownership-first cleanup: make the real owner obvious, delete the duplicated owner, then remove the tests and helper code that only existed for the old shape.
