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
  Send ping traffic from an adopted IP.
- `Managed services`
  Run Echo, HTTP, HTTPS, and SSH services from an adopted IP.
- `Core live behavior`
  Reply to ARP requests, learn peer MACs, answer ICMP echo for adopted identities, and forward routed traffic across listeners.
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
  Adopted identity lifecycle, per-identity actions, and detail/status DTOs.
- `internal/kraken/operations`
  Live adopted-interface operations, managed services, recording, DNS, ping, and packet hot path.
- `internal/kraken/netruntime`
  Low-level netstack/link endpoint primitives with no application-protocol behavior.
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

## Long-Term Direction

The current seams are intentionally shaped around three things:

- `Identity-local operations`
  Adopt, route, script, capture, and serve from one adopted identity without losing the operator in a large control plane.
- `Protocol-aware hooks`
  Keep transport and application hooks distinct so each surface has the right semantics instead of a vague generic callback.
- `Listener-backed services`
  Managed services start from Kraken-owned listeners, which keeps protocol support extensible without rebuilding the control plane every time.

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

- Low-level packet/runtime ownership must move toward the `netruntime` boundary.
- `pcapAdoptionListener` currently fulfills `adoption.Listener`, but it mixes low-level network work with operations-layer concerns.
- `netruntime` should own pcap read/write, capture-loop mechanics, gVisor engine ownership, frame injection, forwarding, ARP/neighbor behavior, BPF filter state, health, and close behavior.
- `operations` should keep higher-level orchestration: transport script execution, application script execution, managed services, recording lifecycle, DNS, and ping commands.
- Do not move `pcap_listener.go` as-is. Split it so packet/runtime mechanics move down and service/script orchestration stays above.
- `adoption.Listener` should continue shrinking. If the manager only needs identity lifecycle plus forwarding target lookup, remove broader operational methods from that interface or replace it with narrower interfaces.
