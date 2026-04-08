# Kraken

Kraken is a Wails desktop application for managing local network identities in red-team and pentest labs.

This repo is the GUI-first rework of the older CLI/Lua-driven Kraken shape. The current codebase focuses on a smaller, cleaner desktop surface for interface inventory, adopted identities, stored configurations, and packet overrides.

## Current State

Kraken currently ships the following desktop modules and behaviors:

- `Local Network Settings`
  Shows OS interfaces plus `gopacket/pcap` capture metadata in one view.
- `IP adoption`
  Adopt an IPv4 identity onto a capture-capable interface, including label, IP, MAC, and interface selection.
- `Adoption management`
  Edit or delete an adopted identity from the UI.
- `Packet Overrides`
  Create and store reusable outbound packet edits across `Ethernet`, `IPv4`, `ARP`, and `ICMPv4` fields.
- `JS Scripts`
  Create and store reusable JavaScript packet scripts with a `main(packet, ctx)` entrypoint for outbound packet mutation.
- `Per-identity override bindings`
  Bind stored overrides and stored scripts to an adopted identity's `ARP request`, `ARP reply`, `ICMP echo request`, and `ICMP echo reply` send paths.
- `ARP behavior`
  Respond to ARP requests for adopted IPs and resolve peer MAC addresses when outbound traffic needs them.
- `ICMP behavior`
  Reply to ICMP echo requests for adopted IPs and issue outbound ping requests from an adopted identity.
- `Activity history`
  Each adopted IP has `Info`, `ARP`, and `ICMP` tabs with bounded in-memory logs for requests and replies in both directions.
- `Stored adoption configurations`
  Save reusable adoption templates under the user config directory in `Kraken/stored_adoption_configuration`, then adopt them directly from the UI later.
- `Stored packet overrides`
  Save reusable packet overrides under the user config directory in `Kraken/stored_packet_overrides`.
- `Stored packet scripts`
  Save reusable JavaScript packet scripts under the user config directory in `Kraken/scripts`.

Today, Kraken is already useful for:

- inspecting what the host and pcap layer expose
- standing up lightweight adopted IP identities
- validating ARP and ICMP behavior for those identities
- reusing named adoption templates without re-entering the same details
- keeping a small library of packet overrides and applying them per identity when modeling outbound behavior
- keeping a small library of packet scripts and applying them per identity when modeling outbound behavior

## Design Direction

The current code is trying to follow a few rules:

- backend code owns the real networking behavior and policy
- frontend code mainly handles layout, interaction, and moving data to and from the backend
- new code should justify itself by enabling a real capability, not by adding framework or glue for its own sake
- cross-platform capability should be the default whenever `net`, `gopacket`, or Wails already provide it

## Code Layout

The current project structure is intentionally split by ownership:

- `app.go` and `api_types.go`
  Keep the Wails-facing shell and public type aliases in `package main`.
- `internal/kraken/runtime.go`
  Owns backend orchestration and binds the feature packages together.
- `internal/kraken/adoption`
  Owns adoption state, identity lifecycle, activity history, and backend DTOs for adopted identities.
- `internal/kraken/capture`
  Owns the live `pcap` listener, ARP cache, packet send/receive flow, and hot-path benchmarks.
- `internal/kraken/config`, `internal/kraken/packet`, and `internal/kraken/inventory`
  Own stored adoption configs, stored packet overrides/serialization, and interface inventory respectively.
- `internal/kraken/common` and `internal/kraken/storeutil`
  Hold shared normalization, cloning, and filesystem helpers.
- `frontend/src/app`
  Splits frontend state, actions, controller/event handling, and rendering into separate modules.

## Compared With `origin/main`

The older `origin/main` line had a different product shape:

- CLI entrypoint plus Lua-powered interactive shell
- command-driven workflow for `devices`, `arp`, `capture`, `script`, `adopt`, `ping`, `listen`, `dial`, and related helpers
- userspace TCP/IP support for adopted IPs through `gVisor`
- packet capture/session logging
- broader scripting and packet-mutation hooks
- Linux swap / interception plumbing

This GUI-first codebase is deliberately narrower right now.

What the current GUI codebase already does better:

- GUI-first workflow instead of shell-first workflow
- app-scoped state instead of leaning on global shell/runtime state
- clearer separation between interface inventory, adoption state, and UI rendering
- stored packet overrides and per-adoption override bindings as first-class UI flows
- better day-to-day UX for the features that are already implemented

What `origin/main` still had that this repo does not yet restore:

- userspace TCP netstack for adopted IPs
- inbound/outbound TCP operations like listen and dial
- full capture/session tooling in the GUI
- swap / interception capabilities
- scripting support and broader hook-driven packet manipulation

So Kraken is not yet feature-parity with `origin/main`, but it is a cleaner base for the features that have already been brought forward.

## Runtime Notes

- Linux capture-backed features depend on `libpcap`
- Windows capture-backed features depend on `Npcap`
- adoption uses capture-visible interfaces approved by the backend
- packet overrides are field-level edits applied on outbound packet serialization paths
- stored scripts are precompiled when loaded or saved, then executed against outbound packet objects immediately before validation and serialization
- ARP and ICMP activity history is currently in-memory only
- the desktop binary embeds `frontend/dist`, so frontend asset generation is part of the local build/test workflow

## Performance Notes

Kraken's current ARP and ICMP work is still a relatively small packet path, so not every micro-optimization is worth the extra code. The project is trying to keep the optimizations that generalize into future routing and userspace TCP work, while avoiding overly specific machinery that only makes a benchmark look better.

Performance work that has been tried and kept:

- `pcap` handle setup prefers immediate mode through an inactive handle, with a safe fallback to `OpenLive`
- the receive loop stays on `gopacket.NewPacketSource(handle, handle.LinkType())`, but uses `DecodeOptions{Lazy: true, NoCopy: true}`
- stored packet overrides are compiled once and reused, instead of reparsing MAC/IP/type-code strings on every outbound packet
- outbound ARP and ICMP packet builders avoid unnecessary cloning when Kraken already owns the relevant IP and MAC slices
- serialization reuses `gopacket` serialize buffers through a pool instead of allocating a fresh buffer on each send
- activity logs store compact raw values and format them later when the UI requests a snapshot, instead of doing string formatting on the hot path

Performance work that was tried and then intentionally backed out:

- pooling and reusing full `outboundPacket` layer structs reduced benchmark allocations, but added enough complexity that it did not feel like the right tradeoff yet
- a more custom receive-side decode path was explored, but the first attempt was too easy to get wrong for link-layer handling and temporarily broke ARP replies on a real setup

The current view is that these backed-out optimizations are not bad ideas in principle, but they should only come back if future routing or TCP work proves they are truly needed.

Interesting future experiments:

- add lightweight stage timing around receive, decode, override application, serialize, and send so optimization work is driven by real measurements instead of guesswork
- cache or precompute more interface/routing metadata used on the outbound path if routing lookups become frequent enough to matter
- move more activity or diagnostics work off the hot path if higher packet rates make UI-facing bookkeeping expensive
- revisit `gopacket.DecodingLayerParser` or other lower-allocation decode paths only if they are implemented with the real capture link type and proven against ARP/ICMP regressions
- consider packet templates or more manual serialization only after routing and TCP features exist and profiling shows `gopacket` serialization itself has become the real bottleneck
- if a userspace TCP/IP stack returns, design that path to minimize default allocations and string work from the start rather than trying to bolt optimizations on later

One practical lesson from the current ARP/ICMP work: live RTTs are often dominated more by capture buffering, scheduling, and correctness of the receive path than by tiny field-assignment costs. Microbenchmarks are still useful, but they should be treated as one input rather than the whole story.

## Development

- `make install`
  Install frontend dependencies
- `make test`
  Run Go tests
- `make test-go`
  Alias for `make test`
- `make dev`
  Start the Wails development app
- `make build`
  Build the Linux app
- `make build-debug`
  Build the Linux app in debug mode
- `make build-windows`
  Build the Windows executable
- `make windows`
  Build the Windows executable and copy it to the configured Windows desktop path
- `make clean`
  Remove generated build artifacts

Useful direct frontend command:

- `npm --prefix frontend run build`
  Build `frontend/dist` when you want to verify the embedded UI bundle directly.

Useful focused benchmark command:

- `go test ./internal/kraken/capture -run '^$' -bench 'BenchmarkEchoReplyHotPath' -benchmem`
  Measure the current ARP/ICMP echo-reply send path without running the full test suite.

If `frontend/dist` is missing, generate it before running Go tests or packaging commands that compile `main.go`.

## Near-Term Fixes And QoL

- live activity refresh so ARP/ICMP tabs update without a manual refresh button
- stored configuration management improvements: rename, duplicate, import, export
- stored packet override management improvements: duplicate, import, export
- clearer validation and inline remediation when a stored configuration points at a missing interface
- richer activity filtering and sorting inside the ARP/ICMP tables
- better surfacing of why an interface is not eligible for adoption
- easier packaging of repeatable lab setups from saved configurations and override libraries

## Bigger Features

- restore a userspace TCP netstack for adopted IPs so Kraken can model real service and client behavior from identities the OS does not own
- add protocol-focused modules for SMB, RPC, HTTP, and other lab-relevant services and clients
- expand the JavaScript scripting module with richer standard-library helpers, packet-drop/replace controls, and deeper protocol-aware packet views
- add packet capture sessions, timelines, and replay-oriented inspection in the GUI
- add traffic interception and swap tooling as first-class modules instead of shell commands
- add scenario/module cards beyond local networking so the landing page becomes a true orchestration surface
- add import/export of complete lab scenarios, not just single stored configurations or overrides

## Long-Term Goal

Kraken is moving toward a desktop orchestration environment for hostile-lab network modeling:

- host-owned identities
- adopted identities
- service/client behavior
- packet mutation, overrides, and scripting
- capture and inspection
- interception and traffic shaping

The current repo is the early GUI foundation for that direction.
