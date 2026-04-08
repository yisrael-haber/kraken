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
- `Per-identity override bindings`
  Bind stored overrides to an adopted identity's `ARP request`, `ARP reply`, `ICMP echo request`, and `ICMP echo reply` send paths.
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

Today, Kraken is already useful for:

- inspecting what the host and pcap layer expose
- standing up lightweight adopted IP identities
- validating ARP and ICMP behavior for those identities
- reusing named adoption templates without re-entering the same details
- keeping a small library of packet overrides and applying them per identity when modeling outbound behavior

## Design Direction

The current code is trying to follow a few rules:

- backend code owns the real networking behavior and policy
- frontend code mainly handles layout, interaction, and moving data to and from the backend
- new code should justify itself by enabling a real capability, not by adding framework or glue for its own sake
- cross-platform capability should be the default whenever `net`, `gopacket`, or Wails already provide it

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
- ARP and ICMP activity history is currently in-memory only
- the desktop binary embeds `frontend/dist`, so frontend asset generation is part of the local build/test workflow

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
- add stored scripting support with JavaScript so users can keep filesystem-backed scripts that receive network buffers and mutate or replace them as part of a modeling flow
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
