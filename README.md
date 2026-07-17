# Kraken

Kraken is a desktop tool for authorized network research in a lab. It adopts IPv4 identities on capture-capable interfaces so traffic, services, packet hooks, and scripts run through the selected identity rather than the host's normal network stack.

## What It Does

- Adopt, save, and release IPv4 identities with an interface, prefix, optional MAC and gateway, and MTU.
- Route traffic to another adopted identity on the same configured IPv4 segment.
- Run Echo, HTTP, HTTPS, and SSH services from an adopted identity.
- Resolve DNS and run ICMP ping through an adopted identity.
- Capture an identity's traffic to a `.pcap` file.
- Run Starlark transport hooks and global socket-based scripts.

Kraken uses gVisor for the adopted identity's ARP, routing, TCP/UDP, and packet egress. One capture listener is shared per physical interface; identities on that interface are selected from the frame destination.

## Research Workflow

1. Adopt an IPv4 identity on a capture-capable interface.
2. Optionally bind a transport script, start a service, or start a recording.
3. Use the identity for DNS, ping, services, or global scripts.
4. Release the identity when the experiment is complete.

Capture, routing, and services are identity-local. Kraken currently routes only within an adopted identity's configured local segment; it is not an interception or MITM framework.

## Scripting

Kraken has two Starlark script kinds.

- Transport scripts use `main(packet, ctx)`. They inspect or mutate outbound and routed Ethernet/ARP/IPv4/ICMP/TCP/UDP packets. A packet is emitted only when the script calls `packet.send()`.
- Global scripts use `main(ctx)`. They open TCP or UDP sockets through a selected adopted identity and can use byte, Windows protocol, and TCP DCE/RPC helpers.

```python
load("kraken/socket", "socket")

def main(ctx):
    identity = ctx.identities["10.0.0.1"]
    conn = socket.tcp(identity, "10.0.0.5:445")
    conn.send(b"...")
    print(conn.recv(4096))
    conn.close()
```

The complete script reference is in [docs/scripting.md](docs/scripting.md). Protocol integration boundaries are in [docs/gopacket-integration.md](docs/gopacket-integration.md).

## Data Locations

Kraken stores data below the user configuration root shown by the app:

- `stored_adoption_configuration/` — saved identities.
- `scripts/Transport/` — transport scripts.
- `scripts/Generic/` — global scripts.
- `services/ssh/hostkeys/` — managed SSH host keys.

Captures default to the user's downloads directory as `<ip>-<timestamp>.pcap`.

## Current Boundaries

- IPv4 only.
- Global scripts use explicit IPv4 sockets; they do not use the host resolver or open hidden network paths.
- DCE/RPC is TCP-only. SMB named-pipe RPC and Kerberos RPC are not available.
- Legacy script folders are not imported automatically; move scripts into the directories above.

## Build

Requirements: Go, Node.js/npm, Wails v2, and libpcap on Linux or Npcap on Windows.

```text
make install
npm --prefix frontend run build
make dev
```

Useful commands: `go test ./...`, `make elf`, `make pe`, and `make clean`.

## Contributor Direction

Keep ownership direct: adoption owns lifecycle, netruntime owns packet and socket mechanics, and operations use ordinary connections and listeners. Prefer subtraction, explicit boundaries, and allocation-light packet paths over new layers or test-only production indirection.
