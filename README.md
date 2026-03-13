# kraken

A network toolkit with a Lua-powered interactive shell. Built on libpcap/Npcap, kraken lets you craft, send, and intercept packets without needing kernel-level socket privileges beyond pcap access.

kraken includes a userspace TCP/IP stack (powered by [gVisor](https://gvisor.dev/)) for adopted IP addresses. This lets you open real TCP connections — both inbound and outbound — from an IP that isn't bound to any interface on the host OS.

## Requirements

### Linux
- `libpcap-dev` at build time (e.g. `apt install libpcap-dev`)
- Root or `CAP_NET_RAW` / `CAP_NET_ADMIN` privileges at runtime

### Windows
- [Wireshark](https://www.wireshark.org/) (includes Npcap) installed — required at runtime only, no SDK needed at build time
- Administrator privileges at runtime

## Building

```bash
# Linux
go build -o bin/kraken .

# Windows
go build -o bin\kraken.exe .
```

Go 1.21+ is required. On Linux, CGo is used to link against libpcap — `libpcap-dev` must be installed. On Windows, the pcap layer loads `wpcap.dll` dynamically at runtime (no CGo, no SDK needed at build time).

## Usage

### Interactive shell

Run with no arguments to open the Lua REPL:

```
$ sudo ./kraken
kraken shell — full Lua available. Type help() for commands, exit to quit.
kraken>
```

Full Lua is available — variables, loops, functions, and conditionals all work. State persists across commands for the lifetime of the session.

Type `help()` to list all commands and `help("command")` for detailed usage of a specific command.

### CLI (non-interactive)

A subset of commands can be run directly without entering the shell:

```bash
./kraken devices
./kraken arp -t 192.168.1.1
./kraken arp -t 192.168.1.1 -i eth0
./kraken capture
./kraken capture -i eth0
./kraken script path/to/script.lua
```

---

## Commands

| Command | Description |
|---------|-------------|
| `devices` | List active network interfaces |
| `arp` | Send an ARP request |
| `ping` | Send ICMP echo requests from an adopted IP |
| `capture` | Capture packets on an interface (stdout or pcapng file) |
| `script` | Load and run a Lua script file |
| `arpcache` | Show the ARP cache |
| `arpclear` | Clear ARP cache entries |
| `adopt` | Claim a virtual IP: respond to ARP/ICMP and start a TCP stack |
| `unadopt` | Stop responding for an adopted IP |
| `adopted` | List currently adopted IP addresses |
| `listen` | Accept TCP connections on an adopted IP and port |
| `dial` | Open an outbound TCP connection from an adopted IP |
| `setmod` | Set persistent outbound header overrides for an adopted IP |
| `connlog` | Show the TCP connection log |
| `connlogclear` | Clear the TCP connection log |
| `clear` | Clear the terminal screen |

---

## General commands

### `devices`

Lists all active network interfaces.

```lua
devices()
```

---

### `arp`

Sends an ARP request. Full control over all packet layers.

**CLI flags:**

| Flag | Description |
|------|-------------|
| `-t <ip>` | Target IP address (required) |
| `-i <iface>` | Interface to use (default: first active) |
| `-src-ip <ip>` | Source IP override |
| `-src-mac <mac>` | Source MAC override |

**Shell syntax:**

```lua
arp{t="192.168.1.1"}
arp{t="192.168.1.1", i="eth0"}

-- ARP layer overrides
arp{t="192.168.1.1", parameters={src_ip="10.0.0.5"}}
arp{t="192.168.1.1", parameters={src_mac="de:ad:be:ef:00:01"}}
arp{t="192.168.1.1", parameters={op=2}}  -- ARP reply

-- Ethernet layer overrides
arp{t="192.168.1.1", eth={src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66"}}
```

**`parameters={}` — ARP layer:**

| Field | Description | Default |
|-------|-------------|---------|
| `op` | ARP opcode | `1` (request) |
| `src_mac` | Sender MAC | interface MAC |
| `src_ip` | Sender IP | interface IP |
| `dst_mac` | Target MAC | `00:00:00:00:00:00` |
| `dst_ip` | Target IP | value of `t` |

**`eth={}` — Ethernet layer:**

| Field | Description | Default |
|-------|-------------|---------|
| `src` | Source MAC | interface MAC |
| `dst` | Destination MAC | `ff:ff:ff:ff:ff:ff` |

---

### `ping`

Sends ICMP echo requests from an adopted IP address to a target and prints RTT for each reply. The adopted IP and MAC appear as the source on the wire, so the target's reply comes back to the adopted address and is received correctly. Resolves the destination MAC via ARP automatically.

The IP must already be adopted.

```lua
adopt{ip="192.168.1.100"}
ping{ip="192.168.1.100", t="192.168.1.1"}
ping{ip="192.168.1.100", t="192.168.1.1", count=5}
ping{ip="192.168.1.100", t="192.168.1.1", id=42}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | Adopted source IP address | (required) |
| `t` | Target IP address | (required) |
| `count` | Number of echo requests | `20` |
| `id` | ICMP identifier | `1` |

**Example output:**

```
PING 192.168.1.1 from 192.168.1.100
reply from 192.168.1.1: icmp_seq=1 time=1.243 ms
reply from 192.168.1.1: icmp_seq=2 time=0.981 ms
Request timeout for icmp_seq=3
20 packets transmitted, 19 received, 5% packet loss
```

---

### `capture`

Captures packets on a network interface. Runs until interrupted (Ctrl+C).

Without `file=`, prints a one-line summary per packet to stdout. With `file=`, writes raw packets directly to a pcapng file (a timestamp is automatically inserted before the extension to avoid overwriting previous captures).

```bash
./kraken capture
./kraken capture -i eth0
```

```lua
capture()
capture{i="eth0"}
capture{i="eth0", file="traffic.pcapng"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `i` | Interface to capture on | first active |
| `file` | Write to a pcapng file instead of printing to stdout | none |

---

### `script`

Loads and runs a Lua script file. All kraken commands are available as globals inside the script.

```bash
./kraken script path/to/script.lua
```

From the interactive shell, `script()` runs the file in the **same runtime**, so any globals or functions defined in the script remain available afterwards.

```lua
script("helpers.lua")
send_range("192.168.1", 1, 254)  -- function defined in helpers.lua
```

---

### `arpcache`

Displays all entries in the ARP cache. Entries expire after 5 minutes; a new ARP request is issued automatically on next use. The cache is populated whenever kraken resolves a MAC address (e.g. when sending a ping or establishing a TCP connection).

```lua
arpcache()
```

---

### `arpclear`

Removes entries from the ARP cache. Called with no arguments, clears the entire cache. Called with an IP string, removes only that entry.

```lua
arpclear()
arpclear("192.168.1.1")
```

---

## IP adoption and TCP stack

`adopt` tells kraken to claim an IP address on the network. The address doesn't have to be bound to any interface on the host OS — kraken responds to ARP and ICMP for it directly via pcap. Behind the scenes, a full userspace TCP/IP stack (gVisor) is started for each adopted IP, enabling real TCP connections both inbound and outbound.

All TCP traffic for each adopted IP is automatically captured to a pcapng file.

### `adopt`

Starts responding to ARP requests and ICMP echo requests for an IP. Also initialises the gVisor TCP stack for that IP, enabling `listen`, `dial`, `ping`, and `setmod`.

```lua
adopt{ip="192.168.1.100"}
adopt{ip="192.168.1.100", i="eth0"}
adopt{ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}
adopt{ip="192.168.1.100", capture="myhost.pcapng"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | IP address to adopt (required) | |
| `i` | Interface to listen on | first active |
| `mac` | MAC address to advertise | interface MAC |
| `capture` | pcapng filename for TCP traffic | `session.pcapng` |

A timestamp is always inserted before the file extension (e.g. `session.pcapng` → `session_20260313_153045.pcapng`). Both inbound and outbound packets are recorded at the IP layer.

---

### `unadopt`

Stops responding for the given adopted IP and shuts down its TCP stack. The interface listener shuts down automatically when no adopted IPs remain on it.

```lua
unadopt("192.168.1.100")
```

---

### `adopted`

Lists all currently adopted IP addresses, their advertised MAC, and the interface they are active on.

```lua
adopted()
```

---

### `listen`

Accepts inbound TCP connections on a port for an adopted IP. The IP must already be adopted.

```lua
adopt{ip="192.168.1.100"}
listen{ip="192.168.1.100", port=80}

-- Echo server: sends back everything it receives
listen{ip="192.168.1.100", port=8080, echo=true}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | Adopted IP to listen on (required) | |
| `port` | TCP port number (required) | |
| `echo` | Echo all received data back to the sender | `false` |

Registering a second handler on the same port replaces the first.

---

### `dial`

Opens an outbound TCP connection from an adopted IP to a remote host. Blocks until connected, then reads up to 4096 bytes with a 3-second deadline and prints whatever the remote sends (banner grab). The adopted IP must already be registered.

```lua
adopt{ip="192.168.1.100"}
dial{ip="192.168.1.100", t="192.168.1.1", port=80}
dial{ip="192.168.1.100", t="192.168.1.1", port=22}
```

| Field | Description |
|-------|-------------|
| `ip` | Adopted source IP address (required) |
| `t` | Target (destination) IP address (required) |
| `port` | Destination TCP port (required) |

---

### `setmod`

Sets persistent outbound header overrides for all packets sent from an adopted IP. Only the fields you specify are overridden; omitted fields use the stack's values. Calling with just `ip=` clears all overrides. Overrides apply at L2 (Ethernet), L3 (IPv4), and L4 (TCP); checksums are recomputed automatically after any modification.

```lua
adopt{ip="192.168.1.100"}

-- Spoof source IP and fix TTL
setmod{ip="192.168.1.100", l3={src="10.0.0.1", ttl=128}}

-- Override Ethernet source and TCP source port
setmod{ip="192.168.1.100", eth={src="de:ad:be:ef:00:01"}, l4={src_port=4444}}

-- Clear all overrides
setmod{ip="192.168.1.100"}
```

**`eth={}` — Ethernet layer:**

| Field | Description |
|-------|-------------|
| `src` | Source MAC address |
| `dst` | Destination MAC (bypasses ARP lookup) |

**`l3={}` — IPv4 layer:**

| Field | Description |
|-------|-------------|
| `src` | Source IP address |
| `dst` | Destination IP address |
| `ttl` | Time-to-live (0–255) |
| `tos` | Type of service / DSCP byte (0–255) |

**`l4={}` — TCP layer:**

| Field | Description |
|-------|-------------|
| `src_port` | Source TCP port |
| `dst_port` | Destination TCP port |
| `window` | TCP receive window size |

---

### `connlog`

Displays the TCP connection log for all adopted IPs. Connections are recorded automatically — no configuration needed. Each entry shows the local address, remote address, bytes received and sent (measured at the IP packet level), connection status, and the time the connection was first seen.

```lua
connlog()
```

Example output:

```
Local                 Remote                RX bytes   TX bytes   Status   Connected
─────────────────────────────────────────────────────────────────────────────────────
192.168.1.100:80      10.0.0.5:54321        1420       512        open     14:32:01
192.168.1.100:22      10.0.0.7:61000        0          0          closed   14:33:15
```

---

### `connlogclear`

Clears all entries from the TCP connection log.

```lua
connlogclear()
```

---

### `clear`

Clears the terminal screen. Works on Linux and Windows.

```lua
clear()
```

---

## Known issues and caveats

### Privileges required

Root (Linux) or Administrator (Windows) privileges are required because pcap opens raw sockets. On Linux, granting `CAP_NET_RAW` to the binary is an alternative to running as root:

```bash
sudo setcap cap_net_raw+eip ./kraken
```

### IPv4 only

kraken currently supports IPv4 only. IPv6 is not implemented.

### IP fragmentation

Fragmented IP packets are not reassembled. Incoming fragmented packets are silently ignored. Outgoing packets are also never fragmented — if a packet exceeds the path MTU it will be dropped by the network.

### Windows: Npcap required

On Windows, [Wireshark](https://www.wireshark.org/) (or standalone [Npcap](https://npcap.com/)) must be installed so that `wpcap.dll` is available at runtime.

---

## Future work

- **HTTP server**: serve configurable HTTP responses on an adopted IP and port via `httpserve{...}`, using a `net.Listener` wrapper over the gVisor TCP stack.
- **Application-layer servers**: generalise the listener pattern to support other protocols (SMTP, FTP, custom banners) for deception and fingerprinting use cases.
- **IPv6**: extend the stack to handle IPv6, NDP, and ICMPv6.
- **UDP**: add `udp_send` / `udp_recv` commands for stateless datagram exchange.
- **DNS**: a simple resolver built on UDP would unlock hostname-based targeting across all commands.
- **IP fragmentation on send**: fragment outgoing packets when they exceed the interface MTU.

---

## Future Work To Consider

### Short term

**Deepen the IP adoption use case.**
The userspace TCP/IP stack is the architectural feature that separates this tool from packet crafting alternatives. Before expanding surface area, make the adoption story complete: reliable connection tracking, TLS termination on adopted IPs, and HTTP-layer parsing should all be first-class. The adoption mechanism is what the tool is built around — it should be the most capable and well-tested part.

**Ship protocol handlers as Lua scripts.**
The `listen`/`dial` API is the right abstraction for protocol-level work. The next step is including useful handlers in the repository as Lua scripts: an HTTP credential harvester, a DNS responder, an SMTP banner collector, a TLS interceptor. These are the primitives security researchers reach for most often. They should be in the box, not left as exercises.

**Reduce operational setup friction.**
Using `adopt` currently requires knowing the interface, a suitable MAC, and the target IP up front. Add auto-discovery: probe via ARP to check whether an IP is in use, fall back to the interface MAC if no existing host responds, and introduce a `steal` command that wraps `adopt` with sensible defaults. The goal is to reduce time-to-adopted-IP to a single command.

**Write one complete end-to-end example script.**
A single Lua script that discovers a target, adopts an IP, listens on port 80, logs connections and any data received, and saves results to a file — runnable with no interaction beyond `./kraken script demo.lua` — demonstrates the tool's core value more clearly than any documentation. Build it and put it in the README.

---

### Long term

**Extend `packetMod` into a per-packet transform pipeline.**
The current header override system is a single struct applied uniformly to all outbound packets. The more powerful design is a chain of Lua-callable transforms applied per packet — rewrite destination IP, strip a header, inject payload bytes. Because outbound packets are intercepted after the gVisor stack produces them, transforms can operate at the TCP stream level as well as the packet level. No widely-used tool currently exposes this in a scriptable form.

**Build out L2/L3 impersonation beyond ARP.**
ARP squatting covers IPv4 on a LAN. Extending to IPv6 NDP spoofing (rogue router advertisements, neighbor advertisement spoofing) covers networks where IPv6 is unmonitored, which is common. Adding DHCP starvation and a rogue DHCP server extends the tool's reach to gateway impersonation. Each of these composes naturally with the existing adoption and TCP stack machinery.

**Address the pcap throughput ceiling.**
pcap has inherent per-packet overhead that limits how much traffic the adoption loop can handle. For use cases involving high connection rates or large transfers, `AF_XDP` (Linux) is a faster inbound path that keeps the same no-kernel-cooperation property. This is not an immediate concern but is the architectural ceiling to plan around.

**Target rogue service impersonation as a flagship scenario.**
The adoption mechanism is well-suited to standing up a fake service on a stolen IP — SMB, LDAP, HTTP, NTLM — to capture credentials or fingerprint clients without touching any real host. This is a concrete attack scenario that cannot be replicated as cleanly with tools that rely on the OS network stack. Building and documenting that scenario end-to-end would establish a clear identity for the tool within the pentesting workflow.

**Expose a richer Lua standard library.**
To keep reporting and output logic out of the Go core, the Lua environment should include file I/O, JSON serialization, and a basic HTTP client as built-in globals. This allows users to write self-contained scripts that discover, exploit, log, and report without leaving the tool. The design should follow the pattern of Nmap's NSE output libraries: functionality lives in Lua, the core stays minimal.
