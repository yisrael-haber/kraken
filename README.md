# kraken

A network toolkit with a Lua-powered interactive shell. Built on libpcap/Npcap, kraken lets you craft, send, and intercept packets without needing kernel-level socket privileges beyond pcap access.

kraken includes a userspace TCP/IP stack (powered by [gVisor](https://gvisor.dev/)) for adopted IP addresses. This lets you open real TCP connections — both inbound and outbound — from an IP that isn't bound to any interface on the host OS.

## Requirements

### Linux
- `libpcap-dev` (e.g. `apt install libpcap-dev`)
- Root or `CAP_NET_RAW` / `CAP_NET_ADMIN` privileges at runtime

### Windows
- [Npcap](https://npcap.com/) installed with WinPcap compatibility mode enabled
- Administrator privileges at runtime

## Building

```bash
# Linux
./build.sh

# Windows
build.bat
```

Output is placed in `bin/kraken` (Linux) or `bin\kraken.exe` (Windows).

Go 1.21+ and CGo are required (the build links against libpcap/Npcap).

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
./kraken ping -t 192.168.1.1
./kraken ping -t 192.168.1.1 -n 5
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
| `ping` | Send ICMP echo requests and report RTT |
| `capture` | Capture packets on an interface (stdout or pcapng file) |
| `script` | Load and run a Lua script file |
| `arpcache` | Show the ARP cache |
| `arpclear` | Clear ARP cache entries |
| `adopt` | Respond to ARP and ICMP for a virtual IP |
| `unadopt` | Stop responding for an adopted IP |
| `adopted` | List currently adopted IP addresses |
| `listen` | Accept TCP connections on an adopted IP and port |
| `dial` | Open an outbound TCP connection from an adopted IP |
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

Sends ICMP echo requests and waits for replies, printing RTT for each. Resolves the destination MAC via ARP automatically. Prints a packet loss summary at the end.

**CLI flags:**

| Flag | Description |
|------|-------------|
| `-t <ip>` | Target IP address (required) |
| `-i <iface>` | Interface to use (default: first active) |
| `-n <count>` | Number of echo requests to send (default: 20) |
| `-src-ip <ip>` | Source IP override |
| `-src-mac <mac>` | Source MAC override |
| `-dst-mac <mac>` | Destination MAC override (skips ARP resolution) |
| `-id <n>` | ICMP identifier (default: 1) |
| `-seq <n>` | ICMP sequence number (default: auto-increment from 1) |
| `-data <bytes>` | Payload: raw string or `0x`-prefixed hex |

**Shell syntax:**

```lua
ping{t="192.168.1.1"}
ping{t="192.168.1.1", i="eth0"}
ping{t="192.168.1.1", count=5}

-- ICMP layer overrides
ping{t="192.168.1.1", parameters={id=42, seq=7}}
ping{t="192.168.1.1", parameters={data="hello world"}}
ping{t="192.168.1.1", parameters={data="0xdeadbeef"}}
ping{t="192.168.1.1", parameters={type=8, code=0}}

-- IPv4 layer overrides
ping{t="192.168.1.1", ip={src="10.0.0.5", ttl=128}}

-- Ethernet layer overrides
ping{t="192.168.1.1", eth={src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66"}}
```

**Top-level options:**

| Field | Description | Default |
|-------|-------------|---------|
| `t` | Target IP address | (required) |
| `i` | Interface name | first active |
| `count` | Number of echo requests | `20` |

**`parameters={}` — ICMP layer:**

| Field | Description | Default |
|-------|-------------|---------|
| `type` | ICMP type | `8` (echo request) |
| `code` | ICMP code | `0` |
| `id` | Identifier | `1` |
| `seq` | Sequence number | auto-increment from `1` |
| `data` | Payload (raw string or `0x` hex) | none |

**`ip={}` — IPv4 layer:**

| Field | Description | Default |
|-------|-------------|---------|
| `src` | Source IP | interface IP |
| `ttl` | TTL | `64` |
| `tos` | TOS byte | `0` |
| `id` | IP ID field | `0` |
| `flags` | IP flags | `0` |
| `frag` | Fragment offset | `0` |

**`eth={}` — Ethernet layer:**

| Field | Description | Default |
|-------|-------------|---------|
| `src` | Source MAC | interface MAC |
| `dst` | Destination MAC | resolved via ARP |

**Example output:**

```
PING 192.168.1.1 on eth0
reply from 192.168.1.1: icmp_seq=1 time=1.243 ms
reply from 192.168.1.1: icmp_seq=2 time=0.981 ms
Request timeout for icmp_seq=3
20 packets transmitted, 19 received, 5% packet loss
```

---

### `capture`

Captures packets on a network interface. Runs until interrupted (Ctrl+C).

Without `file=`, prints a one-line summary per packet to stdout. With `file=`, writes raw packets directly to a pcapng file (timestamp is automatically inserted before the extension to avoid overwriting previous captures).

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
| `file` | Write to a pcapng file instead of stdout | none |

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

Displays all entries in the ARP cache. Entries expire after 5 minutes; a new ARP request is issued automatically on next use. The cache is populated whenever kraken resolves a MAC address (e.g. when sending a ping).

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

### `adopt`

Starts responding to ARP requests and ICMP echo requests for an IP. Also initialises the gVisor TCP stack for that IP, enabling `listen` and `dial`.

```lua
adopt{ip="192.168.1.100"}
adopt{ip="192.168.1.100", i="eth0"}
adopt{ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}
adopt{ip="192.168.1.100", capture="session.pcapng"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | IP address to adopt (required) | |
| `i` | Interface to listen on | first active |
| `mac` | MAC address to advertise | interface MAC |
| `capture` | Write all TCP traffic for this IP to a pcapng file | none |

When `capture` is given, a timestamp is automatically inserted before the file extension (e.g. `session.pcapng` → `session_20260312_153045.pcapng`). Both inbound and outbound packets are recorded at the IP layer.

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

Accepts inbound TCP connections on a port for an adopted IP. Each accepted connection is handed to a handler goroutine. The IP must already be adopted.

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
| `echo` | If true, echo all received data back to the sender | `false` |

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

Clears the terminal screen. Works on Linux, macOS, and Windows.

```lua
clear()
```

---

## Known issues and caveats

### Privileges required

Root (Linux/macOS) or Administrator (Windows) privileges are required because pcap opens raw sockets. On Linux, granting `CAP_NET_RAW` to the binary is an alternative to running as root:

```bash
sudo setcap cap_net_raw+eip ./kraken
```

### IPv4 only

kraken currently supports IPv4 only. IPv6 is not implemented.

### No IP fragmentation on send

Outgoing packets are never fragmented. If a packet exceeds the path MTU it will be silently dropped by the network. Incoming fragmented packets are reassembled correctly.

### Windows: Npcap required

On Windows, [Npcap](https://npcap.com/) must be installed with WinPcap compatibility mode enabled. The legacy WinPcap is no longer maintained and is not supported.

---

## Future work

- **IPv6**: extend the stack to handle IPv6, NDP, and ICMPv6.
- **UDP**: add `udp_send` / `udp_recv` commands for stateless datagram exchange.
- **DNS**: a simple resolver built on UDP would unlock hostname-based targeting across all commands.
- **IP fragmentation on send**: fragment outgoing packets when they exceed the interface MTU.
