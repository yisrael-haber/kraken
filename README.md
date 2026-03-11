# kraken

A network toolkit with a Lua-powered interactive shell. Built on a userspace raw-socket TCP/IP stack (libpcap/Npcap), kraken lets you craft, send, and intercept packets without needing kernel-level socket privileges beyond pcap access.

## Requirements

### Linux
- `libpcap-dev` (e.g. `apt install libpcap-dev`)
- Root or `CAP_NET_RAW` / `CAP_NET_ADMIN` privileges at runtime

### Windows
- [Npcap](https://npcap.com/) installed with WinPcap compatibility mode enabled
- Administrator privileges at runtime

## Building

```bash
# Linux / macOS
go build -o kraken .

# Windows
go build -o kraken.exe .
```

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

TCP and HTTP commands are available in the interactive shell only.

---

## Commands

### General

| Command | Description |
|---------|-------------|
| `devices` | List active network interfaces |
| `arp` | Send an ARP request |
| `ping` | Send ICMP echo requests and report RTT |
| `capture` | Capture and print packets on an interface |
| `script` | Load and run a Lua script file |
| `arpcache` | Show the ARP cache |
| `arpclear` | Clear ARP cache entries |
| `adopt` | Respond to ARP and ICMP for an IP not bound to the interface |
| `unadopt` | Stop responding for an adopted IP |
| `adopted` | List currently adopted IP addresses |
| `clear` | Clear the terminal screen |

### HTTP

| Command | Description |
|---------|-------------|
| `http_serve` | Serve files over HTTP on an adopted IP address |

### TCP (shell only)

| Command | Description |
|---------|-------------|
| `tcp_connect` | Open a raw TCP connection |
| `tcp_listen` | Wait for one incoming TCP connection |
| `tcp_send` | Send data over a TCP session |
| `tcp_recv` | Receive data from a TCP session |
| `tcp_close` | Close a TCP session |
| `tcp_sessions` | List active TCP sessions |

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

Captures and prints packets on a network interface. Runs until interrupted (Ctrl+C).

```bash
./kraken capture
./kraken capture -i eth0
```

```lua
capture()
capture{i="eth0"}
```

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

### `adopt`

Responds to ARP requests and ICMP echo requests for an IP address that is not bound to the interface. A background listener is started on the interface and sends replies whenever another host queries the adopted IP.

If only an IP is given, the interface's own MAC is advertised. A custom MAC can be specified.

```lua
adopt{ip="192.168.1.100"}
adopt{ip="192.168.1.100", i="eth0"}
adopt{ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | IP address to adopt (required) | |
| `i` | Interface to listen on | first active |
| `mac` | MAC address to advertise | interface MAC |

---

### `unadopt`

Stops responding for the given adopted IP. The interface listener shuts down automatically when no adopted IPs remain on it.

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

### `clear`

Clears the terminal screen. Works on Linux, macOS, and Windows.

```lua
clear()
```

---

## HTTP

### `http_serve`

Serves files over HTTP on an adopted IP address using kraken's raw TCP stack. Runs until interrupted (Ctrl+C). The IP is automatically adopted (ARP answered) for the duration of the server; if it was already adopted manually, the existing MAC is used and the adoption is left in place on exit.

```lua
http_serve{ip="192.168.1.100", port=80}
http_serve{ip="192.168.1.100", port=8080, path="/var/www/html"}
http_serve{ip="192.168.1.100", port=80, i="eth0"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `ip` | IPv4 address to listen on (required) | |
| `port` | TCP port to listen on (required) | |
| `path` | Directory to serve | current working directory |
| `i` | Interface to use | first active |

**Notes:**
- `http_serve` blocks the REPL until Ctrl+C. Use `script()` to automate pre-setup before calling it.
- Handles multiple simultaneous connections; each is served in its own goroutine.
- Uses Go's standard `http.FileServer` — directory listings and range requests are supported out of the box.
- HTTP/1.x only (no HTTP/2).

**Example workflow:**

```lua
-- Optional: pre-adopt with a custom MAC
adopt{ip="192.168.1.100", mac="de:ad:be:ef:00:01", i="eth0"}

-- Start the file server (blocks until Ctrl+C)
http_serve{ip="192.168.1.100", port=80, path="/tmp/files"}
```

---

## TCP (shell only)

The TCP commands implement a full userspace TCP stack on top of raw pcap handles. Each session maintains its own pcap capture handle, sequence numbers, and receive buffer. Sessions are identified by an integer session ID returned by `tcp_connect` or `tcp_listen`.

### `tcp_connect`

Opens a raw TCP connection to a remote host and port. Performs a full three-way handshake and returns a session ID.

```lua
s = tcp_connect{dst="192.168.1.1", port=80}
s = tcp_connect{dst="192.168.1.1", port=80, i="eth0"}
s = tcp_connect{dst="192.168.1.1", port=80, src_port=12345}
s = tcp_connect{dst="192.168.1.1", port=80, tcp={window=8192}}
```

| Field | Description | Default |
|-------|-------------|---------|
| `dst` | Destination IP address (required) | |
| `port` | Destination port (required) | |
| `i` | Interface to use | first active |
| `src_port` | Source port | random ephemeral (49152–65535) |
| `tcp.window` | TCP receive window size | `65535` |

---

### `tcp_listen`

Waits for one incoming TCP connection on the given port. Completes the three-way handshake and returns a session ID. Blocks until a connection arrives or the optional timeout elapses.

To listen on an adopted IP (e.g. one not assigned to the interface), pass `ip` and the MAC will be resolved automatically from the adoptions table.

```lua
s = tcp_listen{port=8080}
s = tcp_listen{port=8080, i="eth0"}
s = tcp_listen{port=8080, timeout=30}
s = tcp_listen{port=8080, ip="192.168.1.100"}
s = tcp_listen{port=8080, ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}
```

| Field | Description | Default |
|-------|-------------|---------|
| `port` | Local port to listen on (required) | |
| `i` | Interface to listen on | first active |
| `timeout` | Seconds to wait for a SYN (0 = indefinite) | `0` |
| `ip` | Source IP (for adopted addresses) | interface IP |
| `mac` | Source MAC (for adopted addresses) | from adoptions table or interface MAC |
| `tcp.window` | TCP receive window size | `65535` |

**Note:** `tcp_listen` accepts exactly one connection. For a persistent multi-connection server, use `http_serve`.

---

### `tcp_send`

Sends data over an established TCP session. The session must be in `ESTABLISHED` or `CLOSE_WAIT` state (the peer may have sent FIN, but you can still write before closing your side).

```lua
tcp_send(s, "GET / HTTP/1.0\r\n\r\n")
tcp_send(s, "hello")
```

---

### `tcp_recv`

Blocks until data arrives and returns all currently buffered bytes as a string. Default timeout is 5 seconds.

```lua
data = tcp_recv(s)
data = tcp_recv(s, 10)  -- 10-second timeout
```

---

### `tcp_close`

Performs a graceful TCP close (FIN handshake) and removes the session. Works whether the local side or the peer initiated the close. If the session was already closed by the peer (e.g. RST received), resources are freed immediately without sending a FIN.

```lua
tcp_close(s)
```

---

### `tcp_sessions`

Lists all currently active TCP sessions with their ID, local/remote endpoints, and current TCP state.

```lua
tcp_sessions()
```

**Example output:**

```
ID    local                   remote                  state
1     192.168.1.5:54321       192.168.1.1:80          ESTABLISHED
2     192.168.1.100:8080      192.168.1.7:44210       CLOSE_WAIT
```

---

## Known issues and caveats

### Privileges required

Root (Linux/macOS) or Administrator (Windows) privileges are required because pcap opens raw sockets. On Linux, granting `CAP_NET_RAW` to the binary is an alternative to running as root:

```bash
sudo setcap cap_net_raw+eip ./kraken
```

### IPv4 only

kraken's TCP stack and `http_serve` support IPv4 only. IPv6 is not implemented.

### OS kernel RST interference

On Linux, when the kernel receives a TCP SYN destined for an IP that **is** assigned to the machine (not just adopted), it will send a TCP RST before kraken's userspace stack can respond. This tears down the connection before the handshake completes.

For **adopted IPs** (IPs not assigned to any local interface), the kernel does not know about the address and will not interfere — this is the intended use case for `tcp_listen` and `http_serve`.

If you observe unexpected RST packets, verify the target IP is not assigned to an interface:

```bash
ip addr show   # Linux
ipconfig       # Windows
```

### No TCP retransmission

The userspace TCP stack does not retransmit lost segments. On lossy links, data may be silently dropped and `tcp_recv` will time out. Reliable delivery requires application-level retry logic.

### No flow control or congestion control

There is no sliding window, SACK, or congestion control algorithm. `tcp_send` writes every segment immediately. On rate-limited paths, the receiver's buffer may overflow and silently drop packets.

### No IP fragmentation on send

Outgoing packets are never fragmented. If a packet exceeds the path MTU it will be silently dropped by the network. Incoming fragmented packets are reassembled correctly.

### No TCP TIME_WAIT

After a session is closed, the same source port can be reused immediately. This deviates from the TCP specification's 2MSL wait but is standard for raw-socket tools.

### `http_serve` blocks the REPL

`http_serve` blocks until Ctrl+C. There is no background mode; use a separate terminal session or a script file that calls `http_serve` as its last statement.

### In-flight handshakes delay listener shutdown

When `http_serve` is stopped while handshakes are in progress, each in-flight goroutine may wait up to 10 seconds to complete its FIN exchange before exiting. Shutdown can therefore take up to 10 seconds if connections were being established at the time of Ctrl+C.

### Windows: Npcap required

On Windows, [Npcap](https://npcap.com/) must be installed with WinPcap compatibility mode enabled. The legacy WinPcap is no longer maintained and is not supported.

---

## Future work

### TCP reliability
- **Retransmission**: detect segment loss via timeout or duplicate ACKs and retransmit. Essential for use on anything other than a local LAN.
- **Sliding window / flow control**: honour the receiver's advertised window size.
- **Congestion control**: implement a basic algorithm (e.g. TCP Reno) to avoid saturating the path.
- **SACK support**: parse and generate Selective ACK options for faster multi-loss recovery.

### Protocol support
- **IPv6**: extend the stack to handle IPv6, NDP, and ICMPv6.
- **UDP**: add `udp_send` / `udp_recv` commands for stateless datagram exchange.
- **DNS**: a simple resolver built on UDP would unlock hostname-based targeting across all commands.
- **IP fragmentation on send**: fragment outgoing packets when they exceed the interface MTU.

### HTTP server
- **TLS/HTTPS**: integrate Go's `crypto/tls`; the `TCPListener` already satisfies `net.Listener` so this is straightforward.
- **Non-blocking mode**: start the server in the background and return a handle to the REPL so the user can continue issuing commands while the server runs.
- **Access logging**: print each request (method, path, status, bytes) to the shell in real time.
- **Graceful shutdown**: wait for in-flight HTTP requests to complete before tearing down the listener.

### Listener API
- **Multi-connection `tcp_listen`**: expose `TCPListener` to Lua as a first-class object with `accept()` / `close()` methods, enabling hand-rolled servers without going through `http_serve`.

### Tooling
- **Port scanner**: iterate over a port range using short-timeout TCP connect attempts and report open/closed/filtered.
- **PCAP file capture and replay**: write captured packets to `.pcap` files and replay them on demand.
- **Kernel RST suppression**: on Linux, automatically install an `nftables`/`iptables` rule to drop outgoing RSTs for adopted IPs while kraken is running, removing the need for the address to be unassigned from the interface.
