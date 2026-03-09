# moto

A network toolkit with a Lua-powered interactive shell.

## Requirements

### Linux
- `libpcap` (e.g. via Wireshark or `apt install libpcap-dev`)

### Windows
- [Npcap](https://npcap.com/) installed on the target machine

## Building

```bash
# Linux
go build -o moto .

# Windows
go build -o moto.exe .
```

## Usage

### Interactive shell

Run with no arguments to open the Lua shell:

```
$ ./moto
moto shell — full Lua available. Type help() for commands, exit to quit.
moto>
```

Full Lua is available — variables, loops, functions, and conditionals all work. State persists across commands for the lifetime of the session.

Type `help()` to list commands and `help("command")` for detailed usage.

### CLI (non-interactive)

Commands can also be run directly without entering the shell:

```bash
./moto devices
./moto arp -t 192.168.1.1
./moto arp -t 192.168.1.1 -i eth0
./moto ping -t 192.168.1.1
./moto ping -t 192.168.1.1 -n 5
./moto capture
./moto capture -i eth0
./moto script path/to/script.lua
```

## Commands

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

---

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
./moto capture
./moto capture -i eth0
```

```lua
capture()
capture{i="eth0"}
```

---

### `script`

Loads and runs a Lua script file. All moto commands are available as globals inside the script.

```bash
./moto script path/to/script.lua
```

From the interactive shell, `script()` runs the file in the **same runtime**, so any globals or functions defined in the script remain available afterwards. Scripts can also call `script()` themselves to load further files.

```lua
-- from the shell
script("helpers.lua")
send_range("192.168.1", 1, 254)  -- function defined in helpers.lua

-- helpers.lua example
function send_range(subnet, first, last)
    for i = first, last do
        arp{t=subnet .. "." .. i}
    end
end
```

---

### `arpcache`

Displays all entries in the ARP cache. Entries expire after 5 minutes; a new ARP request is issued automatically on next use. The cache is populated whenever moto resolves a MAC address (e.g. when sending a ping).

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
