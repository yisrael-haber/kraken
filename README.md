# moto

A network toolkit with a Lua-powered interactive shell.

## Requirements

### Linux
- `libpcap` (e.g. via Wireshark or `apt install libpcap0.8`)

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

Full Lua is available — variables, loops, and conditionals all work. Type `help()` to list commands and `help("command")` for detailed usage of a specific command.

### CLI (non-interactive)

Commands can also be run directly without entering the shell:

```bash
./moto devices
./moto arp -t 192.168.1.1
./moto arp -t 192.168.1.1 -i eth0
./moto capture
./moto capture -i eth0
```

## Commands

| Command | Description |
|---------|-------------|
| `devices` | List active network interfaces |
| `arp` | Send an ARP request |
| `capture` | Capture and print packets on an interface |

### `arp` options

| Flag | Description |
|------|-------------|
| `-t <ip>` | Target IP address (required) |
| `-i <iface>` | Interface to use (default: first active) |
| `-src-ip <ip>` | Source IP override |
| `-src-mac <mac>` | Source MAC override |

### Shell syntax

```lua
devices()
arp{t="192.168.1.1"}
arp{t="192.168.1.1", i="eth0"}
arp{t="192.168.1.1", ["src-ip"]="10.0.0.5"}
capture()
capture{i="eth0"}
```
