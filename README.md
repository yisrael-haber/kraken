# moto

A network packet capture and ARP (Address Resolution Protocol) management tool written in Zig. Moto leverages libpcap to capture and analyze network packets, with built-in support for parsing Ethernet and ARP headers.

## Overview

Moto is designed to:
- **Capture network packets** in real-time using libpcap
- **Parse and analyze protocol headers** (Ethernet, ARP, and extensible to others)
- **Manage ARP lookups** with caching to map IP addresses to MAC addresses
- **Query the network** for ARP information on demand

## Architecture

### Core Components

- **`main.zig`** - Entry point; initializes network interfaces and starts the ARP manager
- **`pcap.zig`** - Bindings to the libpcap C library for packet capture
- **`protocol_headers.zig`** - Protocol header definitions and serialization/deserialization logic
  - `EthernetHeader` - Layer 2 (link layer) header structure
  - `ArpHeader` - Layer 3 protocol for IP-MAC address resolution
  - `HeaderNode` - Linked list structure for chaining headers

- **Managers/**
  - `ArpManager.zig` - Maintains ARP cache and handles ARP queries; looks up MAC addresses for given IPs

- **Handlers/**
  - `libpcap_handler.zig` - Wraps libpcap functionality for packet capture and reception

## How It Works

1. **Initialization**: The program initializes libpcap handlers on specified network interfaces (default: `eth0`)
2. **Packet Capture**: Continuously listens for incoming packets on the network interface
3. **Header Parsing**: Incoming Ethernet frames are parsed; ARP packets are identified and extracted
4. **ARP Cache Management**: 
   - When an ARP reply is received, the IP-to-MAC mapping is cached
   - Subsequent lookups for the same IP are served from cache
5. **ARP Queries**: If a MAC address is needed but not cached, the tool sends an ARP request and waits for a reply

## Building and Running

### Prerequisites

- Zig compiler (latest version)
- libpcap development libraries (`libpcap-dev` on Debian/Ubuntu)
- Root/sudo access (required for raw packet capture)

### Build

```bash
zig build
```

### Run

```bash
sudo ./zig-out/bin/moto
```

The program requires elevated privileges to capture packets on the network interface.

## Usage

Currently, moto performs the following on startup:
1. Lists all available network interfaces
2. Opens a handler on the `eth0` interface
3. Performs an ARP query for `10.10.10.10`
4. Displays the results

Future versions may support:
- Custom interface selection
- Configurable target IPs
- Interactive command-line interface

## Example Flow

```
1. Program starts → discovers network interfaces
2. Opens packet capture on eth0
3. Sends ARP request: "Who has 10.10.10.10?"
4. Listens for ARP reply containing the MAC address
5. Caches the result: 10.10.10.10 → MAC address
6. Prints the resolved mapping
```

## Project Structure

```
moto/
├── build.zig              # Zig build configuration
├── build.zig.zon          # Build dependencies
├── src/
│   ├── main.zig          # Entry point
│   ├── pcap.zig          # libpcap bindings
│   ├── protocol_headers.zig  # Header definitions
│   ├── root.zig          # Module root
│   ├── Handlers/
│   │   └── libpcap_handler.zig  # Packet capture wrapper
│   └── Managers/
│       └── ArpManager.zig       # ARP cache & queries
├── test/                  # Test files
└── zig-out/              # Build output
```

## Roadmap / Future Enhancements

### Phase 1: Core Protocol Support
- [ ] **IPv4 Header Parsing** - Add support for parsing and analyzing IPv4 headers
- [ ] **IPv6 Header Parsing** - Extend support to IPv6 packets and dual-stack networks
- [ ] **ICMP Protocol Handler** - Implement ICMP for ping and diagnostics
- [ ] **TCP/UDP Header Parsing** - Support transport layer protocols for deeper packet analysis

### Phase 2: Advanced ARP Features
- [ ] **Gratuitous ARP Detection** - Identify and log gratuitous ARP requests/replies
- [ ] **ARP Poisoning Detection** - Detect potential ARP spoofing attacks
- [ ] **Static ARP Entries** - Allow manual ARP cache entries for security
- [ ] **ARP Table Export** - Export discovered ARP mappings to file (CSV/JSON)
- [ ] **TTL Management** - Implement configurable TTL for ARP cache entries

### Phase 3: Configuration & CLI
- [ ] **Command-line Argument Parser** - Support custom interface, target IPs, timeout values
- [ ] **Config File Support** - Load settings from YAML/TOML configuration files
- [ ] **Interactive Shell** - Implement REPL for real-time queries and commands
- [ ] **Verbose Logging Levels** - Debug, info, warning, error output control

### Phase 4: Filtering & Capture
- [ ] **Packet Filtering** - BPF (Berkeley Packet Filter) integration for selective capture
- [ ] **Protocol-specific Filters** - Filter by source/dest IP, MAC, port ranges, etc.
- [ ] **Ring Buffer Implementation** - Circular buffer for efficient memory usage

### Phase 5: Analysis & Statistics
- [ ] **Packet Statistics** - Count packets by protocol, direction, source, destination
- [ ] **Bandwidth Monitoring** - Real-time throughput calculation

### Phase 6: Output & Reporting
- [ ] **PCAP File Export** - Write captured packets to standard PCAP format
- [ ] **JSON Export** - Export parsed packet data as JSON for integration

### Phase 7: DNS & Service Discovery
- [ ] **DNS Packet Parsing** - Capture and analyze DNS queries/responses
- [ ] **DNS Cache** - Cache DNS lookups for hostname resolution
- [ ] **Service Discovery** - Detect common network services (HTTP, SSH, etc.)

### Phase 8: Advanced Features
- [ ] **Packet Reconstruction** - Reassemble fragmented packets
- [ ] **Session Tracking** - Follow TCP connection lifecycle
- [ ] **Multi-interface Capture** - Simultaneously capture on multiple interfaces

### Phase 9: Performance & Optimization
- [ ] **Parallel Packet Processing** - Multi-threaded packet handling
- [ ] **Memory Pooling** - Custom allocators for high-performance capture
- [ ] **Zero-copy Techniques** - Minimize data copying during processing
- [ ] **Benchmarking Suite** - Performance tests and profiling tools
- [ ] **Hardware Acceleration** - DPDK or similar for high-speed capture

### Quality Assurance
- [ ] **Unit Tests** - Comprehensive test coverage for all modules
- [ ] **Integration Tests** - Test real network scenarios
- [ ] **Fuzzing** - Fuzz testing with malformed packets
- [ ] **Documentation** - API docs, user guide, architecture documentation
- [ ] **Example Scripts** - Sample scripts demonstrating common use cases
