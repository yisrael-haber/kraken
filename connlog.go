package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// connKey uniquely identifies a TCP connection from the perspective of an adopted IP.
// localPort is the adopted IP's port; remotePort is the peer's port.
type connKey struct {
	adoptedIP  [4]byte
	localPort  uint16
	remoteIP   [4]byte
	remotePort uint16
}

// connLogEntry holds accumulated metadata for a single TCP connection.
type connLogEntry struct {
	adoptedIP   net.IP
	localPort   uint16
	remoteIP    net.IP
	remotePort  uint16
	connectedAt time.Time
	closedAt    time.Time // zero if still open
	rxBytes     int64     // bytes received by the adopted IP (inbound payloads)
	txBytes     int64     // bytes sent by the adopted IP (outbound payloads)
}

func (e *connLogEntry) closed() bool { return !e.closedAt.IsZero() }

// connLogStore is the global per-connection tracking store.
type connLogStore struct {
	mu      sync.Mutex
	entries map[connKey]*connLogEntry
}

var globalConnLog = &connLogStore{
	entries: make(map[connKey]*connLogEntry),
}

// keyFor builds a connKey. adoptedIP is the local side.
func keyFor(adoptedIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) connKey {
	var k connKey
	copy(k.adoptedIP[:], adoptedIP.To4())
	k.localPort = localPort
	copy(k.remoteIP[:], remoteIP.To4())
	k.remotePort = remotePort
	return k
}

// parseTCP extracts TCP fields from a raw IPv4 packet.
// Returns ok=false if the packet is too short or not TCP.
func parseTCP(ipBytes []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte, payload int, ok bool) {
	if len(ipBytes) < 20 {
		return
	}
	if ipBytes[9] != 6 { // not TCP
		return
	}
	ihl := int(ipBytes[0]&0x0f) * 4
	totalLen := int(ipBytes[2])<<8 | int(ipBytes[3])
	if len(ipBytes) < ihl+20 || totalLen < ihl+20 {
		return
	}
	tcp := ipBytes[ihl:]
	tcpHdrLen := int(tcp[12]>>4) * 4
	if tcpHdrLen < 20 || len(tcp) < tcpHdrLen {
		return
	}
	srcIP = net.IP(ipBytes[12:16])
	dstIP = net.IP(ipBytes[16:20])
	srcPort = uint16(tcp[0])<<8 | uint16(tcp[1])
	dstPort = uint16(tcp[2])<<8 | uint16(tcp[3])
	flags = tcp[13]
	payload = totalLen - ihl - tcpHdrLen
	if payload < 0 {
		payload = 0
	}
	ok = true
	return
}

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
)

// UpdateInbound is called from injectInbound with raw IPv4 bytes that are
// heading INTO the gVisor stack (packets destined for adoptedIP).
func (s *connLogStore) UpdateInbound(adoptedIP net.IP, ipBytes []byte) {
	srcIP, dstIP, srcPort, dstPort, flags, payloadLen, ok := parseTCP(ipBytes)
	if !ok {
		return
	}
	_ = dstIP // dstIP == adoptedIP
	adopted4 := adoptedIP.To4()
	if adopted4 == nil {
		return
	}

	k := keyFor(adopted4, dstPort, srcIP, srcPort)

	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.entries[k]
	if !exists {
		e = &connLogEntry{
			adoptedIP:   net.IP(append([]byte{}, adopted4...)),
			localPort:   dstPort,
			remoteIP:    net.IP(append([]byte{}, srcIP.To4()...)),
			remotePort:  srcPort,
			connectedAt: time.Now(),
		}
		s.entries[k] = e
	}
	e.rxBytes += int64(payloadLen)
	if flags&(tcpFlagFIN|tcpFlagRST) != 0 && !e.closed() {
		e.closedAt = time.Now()
	}
}

// UpdateOutbound is called from runOutbound with raw IPv4 bytes that are
// leaving the gVisor stack (packets sourced from adoptedIP).
func (s *connLogStore) UpdateOutbound(adoptedIP net.IP, ipBytes []byte) {
	srcIP, _, srcPort, dstPort, flags, payloadLen, ok := parseTCP(ipBytes)
	if !ok {
		return
	}
	_ = srcIP // srcIP == adoptedIP
	adopted4 := adoptedIP.To4()
	if adopted4 == nil {
		return
	}

	// dstIP is the remote peer
	dstIP := net.IP(ipBytes[16:20])
	k := keyFor(adopted4, srcPort, dstIP, dstPort)

	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.entries[k]
	if !exists {
		// Outbound-only connection (e.g. dial); create the entry.
		e = &connLogEntry{
			adoptedIP:   net.IP(append([]byte{}, adopted4...)),
			localPort:   srcPort,
			remoteIP:    net.IP(append([]byte{}, dstIP.To4()...)),
			remotePort:  dstPort,
			connectedAt: time.Now(),
		}
		s.entries[k] = e
	}
	e.txBytes += int64(payloadLen)
	if flags&(tcpFlagFIN|tcpFlagRST) != 0 && !e.closed() {
		e.closedAt = time.Now()
	}
}

// Snapshot returns all entries sorted by connectedAt (oldest first).
func (s *connLogStore) Snapshot() []*connLogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*connLogEntry, 0, len(s.entries))
	for _, e := range s.entries {
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].connectedAt.Before(out[j].connectedAt)
	})
	return out
}

// Clear removes all entries.
func (s *connLogStore) Clear() {
	s.mu.Lock()
	s.entries = make(map[connKey]*connLogEntry)
	s.mu.Unlock()
}

// Print displays the connection log to stdout.
func (s *connLogStore) Print() {
	entries := s.Snapshot()
	if len(entries) == 0 {
		fmt.Println(dim("(no connections logged)"))
		return
	}
	fmt.Printf("%-21s %-21s %-10s %-10s %-8s %s\n",
		bold("Local"), bold("Remote"), bold("RX bytes"), bold("TX bytes"), bold("Status"), bold("Connected"))
	fmt.Println(dim("─────────────────────────────────────────────────────────────────────────────────────"))
	for _, e := range entries {
		local := fmt.Sprintf("%s:%d", e.adoptedIP, e.localPort)
		remote := fmt.Sprintf("%s:%d", e.remoteIP, e.remotePort)
		status := green("open")
		if e.closed() {
			status = dim("closed")
		}
		fmt.Printf("%-21s %-21s %-10d %-10d %-8s %s\n",
			cyan(local), remote, e.rxBytes, e.txBytes, status,
			e.connectedAt.Format("15:04:05"))
	}
}
