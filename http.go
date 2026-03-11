package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ── TCPSession as net.Conn ────────────────────────────────────────────────────

// Read reads up to len(b) bytes from the receive buffer, blocking until data
// arrives, the read deadline elapses, or the connection is closed.
func (s *TCPSession) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.recvBuf) == 0 {
		// The peer will send no more data in CLOSE_WAIT (peer FIN received),
		// LAST_ACK (we also sent FIN), or CLOSED.
		switch s.state {
		case tcpStateCloseWait, tcpStateLastAck, tcpStateClosed:
			return 0, io.EOF
		}
		dl := s.readDeadline
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.AfterFunc(d, func() { s.recvCond.Broadcast() })
			s.recvCond.Wait()
			t.Stop()
		} else {
			s.recvCond.Wait()
		}
	}
	n := copy(b, s.recvBuf)
	// Shift remaining bytes to the front so the backing array is reused.
	remaining := copy(s.recvBuf, s.recvBuf[n:])
	s.recvBuf = s.recvBuf[:remaining]
	return n, nil
}

// Write sends b over the session, respecting the write deadline.
func (s *TCPSession) Write(b []byte) (int, error) {
	s.mu.Lock()
	dl := s.writeDeadline
	s.mu.Unlock()
	if !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := tcpSend(s, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close initiates a graceful TCP close.
func (s *TCPSession) Close() error { return tcpClose(s) }

// LocalAddr returns the local (source) address of the session.
func (s *TCPSession) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: s.srcIP, Port: int(s.srcPort)}
}

// RemoteAddr returns the remote (destination) address of the session.
func (s *TCPSession) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: s.dstIP, Port: int(s.dstPort)}
}

// SetDeadline sets both read and write deadlines.
func (s *TCPSession) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.recvCond.Broadcast()
	s.mu.Unlock()
	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
func (s *TCPSession) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.recvCond.Broadcast()
	s.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (s *TCPSession) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

var _ net.Conn = (*TCPSession)(nil)

// ── TCPListener as net.Listener ───────────────────────────────────────────────

// TCPListener accepts inbound TCP connections on a given port using moto's
// raw-socket stack.  A single persistent pcap handle watches for SYNs; each
// accepted SYN is handed to its own goroutine which opens a per-session handle
// and completes the handshake, so the listener never misses a new SYN while a
// handshake is in progress.
type TCPListener struct {
	iface     net.Interface
	srcIP     net.IP
	srcMAC    net.HardwareAddr
	port      uint16
	tcpParams TCPParams

	handle    *pcap.Handle    // shared listener handle — closed by Close()
	connCh    chan *TCPSession // established sessions ready for Accept()
	done      chan struct{}    // closed by Close() to unblock Accept()
	closeOnce sync.Once

	pendingMu sync.Mutex
	pending   map[string]struct{} // 4-tuples currently completing a handshake
}

// NewTCPListener opens a listener on the given interface and port.
// srcIP / srcMAC may be nil to use the interface's own address/MAC.
func NewTCPListener(iface net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, port uint16, tcpParams TCPParams) (*TCPListener, error) {
	if srcIP == nil {
		var err error
		if srcIP, err = ifaceIPv4(iface); err != nil {
			return nil, err
		}
	}
	if srcMAC == nil {
		srcMAC = iface.HardwareAddr
	}
	devName, err := pcapDeviceName(iface)
	if err != nil {
		return nil, err
	}
	bpf := fmt.Sprintf(
		"(tcp and dst host %s and dst port %d) or (ip[6:2] & 0x3fff != 0)",
		srcIP, port,
	)
	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
		return nil, fmt.Errorf("BPF filter: %w", err)
	}
	l := &TCPListener{
		iface:     iface,
		srcIP:     srcIP,
		srcMAC:    srcMAC,
		port:      port,
		tcpParams: tcpParams,
		handle:    handle,
		connCh:    make(chan *TCPSession, 8),
		done:      make(chan struct{}),
		pending:   make(map[string]struct{}),
	}
	go l.listenLoop()
	return l, nil
}

// listenLoop reads the shared handle continuously.  For each clean SYN it
// spawns acceptSYN to complete the handshake in the background.
func (l *TCPListener) listenLoop() {
	defer close(l.connCh)
	src := gopacket.NewPacketSource(l.handle, l.handle.LinkType())
	defragger := ip4defrag.NewIPv4Defragmenter()
	for {
		select {
		case <-l.done:
			return
		default:
		}
		rawPkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return // handle closed
		}
		pkt, err := defragPacket(defragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}
		ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		tcpPkt, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || !tcpPkt.SYN || tcpPkt.ACK {
			continue
		}
		ethPkt, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", ip4Pkt.SrcIP, tcpPkt.SrcPort)
		l.pendingMu.Lock()
		_, inProgress := l.pending[key]
		if !inProgress {
			l.pending[key] = struct{}{}
		}
		l.pendingMu.Unlock()
		if inProgress {
			continue // SYN retransmission — handshake already in flight
		}
		go l.acceptSYN(key, pkt, ip4Pkt, tcpPkt, ethPkt)
	}
}

// acceptSYN opens a per-session handle, sends the SYN-ACK, waits for the
// final ACK, and enqueues the established session on connCh.
// Running concurrently with listenLoop and other acceptSYN goroutines means
// the listener never stalls on a single client's handshake.
func (l *TCPListener) acceptSYN(key string, synPkt gopacket.Packet, ip4Pkt *layers.IPv4, synTCP *layers.TCP, ethPkt *layers.Ethernet) {
	defer func() {
		l.pendingMu.Lock()
		delete(l.pending, key)
		l.pendingMu.Unlock()
	}()
	clientIP := ip4Pkt.SrcIP.To4()
	clientPort := uint16(synTCP.SrcPort)
	clientMAC := net.HardwareAddr(ethPkt.SrcMAC)

	devName, err := pcapDeviceName(l.iface)
	if err != nil {
		return
	}
	narrowBPF := fmt.Sprintf(
		"(tcp and src host %s and src port %d and dst port %d) or (ip[6:2] & 0x3fff != 0)",
		clientIP, clientPort, l.port,
	)
	// Open the session handle before sending SYN-ACK so we don't miss the
	// client's ACK or any early data.
	sessHandle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return
	}
	if err := sessHandle.SetBPFFilter(narrowBPF); err != nil {
		sessHandle.Close()
		return
	}

	s := &TCPSession{
		iface:     l.iface,
		handle:    sessHandle,
		srcIP:     l.srcIP,
		dstIP:     clientIP,
		srcPort:   l.port,
		dstPort:   clientPort,
		srcMAC:    l.srcMAC,
		dstMAC:    clientMAC,
		tcpParams: l.tcpParams,
		state:     tcpStateSynSent,
		seqOut:    randomISN(),
		ackIn:     synTCP.Seq + 1,
		seedPkt:   synPkt,
		synAckCh:  make(chan error, 1),
	}
	s.recvCond = sync.NewCond(&s.mu)

	if err := s.sendTCP(true, true, false, false, false, nil); err != nil {
		sessHandle.Close()
		return
	}
	s.mu.Lock()
	s.seqOut++
	s.mu.Unlock()

	// Wait for the final ACK on the session handle.
	// gopacket.PacketSource.NextPacket() is synchronous (no background
	// goroutine), so handing the handle to recvLoop afterward is safe.
	ackSrc := gopacket.NewPacketSource(sessHandle, sessHandle.LinkType())
	ackDefragger := ip4defrag.NewIPv4Defragmenter()
	deadline := time.Now().Add(tcpListenHandshakeTimeout)

	for {
		if time.Now().After(deadline) {
			sessHandle.Close()
			return
		}
		rawPkt, err := ackSrc.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			sessHandle.Close()
			return
		}
		pkt, err := defragPacket(ackDefragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}
		ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !ip4.SrcIP.To4().Equal(clientIP) {
			continue
		}
		tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || uint16(tcp.SrcPort) != clientPort {
			continue
		}
		if tcp.RST {
			sessHandle.Close()
			return
		}
		if tcp.ACK && !tcp.SYN {
			break // handshake complete
		}
	}

	s.mu.Lock()
	s.state = tcpStateEstablished
	s.mu.Unlock()

	globalTCPSessions.add(s)
	go s.recvLoop()

	select {
	case l.connCh <- s:
	case <-l.done:
		tcpClose(s) //nolint:errcheck
	}
}

// Accept blocks until an inbound connection is established or the listener is
// closed.
func (l *TCPListener) Accept() (net.Conn, error) {
	select {
	case sess, ok := <-l.connCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return sess, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close shuts down the listener.  In-progress handshakes are abandoned;
// already-established sessions returned by Accept are unaffected.
func (l *TCPListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.handle.Close() // causes listenLoop's NextPacket to return an error
	})
	return nil
}

// Addr returns the listener's network address.
func (l *TCPListener) Addr() net.Addr {
	return &net.TCPAddr{IP: l.srcIP, Port: int(l.port)}
}

var _ net.Listener = (*TCPListener)(nil)
