package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

// ── TCP state ─────────────────────────────────────────────────────────────────

type tcpState int

const (
	tcpStateSynSent     tcpState = iota
	tcpStateEstablished          // three-way handshake complete
	tcpStateFinWait1             // we sent FIN, waiting for ACK
	tcpStateFinWait2             // our FIN was ACKed, waiting for peer FIN
	tcpStateCloseWait            // peer sent FIN first; we still need to send ours
	tcpStateLastAck              // we sent FIN after CLOSE_WAIT, waiting for final ACK
	tcpStateClosed
)

func (s tcpState) String() string {
	switch s {
	case tcpStateSynSent:
		return "SYN_SENT"
	case tcpStateEstablished:
		return "ESTABLISHED"
	case tcpStateFinWait1:
		return "FIN_WAIT_1"
	case tcpStateFinWait2:
		return "FIN_WAIT_2"
	case tcpStateCloseWait:
		return "CLOSE_WAIT"
	case tcpStateLastAck:
		return "LAST_ACK"
	case tcpStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// ── Session ───────────────────────────────────────────────────────────────────

type TCPSession struct {
	id      int
	iface   net.Interface
	handle  *pcap.Handle

	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	tcpParams TCPParams

	mu      sync.Mutex
	sendMu  sync.Mutex // serialises WritePacketData calls across goroutines
	state   tcpState
	seqOut  uint32 // next sequence number to place in outgoing segments
	ackIn   uint32 // next expected byte from peer (= ACK number we send)

	recvBuf  []byte
	recvCond *sync.Cond // broadcast whenever recvBuf grows or state changes

	// synAckCh receives nil when the SYN-ACK arrives, or an error on RST/failure.
	synAckCh chan error

	// seedPkt holds the peer's initial SYN (server/listen mode) so recvLoop
	// can seed the reassembly assembler with the peer's ISN before data arrives.
	// Without this the first data segment would appear out-of-order and be
	// buffered forever.  Cleared by recvLoop immediately after use.
	seedPkt gopacket.Packet
}

// ── Session table ─────────────────────────────────────────────────────────────

type tcpSessionTable struct {
	mu      sync.RWMutex
	nextID  int
	entries map[int]*TCPSession
}

var globalTCPSessions = &tcpSessionTable{entries: make(map[int]*TCPSession)}

func (t *tcpSessionTable) add(s *TCPSession) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	s.id = t.nextID
	t.entries[t.nextID] = s
	return t.nextID
}

func (t *tcpSessionTable) get(id int) (*TCPSession, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.entries[id]
	return s, ok
}

func (t *tcpSessionTable) remove(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, id)
}

func (t *tcpSessionTable) snapshot() []*TCPSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*TCPSession, 0, len(t.entries))
	for _, s := range t.entries {
		out = append(out, s)
	}
	return out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func randomISN() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func randomEphemeralPort() uint16 {
	var b [2]byte
	rand.Read(b[:])
	// IANA ephemeral range: 49152–65535
	return 49152 + binary.BigEndian.Uint16(b[:])%16383
}

// ── Packet send ───────────────────────────────────────────────────────────────

// sendTCP builds a TCP segment from the current seqOut/ackIn and sends it.
// sendMu ensures that concurrent callers (recvLoop ACKs vs Lua-thread sends)
// do not interleave writes to the same pcap handle.
func (s *TCPSession) sendTCP(syn, ack, psh, fin, rst bool, payload []byte) error {
	s.mu.Lock()
	seq := s.seqOut
	ackNum := s.ackIn
	s.mu.Unlock()

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	eth := buildEthLayer(EthParams{}, s.srcMAC, s.dstMAC, layers.EthernetTypeIPv4)
	ip4Layer := buildIPv4Layer(IPv4Params{}, s.srcIP, s.dstIP, layers.IPProtocolTCP)
	tcpLayer := buildTCPLayer(s.tcpParams, s.srcPort, s.dstPort, seq, ackNum, syn, ack, psh, fin, rst)
	if err := tcpLayer.SetNetworkLayerForChecksum(&ip4Layer); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip4Layer, &tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	return s.handle.WritePacketData(buf.Bytes())
}

// ── Reassembly callbacks ──────────────────────────────────────────────────────

// captureCtx satisfies reassembly.AssemblerContext.
type captureCtx struct{ ci gopacket.CaptureInfo }

func (c *captureCtx) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

// tcpStreamFactory creates a tcpStream for each new 4-tuple the assembler sees.
// Because each session has its own assembler, this always creates streams for
// the same session.
type tcpStreamFactory struct{ session *TCPSession }

func (f *tcpStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return &tcpStream{session: f.session}
}

// tcpStream receives in-order bytes from the assembler and appends them to the
// session's receive buffer.
type tcpStream struct{ session *TCPSession }

func (ts *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true // BPF already limits traffic to our 4-tuple
}

func (ts *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	available, _ := sg.Lengths()
	if available == 0 {
		return
	}
	data := sg.Fetch(available)
	if len(data) == 0 {
		return
	}

	sess := ts.session
	sess.mu.Lock()
	sess.recvBuf = append(sess.recvBuf, data...)
	sess.ackIn += uint32(len(data))
	sess.recvCond.Broadcast()
	sess.mu.Unlock()

	// ACK the delivered bytes.  Called from recvLoop goroutine, so no concurrent
	// read on the handle — sendMu protects against Lua-thread writes.
	sess.sendTCP(false, true, false, false, false, nil)
}

func (ts *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return false // keep stream in pool; we manage lifetime ourselves
}

// ── Receive loop ──────────────────────────────────────────────────────────────

// recvLoop is the per-session background goroutine.  It owns the pcap handle
// for reading and drives the TCP state machine for inbound events.
func (s *TCPSession) recvLoop() {
	defragger := ip4defrag.NewIPv4Defragmenter()
	factory := &tcpStreamFactory{session: s}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	peerIP4 := s.dstIP.To4()

	// Server mode: seed the assembler with the client's SYN so it knows the
	// peer's ISN.  The client-mode equivalent happens inside the loop when the
	// SYN-ACK is received.
	s.mu.Lock()
	seed := s.seedPkt
	s.seedPkt = nil
	s.mu.Unlock()
	if seed != nil {
		if seedTCP, ok := seed.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			assembler.AssembleWithContext(
				seed.NetworkLayer().NetworkFlow(),
				seedTCP,
				&captureCtx{seed.Metadata().CaptureInfo},
			)
		}
	}

	markClosed := func() {
		s.mu.Lock()
		s.state = tcpStateClosed
		s.recvCond.Broadcast()
		s.mu.Unlock()
	}

	for {
		rawPkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err != nil {
			markClosed()
			return
		}

		pkt, err := defragPacket(defragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}

		ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !ip4Pkt.SrcIP.To4().Equal(peerIP4) {
			continue
		}
		tcpPkt, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}

		s.mu.Lock()
		state := s.state
		s.mu.Unlock()

		// ── Handshake phase ──────────────────────────────────────────────────
		if state == tcpStateSynSent {
			if tcpPkt.SYN && tcpPkt.ACK {
				s.mu.Lock()
				s.ackIn = tcpPkt.Seq + 1 // SYN consumes one sequence number
				s.mu.Unlock()
				// Feed the SYN-ACK to the assembler so it records the
				// server's ISN.  The assembler only initialises a stream's
				// nextSeq when it sees a SYN; without this, the first data
				// packet would appear "out of order" and be buffered forever.
				assembler.AssembleWithContext(
					pkt.NetworkLayer().NetworkFlow(),
					tcpPkt,
					&captureCtx{pkt.Metadata().CaptureInfo},
				)
				s.synAckCh <- nil
			} else if tcpPkt.RST {
				s.synAckCh <- fmt.Errorf("connection refused (RST)")
			}
			continue
		}

		// ── RST ──────────────────────────────────────────────────────────────
		if tcpPkt.RST {
			markClosed()
			return
		}

		// ── Data ─────────────────────────────────────────────────────────────
		// Feed before processing FIN so any piggybacked data is not lost.
		if len(tcpPkt.Payload) > 0 {
			assembler.AssembleWithContext(
				pkt.NetworkLayer().NetworkFlow(),
				tcpPkt,
				&captureCtx{pkt.Metadata().CaptureInfo},
			)
		}

		// ── ACK of our FIN ───────────────────────────────────────────────────
		if tcpPkt.ACK {
			s.mu.Lock()
			finAcked := tcpPkt.Ack == s.seqOut
			switch s.state {
			case tcpStateFinWait1:
				if finAcked {
					s.state = tcpStateFinWait2
				}
			case tcpStateLastAck:
				if finAcked {
					s.state = tcpStateClosed
					s.recvCond.Broadcast()
					s.mu.Unlock()
					return
				}
			}
			s.mu.Unlock()
		}

		// ── Peer FIN ─────────────────────────────────────────────────────────
		if tcpPkt.FIN {
			s.mu.Lock()
			// FIN consumes one sequence number; if data was piggybacked,
			// ReassembledSG already advanced ackIn past it, so just add 1.
			s.ackIn++
			switch s.state {
			case tcpStateEstablished:
				s.state = tcpStateCloseWait
				s.recvCond.Broadcast()
				s.mu.Unlock()
				s.sendTCP(false, true, false, false, false, nil)
			case tcpStateFinWait1:
				// Simultaneous close: peer sent FIN before ACKing ours.
				// ACK the peer's FIN and treat the connection as done.
				s.state = tcpStateClosed
				s.recvCond.Broadcast()
				s.mu.Unlock()
				s.sendTCP(false, true, false, false, false, nil)
				return
			case tcpStateFinWait2:
				s.state = tcpStateClosed
				s.recvCond.Broadcast()
				s.mu.Unlock()
				s.sendTCP(false, true, false, false, false, nil) // final ACK
				return
			default:
				s.mu.Unlock()
			}
		}
	}
}

// ── Connect ───────────────────────────────────────────────────────────────────

const tcpConnectTimeout = 10 * time.Second

// doTCPConnect performs a TCP three-way handshake and returns an established session.
// srcPort == 0 picks a random ephemeral port.
func doTCPConnect(iface net.Interface, dstIP net.IP, dstPort, srcPort uint16, tcpParams TCPParams) (*TCPSession, error) {
	srcIP, err := ifaceIPv4(iface)
	if err != nil {
		return nil, err
	}
	dstMAC, err := resolveMAC(iface, dstIP)
	if err != nil {
		return nil, fmt.Errorf("resolving MAC for %s: %w", dstIP, err)
	}
	if srcPort == 0 {
		srcPort = randomEphemeralPort()
	}

	devName, err := pcapDeviceName(iface)
	if err != nil {
		return nil, err
	}

	// Capture inbound segments for our 4-tuple, plus IP fragments for defrag.
	bpf := fmt.Sprintf(
		"(tcp and src host %s and src port %d and dst port %d) or (ip[6:2] & 0x3fff != 0)",
		dstIP, dstPort, srcPort,
	)
	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
		return nil, fmt.Errorf("BPF filter: %w", err)
	}

	s := &TCPSession{
		iface:     iface,
		handle:    handle,
		srcIP:     srcIP,
		dstIP:     dstIP.To4(),
		srcPort:   srcPort,
		dstPort:   dstPort,
		srcMAC:    iface.HardwareAddr,
		dstMAC:    dstMAC,
		tcpParams: tcpParams,
		state:     tcpStateSynSent,
		seqOut:    randomISN(),
		synAckCh:  make(chan error, 1),
	}
	s.recvCond = sync.NewCond(&s.mu)

	go s.recvLoop()

	// SYN
	if err := s.sendTCP(true, false, false, false, false, nil); err != nil {
		handle.Close()
		return nil, fmt.Errorf("sending SYN: %w", err)
	}
	s.mu.Lock()
	s.seqOut++ // SYN consumes one sequence number
	s.mu.Unlock()

	// Wait for SYN-ACK
	select {
	case err := <-s.synAckCh:
		if err != nil {
			handle.Close()
			return nil, err
		}
	case <-time.After(tcpConnectTimeout):
		handle.Close()
		return nil, fmt.Errorf("tcp_connect: timeout")
	}

	// ACK
	if err := s.sendTCP(false, true, false, false, false, nil); err != nil {
		handle.Close()
		return nil, fmt.Errorf("sending ACK: %w", err)
	}

	s.mu.Lock()
	s.state = tcpStateEstablished
	s.mu.Unlock()

	globalTCPSessions.add(s)
	return s, nil
}

// ── Send data ─────────────────────────────────────────────────────────────────

func tcpSend(sess *TCPSession, data []byte) error {
	sess.mu.Lock()
	state := sess.state
	sess.mu.Unlock()
	if state != tcpStateEstablished {
		return fmt.Errorf("tcp_send: session is %s, not ESTABLISHED", state)
	}
	if err := sess.sendTCP(false, true, true, false, false, data); err != nil {
		return err
	}
	sess.mu.Lock()
	sess.seqOut += uint32(len(data))
	sess.mu.Unlock()
	return nil
}

// ── Receive data ──────────────────────────────────────────────────────────────

const defaultTCPRecvTimeout = 5 * time.Second

// tcpRecv blocks until data arrives in the session's receive buffer or timeout
// elapses.  It drains and returns all currently buffered bytes.
func tcpRecv(sess *TCPSession, timeout time.Duration) ([]byte, error) {
	// Wake the cond when the deadline passes so the loop re-evaluates.
	timer := time.AfterFunc(timeout, func() { sess.recvCond.Broadcast() })
	defer timer.Stop()

	deadline := time.Now().Add(timeout)

	sess.mu.Lock()
	defer sess.mu.Unlock()
	for len(sess.recvBuf) == 0 {
		if sess.state == tcpStateClosed {
			return nil, fmt.Errorf("tcp_recv: connection closed")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("tcp_recv: timeout")
		}
		sess.recvCond.Wait()
	}
	data := make([]byte, len(sess.recvBuf))
	copy(data, sess.recvBuf)
	sess.recvBuf = sess.recvBuf[:0]
	return data, nil
}

// ── Close ─────────────────────────────────────────────────────────────────────

const tcpCloseTimeout = 10 * time.Second

// tcpClose performs a graceful TCP close.  Works from both ESTABLISHED
// (active close) and CLOSE_WAIT (passive close after peer FIN).
func tcpClose(sess *TCPSession) error {
	sess.mu.Lock()
	switch sess.state {
	case tcpStateEstablished:
		sess.state = tcpStateFinWait1
	case tcpStateCloseWait:
		sess.state = tcpStateLastAck
	default:
		state := sess.state
		sess.mu.Unlock()
		return fmt.Errorf("tcp_close: session is %s", state)
	}
	sess.mu.Unlock()

	// Send FIN+ACK.
	if err := sess.sendTCP(false, true, false, true, false, nil); err != nil {
		return err
	}
	sess.mu.Lock()
	sess.seqOut++ // FIN consumes one sequence number
	sess.mu.Unlock()

	// Wait for the state machine to reach CLOSED (recvLoop broadcasts on transition).
	timer := time.AfterFunc(tcpCloseTimeout, func() { sess.recvCond.Broadcast() })
	defer timer.Stop()

	deadline := time.Now().Add(tcpCloseTimeout)
	sess.mu.Lock()
	for sess.state != tcpStateClosed {
		if time.Now().After(deadline) {
			break
		}
		sess.recvCond.Wait()
	}
	sess.mu.Unlock()

	globalTCPSessions.remove(sess.id)
	sess.handle.Close()
	return nil
}

// ── Listen ────────────────────────────────────────────────────────────────────

// tcpListenHandshakeTimeout is the deadline for completing the three-way
// handshake after a SYN arrives (not the wait-for-SYN timeout, which is
// caller-supplied via the timeout parameter).
const tcpListenHandshakeTimeout = 10 * time.Second

// doTCPListen waits for an inbound TCP SYN on port, completes the three-way
// handshake, and returns an established session.
// timeout == 0 means wait indefinitely for the initial SYN.
// srcIP / srcMAC may be nil to use the interface's own address/MAC (normal case);
// pass non-nil values to listen on an adopted IP address.
func doTCPListen(iface net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, port uint16, timeout time.Duration, tcpParams TCPParams) (*TCPSession, error) {
	if srcIP == nil {
		var err error
		srcIP, err = ifaceIPv4(iface)
		if err != nil {
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

	// Broad filter: all TCP to our port + IP fragments (for defrag).
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

	// ── Phase 1: wait for SYN ─────────────────────────────────────────────────

	defragger := ip4defrag.NewIPv4Defragmenter()
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	var synDeadline time.Time
	if timeout > 0 {
		synDeadline = time.Now().Add(timeout)
	}

	var synPkt gopacket.Packet
	var clientIP net.IP
	var clientPort uint16
	var clientMAC net.HardwareAddr

	for {
		if !synDeadline.IsZero() && time.Now().After(synDeadline) {
			handle.Close()
			return nil, fmt.Errorf("tcp_listen: timeout waiting for connection")
		}
		rawPkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err != nil {
			handle.Close()
			return nil, fmt.Errorf("tcp_listen: %w", err)
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
		if !ok {
			continue
		}
		// Accept only a clean SYN (not SYN-ACK).
		if !tcpPkt.SYN || tcpPkt.ACK {
			continue
		}
		ethPkt, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}
		clientIP = ip4Pkt.SrcIP.To4()
		clientPort = uint16(tcpPkt.SrcPort)
		clientMAC = net.HardwareAddr(ethPkt.SrcMAC)
		synPkt = pkt
		break
	}

	// Narrow BPF to this specific 4-tuple so the session only sees traffic
	// from the accepted client.
	narrowBPF := fmt.Sprintf(
		"(tcp and src host %s and src port %d and dst port %d) or (ip[6:2] & 0x3fff != 0)",
		clientIP, clientPort, port,
	)
	if err := handle.SetBPFFilter(narrowBPF); err != nil {
		handle.Close()
		return nil, fmt.Errorf("narrowing BPF filter: %w", err)
	}

	s := &TCPSession{
		iface:     iface,
		handle:    handle,
		srcIP:     srcIP,
		dstIP:     clientIP,
		srcPort:   port,
		dstPort:   clientPort,
		srcMAC:    srcMAC,
		dstMAC:    clientMAC,
		tcpParams: tcpParams,
		state:     tcpStateSynSent, // temporary; set to ESTABLISHED after ACK
		seqOut:    randomISN(),
		ackIn:     synPkt.Layer(layers.LayerTypeTCP).(*layers.TCP).Seq + 1,
		seedPkt:   synPkt,
		synAckCh:  make(chan error, 1),
	}
	s.recvCond = sync.NewCond(&s.mu)

	// Send SYN-ACK.
	if err := s.sendTCP(true, true, false, false, false, nil); err != nil {
		handle.Close()
		return nil, fmt.Errorf("sending SYN-ACK: %w", err)
	}
	s.mu.Lock()
	s.seqOut++ // SYN-ACK consumes one sequence number
	s.mu.Unlock()

	// ── Phase 2: wait for the final ACK ──────────────────────────────────────

	ackDeadline := time.Now().Add(tcpListenHandshakeTimeout)
	for {
		if time.Now().After(ackDeadline) {
			handle.Close()
			return nil, fmt.Errorf("tcp_listen: timeout waiting for handshake ACK")
		}
		rawPkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err != nil {
			handle.Close()
			return nil, fmt.Errorf("tcp_listen: %w", err)
		}
		pkt, err := defragPacket(defragger, rawPkt)
		if err != nil || pkt == nil {
			continue
		}
		ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !ip4Pkt.SrcIP.To4().Equal(clientIP) {
			continue
		}
		tcpPkt, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || uint16(tcpPkt.SrcPort) != clientPort {
			continue
		}
		if tcpPkt.RST {
			handle.Close()
			return nil, fmt.Errorf("tcp_listen: connection reset")
		}
		if tcpPkt.ACK && !tcpPkt.SYN {
			break // handshake complete
		}
	}

	s.mu.Lock()
	s.state = tcpStateEstablished
	s.mu.Unlock()

	globalTCPSessions.add(s)
	go s.recvLoop()
	return s, nil
}
