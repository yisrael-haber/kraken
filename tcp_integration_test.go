//go:build integration

package main

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── rawTCPServer ──────────────────────────────────────────────────────────────
//
// rawTCPServer is a minimal, single-connection TCP server built on top of
// gopacket.  It lives on an adopted IP so the kernel never sees the 4-tuple
// and never sends a spurious RST toward our moto client.
//
// The server implements a simple echo: it ACKs every received byte and sends
// the same payload back.

const (
	serverPort = uint16(9001)
	serverIPStr = "169.254.99.10"
)

var serverMAC = net.HardwareAddr{0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01}

type rawTCPServer struct {
	handle  *pcap.Handle
	iface   net.Interface
	serverIP net.IP
	serverMAC net.HardwareAddr

	// filled in once SYN arrives
	clientIP   net.IP
	clientMAC  net.HardwareAddr
	clientPort uint16

	serverISN uint32
	clientISN uint32 // from SYN

	seqOut uint32 // next byte we will send
	ackIn  uint32 // next byte we expect from client

	errCh  chan error
	doneCh chan struct{}
}

func newRawTCPServer(t *testing.T, iface net.Interface) *rawTCPServer {
	t.Helper()
	serverIP := net.ParseIP(serverIPStr).To4()

	// Adopt the server IP so the kernel doesn't route traffic there.
	adoptIP(t, serverIP, serverMAC, iface)

	devName, err := pcapDeviceName(iface)
	require.NoError(t, err)

	bpf := fmt.Sprintf("tcp dst port %d", serverPort)
	h, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, h.SetBPFFilter(bpf))

	srv := &rawTCPServer{
		handle:    h,
		iface:     iface,
		serverIP:  serverIP,
		serverMAC: serverMAC,
		serverISN: 0x12340000,
		errCh:     make(chan error, 1),
		doneCh:    make(chan struct{}),
	}
	t.Cleanup(h.Close)
	return srv
}

// sendTCP sends a TCP segment from the server to the client.
func (s *rawTCPServer) sendTCP(syn, ack, psh, fin bool, payload []byte) error {
	eth := layers.Ethernet{
		SrcMAC:       s.serverMAC,
		DstMAC:       s.clientMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    s.serverIP,
		DstIP:    s.clientIP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(serverPort),
		DstPort: layers.TCPPort(s.clientPort),
		Seq:     s.seqOut,
		Ack:     s.ackIn,
		SYN:     syn,
		ACK:     ack,
		PSH:     psh,
		FIN:     fin,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(&ip4); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip4, &tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	return s.handle.WritePacketData(buf.Bytes())
}

// run is the server's main loop.  It blocks until the connection is fully
// closed or an error occurs.
func (s *rawTCPServer) run() {
	defer close(s.doneCh)

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	established := false

	for {
		pkt, err := src.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err != nil {
			s.errCh <- err
			return
		}

		tcpPkt, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}
		ip4Pkt, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		ethPkt, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !ok {
			continue
		}

		// Ignore RST (the kernel may send one for unrelated reasons).
		if tcpPkt.RST {
			continue
		}

		if !established {
			// Expect SYN.
			if !tcpPkt.SYN || tcpPkt.ACK {
				continue
			}
			s.clientIP = net.IP(ip4Pkt.SrcIP).To4()
			s.clientMAC = net.HardwareAddr(ethPkt.SrcMAC)
			s.clientPort = uint16(tcpPkt.SrcPort)
			s.clientISN = tcpPkt.Seq

			s.seqOut = s.serverISN
			s.ackIn = s.clientISN + 1 // SYN consumes one seq

			// SYN-ACK
			if err := s.sendTCP(true, true, false, false, nil); err != nil {
				s.errCh <- err
				return
			}
			s.seqOut++ // SYN-ACK consumes one seq
			established = true
			continue
		}

		// ESTABLISHED: handle data, FIN.
		if len(tcpPkt.Payload) > 0 {
			s.ackIn += uint32(len(tcpPkt.Payload))
			// Echo the data back.
			if err := s.sendTCP(false, true, true, false, tcpPkt.Payload); err != nil {
				s.errCh <- err
				return
			}
			s.seqOut += uint32(len(tcpPkt.Payload))
		}

		if tcpPkt.FIN {
			s.ackIn++ // FIN consumes one seq
			// Send FIN-ACK.
			if err := s.sendTCP(false, true, false, true, nil); err != nil {
				s.errCh <- err
				return
			}
			s.seqOut++
			return // connection done
		}
	}
}

func (s *rawTCPServer) start() {
	go s.run()
}

func (s *rawTCPServer) waitDone(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.doneCh:
		// check for server-side errors
		select {
		case err := <-s.errCh:
			t.Errorf("raw TCP server error: %v", err)
		default:
		}
	case <-time.After(timeout):
		t.Error("raw TCP server did not finish within timeout")
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestTCPConnect_HandshakeAndClose verifies that doTCPConnect successfully
// completes the three-way handshake with our raw TCP server and that tcpClose
// sends FIN and waits for the server's FIN-ACK.
func TestTCPConnect_HandshakeAndClose(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	ifaceIP, err := ifaceIPv4(iface)
	require.NoError(t, err)
	_ = ifaceIP // used implicitly by doTCPConnect

	srv := newRawTCPServer(t, iface)
	srv.start()

	serverIP := srv.serverIP
	sess, err := doTCPConnect(iface, serverIP, serverPort, 0, TCPParams{})
	require.NoError(t, err, "doTCPConnect")
	t.Cleanup(func() { globalTCPSessions.remove(sess.id) })

	sess.mu.Lock()
	state := sess.state
	sess.mu.Unlock()
	assert.Equal(t, tcpStateEstablished, state)

	require.NoError(t, tcpClose(sess))

	sess.mu.Lock()
	finalState := sess.state
	sess.mu.Unlock()
	assert.Equal(t, tcpStateClosed, finalState)

	srv.waitDone(t, 5*time.Second)
}

// TestTCPConnect_SendAndRecv verifies that data sent through the moto TCP
// session is echoed back correctly by the raw server.
func TestTCPConnect_SendAndRecv(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)

	srv := newRawTCPServer(t, iface)
	srv.start()

	sess, err := doTCPConnect(iface, srv.serverIP, serverPort, 0, TCPParams{})
	require.NoError(t, err)
	t.Cleanup(func() {
		tcpClose(sess)
		globalTCPSessions.remove(sess.id)
	})

	const msg = "hello moto"
	require.NoError(t, tcpSend(sess, []byte(msg)))

	data, err := tcpRecv(sess, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, []byte(msg), data)
}

// TestTCPConnect_MultipleMessages verifies that several sequential send/recv
// round-trips all succeed.
func TestTCPConnect_MultipleMessages(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)

	srv := newRawTCPServer(t, iface)
	srv.start()

	sess, err := doTCPConnect(iface, srv.serverIP, serverPort, 0, TCPParams{})
	require.NoError(t, err)
	t.Cleanup(func() {
		tcpClose(sess)
		globalTCPSessions.remove(sess.id)
	})

	messages := []string{"ping", "pong", "foo", "bar baz qux"}
	for _, msg := range messages {
		require.NoError(t, tcpSend(sess, []byte(msg)), "send %q", msg)
		data, err := tcpRecv(sess, 3*time.Second)
		require.NoError(t, err, "recv for %q", msg)
		assert.Equal(t, []byte(msg), data, "echo mismatch for %q", msg)
	}
}

// TestTCPConnect_SessionAppearsInTable verifies that after connecting, the
// session appears in the global session table.
func TestTCPConnect_SessionAppearsInTable(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)

	srv := newRawTCPServer(t, iface)
	srv.start()

	sess, err := doTCPConnect(iface, srv.serverIP, serverPort, 0, TCPParams{})
	require.NoError(t, err)

	got, ok := globalTCPSessions.get(sess.id)
	assert.True(t, ok, "session should be in global table after connect")
	assert.Equal(t, sess, got)

	tcpClose(sess)
	_, ok = globalTCPSessions.get(sess.id)
	assert.False(t, ok, "session should be removed after close")
}

// TestTCPConnect_RecvTimeout verifies that tcpRecv returns a timeout error when
// the server sends nothing.
func TestTCPConnect_RecvTimeout(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)

	srv := newRawTCPServer(t, iface)
	srv.start()

	sess, err := doTCPConnect(iface, srv.serverIP, serverPort, 0, TCPParams{})
	require.NoError(t, err)
	t.Cleanup(func() {
		tcpClose(sess)
		globalTCPSessions.remove(sess.id)
	})

	// Don't send anything — just wait for the recv to time out.
	_, err = tcpRecv(sess, 300*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}
