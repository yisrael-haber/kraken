package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── allocateDummyIPs ─────────────────────────────────────────────────────────

func TestAllocateDummyIPsRange(t *testing.T) {
	srv, cli := allocateDummyIPs()
	assert.Equal(t, byte(169), srv[0])
	assert.Equal(t, byte(254), srv[1])
	assert.Equal(t, byte(201), srv[2])
	assert.Equal(t, byte(169), cli[0])
	assert.Equal(t, byte(254), cli[1])
	assert.Equal(t, byte(202), cli[2])
}

func TestAllocateDummyIPsUnique(t *testing.T) {
	seen := make(map[string]bool)
	// Allocate 256 consecutive pairs — within one full byte cycle, no last-octet
	// should repeat within either the srv or cli range.
	for i := 0; i < 256; i++ {
		srv, cli := allocateDummyIPs()
		srvStr := srv.String()
		cliStr := cli.String()
		assert.NotEqual(t, srvStr, cliStr, "srv and cli dummy IPs must differ")
		assert.False(t, seen[srvStr], "srvDummy collision at iteration %d: %s", i, srvStr)
		assert.False(t, seen[cliStr], "cliDummy collision at iteration %d: %s", i, cliStr)
		seen[srvStr] = true
		seen[cliStr] = true
	}
}

// ── allocateQueueNum ─────────────────────────────────────────────────────────

func TestAllocateQueueNumRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		q := allocateQueueNum()
		assert.GreaterOrEqual(t, int(q), 100, "queue number below 100")
		assert.LessOrEqual(t, int(q), 65535, "queue number above uint16 max")
	}
}

// ── runBridge ────────────────────────────────────────────────────────────────

// pipePair returns (external, internal) net.Pipe ends. The test drives
// external; the bridge receives internal.
func pipePair(t *testing.T) (external, internal net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	return a, b
}

func TestRunBridgeMirror(t *testing.T) {
	clientExt, clientInt := pipePair(t)
	serverExt, serverInt := pipePair(t)
	defer clientExt.Close()
	defer serverExt.Close()

	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		runBridge(clientInt, serverInt, nil, nil)
	}()

	_, err := clientExt.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	n, err := serverExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	_, err = serverExt.Write([]byte("pong"))
	require.NoError(t, err)
	n, err = clientExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf[:n]))

	clientExt.Close()
	select {
	case <-bridgeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runBridge did not terminate after client closed")
	}
}

func TestRunBridgeClientToServerTransform(t *testing.T) {
	clientExt, clientInt := pipePair(t)
	serverExt, serverInt := pipePair(t)
	defer clientExt.Close()
	defer serverExt.Close()

	upperCase := func(b []byte) []byte { return bytes.ToUpper(b) }
	go runBridge(clientInt, serverInt, upperCase, nil)

	clientExt.Write([]byte("hello"))
	buf := make([]byte, 5)
	n, err := serverExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "HELLO", string(buf[:n]), "client→server transform not applied")

	serverExt.Write([]byte("world"))
	n, err = clientExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "world", string(buf[:n]), "server→client should be unmodified (nil transform)")
}

func TestRunBridgeServerToClientTransform(t *testing.T) {
	clientExt, clientInt := pipePair(t)
	serverExt, serverInt := pipePair(t)
	defer clientExt.Close()
	defer serverExt.Close()

	reverse := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i, v := range b {
			out[len(b)-1-i] = v
		}
		return out
	}
	go runBridge(clientInt, serverInt, nil, reverse)

	clientExt.Write([]byte("abc"))
	buf := make([]byte, 3)
	n, err := serverExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(buf[:n]), "client→server should be unmodified (nil transform)")

	serverExt.Write([]byte("abc"))
	n, err = clientExt.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "cba", string(buf[:n]), "server→client transform not applied")
}

func TestRunBridgeServerClosePropagates(t *testing.T) {
	clientExt, clientInt := pipePair(t)
	serverExt, serverInt := pipePair(t)
	defer clientExt.Close()
	defer serverExt.Close()

	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		runBridge(clientInt, serverInt, nil, nil)
	}()

	serverExt.Close()
	select {
	case <-bridgeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runBridge did not terminate after server closed")
	}
}

// ── applyPacketMod with IPDst / IPSrc (ingress + egress rewrite paths) ──────

// buildRawIPTCP returns a raw IPv4+TCP byte slice (no Ethernet header),
// matching what NFQUEUE delivers and what gVisor's injectInboundRaw expects.
func buildRawIPTCP(t *testing.T, src, dst net.IP, sport, dport layers.TCPPort) []byte {
	t.Helper()
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
	}
	tcp := &layers.TCP{SrcPort: sport, DstPort: dport, SYN: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip4, tcp))
	return buf.Bytes()
}

// buildRawIPTCPWithSeqAck returns a raw IPv4+TCP ACK packet with explicit
// seq and ack numbers. Used to complete the 3-way handshake in tests.
func buildRawIPTCPWithSeqAck(t *testing.T, src, dst net.IP, sport, dport layers.TCPPort, seq, ack uint32) []byte {
	t.Helper()
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
	}
	tcpLayer := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: seq, Ack: ack, ACK: true}
	require.NoError(t, tcpLayer.SetNetworkLayerForChecksum(ip4))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip4, tcpLayer))
	return buf.Bytes()
}

// parseIPv4 re-parses a raw IP byte slice and returns the IPv4 layer.
func parseIPv4(t *testing.T, raw []byte) *layers.IPv4 {
	t.Helper()
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok, "packet does not contain IPv4 layer")
	return ip4
}

func TestApplyPacketModIPDstRewrite(t *testing.T) {
	src := net.ParseIP("10.0.0.2").To4()
	origDst := net.ParseIP("10.0.0.1").To4()
	newDst := net.ParseIP("169.254.201.1").To4()

	raw := buildRawIPTCP(t, src, origDst, 54321, 80)
	rewritten := applyPacketMod(raw, packetMod{IPDst: newDst})

	// Destination IP at bytes [16:20] must be updated.
	assert.Equal(t, newDst, net.IP(rewritten[16:20]).To4())
	// Source IP must be unchanged.
	assert.Equal(t, src, net.IP(rewritten[12:16]).To4())

	// Re-parse: verify the packet is structurally valid and addresses are correct.
	ip4 := parseIPv4(t, rewritten)
	assert.Equal(t, newDst, ip4.DstIP.To4())
	assert.Equal(t, src, ip4.SrcIP.To4())
}

func TestApplyPacketModIPSrcRewrite(t *testing.T) {
	origSrc := net.ParseIP("169.254.201.1").To4()
	newSrc := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("10.0.0.2").To4()

	raw := buildRawIPTCP(t, origSrc, dst, 80, 54321)
	rewritten := applyPacketMod(raw, packetMod{IPSrc: newSrc})

	assert.Equal(t, newSrc, net.IP(rewritten[12:16]).To4())
	assert.Equal(t, dst, net.IP(rewritten[16:20]).To4())

	ip4 := parseIPv4(t, rewritten)
	assert.Equal(t, newSrc, ip4.SrcIP.To4())
	assert.Equal(t, dst, ip4.DstIP.To4())
}

// TestApplyPacketModIngressEgressPaths verifies both rewrite directions
// independently, mirroring the actual swap data flow:
//
//   Ingress (NFQUEUE handler): C→S packet, rewrite dst S → srvDummy
//   Egress  (runOutbound mod): gVisor-emitted reply, rewrite src srvDummy → S
//
// These operate on different packets — they are not composed on the same bytes.
func TestApplyPacketModIngressEgressPaths(t *testing.T) {
	client := net.ParseIP("192.168.1.10").To4()
	server := net.ParseIP("192.168.1.1").To4()
	srvDummy := net.ParseIP("169.254.201.1").To4()

	// Ingress: client sends SYN to server; NFQUEUE rewrites dst → srvDummy.
	ingressPkt := buildRawIPTCP(t, client, server, 54321, 80)
	afterIngress := applyPacketMod(ingressPkt, packetMod{IPDst: srvDummy})
	assert.Equal(t, client, net.IP(afterIngress[12:16]).To4(), "ingress: src must remain client")
	assert.Equal(t, srvDummy, net.IP(afterIngress[16:20]).To4(), "ingress: dst must be srvDummy")

	// Egress: gVisor (srvDummy) emits SYN-ACK back to client;
	// runOutbound mod rewrites src srvDummy → server.
	egressPkt := buildRawIPTCP(t, srvDummy, client, 80, 54321)
	afterEgress := applyPacketMod(egressPkt, packetMod{IPSrc: server})
	assert.Equal(t, server, net.IP(afterEgress[12:16]).To4(), "egress: src must be rewritten to server")
	assert.Equal(t, client, net.IP(afterEgress[16:20]).To4(), "egress: dst must remain client")

	// Both output packets must have parseable TCP layers.
	for _, raw := range [][]byte{afterIngress, afterEgress} {
		pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
		assert.NotNil(t, pkt.Layer(layers.LayerTypeTCP), "TCP layer missing after rewrite")
	}
}

// ── classifySwapPacket ────────────────────────────────────────────────────────

func TestClassifySwapPacketClientToServer(t *testing.T) {
	client := net.ParseIP("10.0.0.1").To4()
	server := net.ParseIP("10.0.0.2").To4()

	payload := buildRawIPTCP(t, client, server, 54321, 80)
	toServer, ok := classifySwapPacket(payload, client, server)

	assert.True(t, ok, "packet should match the 3-tuple")
	assert.True(t, toServer, "client→server packet should report toServer=true")
}

func TestClassifySwapPacketServerToClient(t *testing.T) {
	client := net.ParseIP("10.0.0.1").To4()
	server := net.ParseIP("10.0.0.2").To4()

	// Server sends back to client (e.g. SYN-ACK).
	payload := buildRawIPTCP(t, server, client, 80, 54321)
	toServer, ok := classifySwapPacket(payload, client, server)

	assert.True(t, ok, "packet should match the 3-tuple")
	assert.False(t, toServer, "server→client packet should report toServer=false")
}

func TestClassifySwapPacketUnrelated(t *testing.T) {
	client := net.ParseIP("10.0.0.1").To4()
	server := net.ParseIP("10.0.0.2").To4()
	other := net.ParseIP("10.0.0.99").To4()

	// Packet between unrelated hosts — should not match.
	payload := buildRawIPTCP(t, other, server, 1234, 80)
	_, ok := classifySwapPacket(payload, client, server)
	assert.False(t, ok, "unrelated src should not match")

	payload2 := buildRawIPTCP(t, client, other, 1234, 80)
	_, ok2 := classifySwapPacket(payload2, client, server)
	assert.False(t, ok2, "unrelated dst should not match")
}

func TestClassifySwapPacketTooShort(t *testing.T) {
	client := net.ParseIP("10.0.0.1").To4()
	server := net.ParseIP("10.0.0.2").To4()

	for _, size := range []int{0, 1, 19} {
		_, ok := classifySwapPacket(make([]byte, size), client, server)
		assert.False(t, ok, "payload of %d bytes should report ok=false", size)
	}
}
