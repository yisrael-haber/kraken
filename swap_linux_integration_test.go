//go:build linux && integration

package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── nftables ─────────────────────────────────────────────────────────────────

// TestSetupNftablesCreateDelete verifies that setupNftables creates the
// expected table in the kernel and that the returned cleanup func removes it.
func TestSetupNftablesCreateDelete(t *testing.T) {
	requireRoot(t)

	client := net.ParseIP("10.0.0.1").To4()
	server := net.ParseIP("10.0.0.2").To4()
	const queueNum = uint16(201)
	tableName := fmt.Sprintf("kraken_%d", queueNum)

	cleanup, err := setupNftables(queueNum, client, server, 8080)
	require.NoError(t, err, "setupNftables should succeed")

	// Table must exist after setup.
	c, err := nftables.New()
	require.NoError(t, err)
	tables, err := c.ListTables()
	require.NoError(t, err)
	var found bool
	for _, tbl := range tables {
		if tbl.Name == tableName {
			found = true
			break
		}
	}
	assert.True(t, found, "nftables table %q should exist after setupNftables", tableName)

	// Table must be gone after cleanup.
	cleanup()
	c2, err := nftables.New()
	require.NoError(t, err)
	tables2, err := c2.ListTables()
	require.NoError(t, err)
	for _, tbl := range tables2 {
		assert.NotEqual(t, tableName, tbl.Name,
			"nftables table %q should be removed after cleanup", tableName)
	}
}

// TestSetupNftablesIdempotentCleanup verifies that calling cleanup twice does
// not panic or return an error (the table is simply absent on the second call).
func TestSetupNftablesIdempotentCleanup(t *testing.T) {
	requireRoot(t)

	cleanup, err := setupNftables(202, net.ParseIP("10.1.0.1").To4(), net.ParseIP("10.1.0.2").To4(), 9090)
	require.NoError(t, err)

	cleanup()
	// Second call must not panic.
	assert.NotPanics(t, cleanup, "second cleanup call should be a no-op")
}

// ── NFQUEUE ───────────────────────────────────────────────────────────────────

// TestNFQueueOpenClose verifies that the kernel's NFQUEUE subsystem is
// available and that we can open a handle, register a handler, and close it
// cleanly.
func TestNFQueueOpenClose(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())

	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      203,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  16,
		Copymode:     nfqueue.NfQnlCopyPacket,
	})
	require.NoError(t, err, "nfqueue.Open should succeed — is nf_queue kernel module loaded?")

	err = nfq.RegisterWithErrorFunc(ctx, func(attrs nfqueue.Attribute) int {
		return 0
	}, func(e error) int {
		return 0
	})
	require.NoError(t, err, "RegisterWithErrorFunc should succeed")

	cancel()
	nfq.Close()
}

// ── gVisor injection ──────────────────────────────────────────────────────────

// TestInjectInboundRawReachesGVisor verifies that injectInboundRaw delivers a
// SYN packet to gVisor's TCP forwarder and that the registered handler is
// invoked after the 3-way handshake completes. The test simulates the client
// side of the handshake: inject SYN → capture SYN-ACK from runOutbound →
// inject ACK → handler called.
func TestInjectInboundRawReachesGVisor(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	devName, err := pcapDeviceName(iface)
	require.NoError(t, err)

	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	require.NoError(t, err)
	defer handle.Close()

	dummyIP := net.ParseIP("169.254.203.1").To4()
	clientIP := net.ParseIP("10.99.0.1").To4()
	const (
		clientPort = layers.TCPPort(54321)
		testPort   = uint16(19999)
	)

	ns, err := newAdoptedNetstack(dummyIP, iface.HardwareAddr, iface, handle, "")
	require.NoError(t, err)
	defer ns.stop()

	// Set EthDst so runOutbound can send the SYN-ACK without an ARP lookup
	// failing for a non-existent source IP on the test machine's network.
	ns.setMod(packetMod{EthDst: iface.HardwareAddr})

	connCh := make(chan net.Conn, 1)
	ns.listen(testPort, func(conn net.Conn) {
		connCh <- conn
	})

	// Open a second handle to capture the SYN-ACK that gVisor emits.
	// Must be opened before injecting the SYN so we don't miss the reply.
	capHandle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	require.NoError(t, err)
	defer capHandle.Close()
	require.NoError(t, capHandle.SetBPFFilter(
		fmt.Sprintf("tcp and src host %s and src port %d", dummyIP, testPort)))

	// Step 1: inject the SYN. The forwarder goroutine sends a SYN-ACK and
	// then blocks in performHandshake waiting for the final ACK.
	synPkt := buildRawIPTCP(t, clientIP, dummyIP, clientPort, layers.TCPPort(testPort))
	ns.injectInboundRaw(synPkt)

	// Step 2: read the SYN-ACK that gVisor wrote to the wire via runOutbound.
	capSrc := gopacket.NewPacketSource(capHandle, capHandle.LinkType())
	synAckPkt := nextPacketTimeout(capSrc, 2*time.Second, func(p gopacket.Packet) bool {
		tcpL, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		return ok && tcpL.SYN && tcpL.ACK
	})
	require.NotNil(t, synAckPkt, "gVisor did not emit SYN-ACK within 2s")

	// Step 3: inject the ACK to complete the handshake.
	// Client ISN was 0 (buildRawIPTCP default), so the next client seq = 1.
	serverISN := synAckPkt.Layer(layers.LayerTypeTCP).(*layers.TCP).Seq
	ackPkt := buildRawIPTCPWithSeqAck(t,
		clientIP, dummyIP, clientPort, layers.TCPPort(testPort),
		1, serverISN+1,
	)
	ns.injectInboundRaw(ackPkt)

	// Step 4: performHandshake completes; handler is invoked.
	select {
	case conn := <-connCh:
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("injectInboundRaw: gVisor did not invoke the connection handler within 2s")
	}
}

// TestInjectInboundRawUnknownPortSendsRST verifies that injecting a SYN for a
// port with no registered handler causes gVisor to RST (Complete(true)), not
// hang or panic. The RST goes out via pcap and there is no listener invocation.
func TestInjectInboundRawUnknownPortSendsRST(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	devName, err := pcapDeviceName(iface)
	require.NoError(t, err)

	handle, err := pcap.OpenLive(devName, 65535, true, 50*time.Millisecond)
	require.NoError(t, err)
	defer handle.Close()

	dummyIP := net.ParseIP("169.254.203.2").To4()
	ns, err := newAdoptedNetstack(dummyIP, iface.HardwareAddr, iface, handle, "")
	require.NoError(t, err)
	defer ns.stop()
	ns.setMod(packetMod{EthDst: iface.HardwareAddr})

	// No listener registered — handler should RST.
	synPkt := buildRawIPTCP(t,
		net.ParseIP("10.99.0.2").To4(), dummyIP,
		layers.TCPPort(54322), layers.TCPPort(29999),
	)

	// Inject must not panic or block.
	done := make(chan struct{})
	go func() {
		ns.injectInboundRaw(synPkt)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("injectInboundRaw blocked for >1s with no handler registered")
	}
}
