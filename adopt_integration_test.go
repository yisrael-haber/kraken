//go:build integration

package main

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ARP adoption ──────────────────────────────────────────────────────────────

// TestAdoptARPReply verifies that after adopting an IP address, the adoption
// listener responds to ARP who-has requests with the configured MAC.
func TestAdoptARPReply(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	ifaceIP, err := ifaceIPv4(iface)
	require.NoError(t, err)

	adoptedIP := net.ParseIP(testAdoptedIPStr).To4()
	adoptIP(t, adoptedIP, adoptedMAC, iface)

	// Open a capture handle filtered to ARP replies about our adopted IP.
	replyHandle := openCapture(t, iface, "arp")
	replySrc := gopacket.NewPacketSource(replyHandle, replyHandle.LinkType())

	// Open a separate handle to send the ARP request.
	reqHandle := openCapture(t, iface, "arp")

	// Build and send an ARP who-has request for adoptedIP.
	ethLayer := buildEthLayer(EthParams{},
		iface.HardwareAddr,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		layers.EthernetTypeARP)
	arpLayer := buildARPLayer(ARPParams{},
		iface.HardwareAddr, ifaceIP, adoptedIP)
	sendPacket(t, reqHandle, &ethLayer, &arpLayer)

	// Wait up to 3 s for an ARP reply from adoptedMAC.
	pkt := nextPacketTimeout(replySrc, 3*time.Second, func(p gopacket.Packet) bool {
		arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !ok || arp.Operation != uint16(layers.ARPReply) {
			return false
		}
		return net.IP(arp.SourceProtAddress).Equal(adoptedIP)
	})

	require.NotNil(t, pkt, "did not receive ARP reply for adopted IP within timeout")

	arp := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	assert.Equal(t, []byte(adoptedMAC), arp.SourceHwAddress,
		"ARP reply MAC should match the adopted MAC")
	assert.Equal(t, []byte(adoptedIP.To4()), arp.SourceProtAddress)
}

// TestAdoptARPReply_StopsAfterUnadopt verifies that after removing the adoption
// no further ARP replies are emitted.
func TestAdoptARPReply_StopsAfterUnadopt(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	ifaceIP, err := ifaceIPv4(iface)
	require.NoError(t, err)

	adoptedIP := net.ParseIP(testAdoptedIPStr2).To4()

	// Adopt, then immediately unadopt (cleanup will also call remove, but that
	// is idempotent).
	require.NoError(t, globalAdoptions.add(adoptedIP, adoptedMAC2, iface))
	time.Sleep(50 * time.Millisecond)
	globalAdoptions.remove(adoptedIP)
	time.Sleep(100 * time.Millisecond) // let listener goroutine exit

	replyHandle := openCapture(t, iface, "arp")
	replySrc := gopacket.NewPacketSource(replyHandle, replyHandle.LinkType())

	reqHandle := openCapture(t, iface, "arp")
	ethLayer := buildEthLayer(EthParams{},
		iface.HardwareAddr,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		layers.EthernetTypeARP)
	arpLayer := buildARPLayer(ARPParams{},
		iface.HardwareAddr, ifaceIP, adoptedIP)
	sendPacket(t, reqHandle, &ethLayer, &arpLayer)

	pkt := nextPacketTimeout(replySrc, 500*time.Millisecond, func(p gopacket.Packet) bool {
		arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !ok || arp.Operation != uint16(layers.ARPReply) {
			return false
		}
		return net.IP(arp.SourceProtAddress).Equal(adoptedIP)
	})
	assert.Nil(t, pkt, "should not receive ARP reply after unadopt")
}

// ── ICMP adoption ─────────────────────────────────────────────────────────────

// TestAdoptICMPReply verifies that after adopting an IP the listener responds
// to ICMP echo requests with a properly formed echo reply.
func TestAdoptICMPReply(t *testing.T) {
	requireRoot(t)

	iface := firstEthernetIface(t)
	ifaceIP, err := ifaceIPv4(iface)
	require.NoError(t, err)

	adoptedIP := net.ParseIP(testAdoptedIPStr).To4()
	adoptIP(t, adoptedIP, adoptedMAC, iface)

	// Pre-populate the ARP cache so the adoption listener already knows our MAC.
	// (The listener replies to ICMP only; we seed the echo request with the
	// correct dst MAC directly so no ARP resolution is needed here.)

	// Capture ICMP traffic.
	capHandle := openCapture(t, iface, "icmp")
	capSrc := gopacket.NewPacketSource(capHandle, capHandle.LinkType())

	// Send ICMP echo request from our interface IP to the adopted IP.
	const (
		testID  = uint16(0xF00D)
		testSeq = uint16(0x0001)
	)
	reqBytes := buildEchoRequest(t,
		iface.HardwareAddr, adoptedMAC, // dst MAC = adoptedMAC (direct delivery)
		ifaceIP, adoptedIP,
		testID, testSeq,
	)

	sendHandle := openCapture(t, iface, "icmp")
	require.NoError(t, sendHandle.WritePacketData(reqBytes))

	// Wait for echo reply from adoptedIP.
	pkt := nextPacketTimeout(capSrc, 3*time.Second, func(p gopacket.Packet) bool {
		ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !net.IP(ip4.SrcIP).Equal(adoptedIP) {
			return false
		}
		icmp, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		return ok && icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply
	})

	require.NotNil(t, pkt, "did not receive ICMP echo reply from adopted IP")

	icmp := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	assert.Equal(t, uint8(layers.ICMPv4TypeEchoReply), icmp.TypeCode.Type())
	assert.Equal(t, testID, icmp.Id, "echo reply ID should match request ID")
	assert.Equal(t, testSeq, icmp.Seq, "echo reply Seq should match request Seq")

	// Ethernet source should be the adopted MAC.
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	assert.Equal(t, []byte(adoptedMAC), []byte(eth.SrcMAC))
}
