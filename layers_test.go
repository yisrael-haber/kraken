package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helpers

var (
	testMAC1 = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testMAC2 = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testMAC3 = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	testIP1  = net.ParseIP("10.0.0.1").To4()
	testIP2  = net.ParseIP("10.0.0.2").To4()
	testIP3  = net.ParseIP("192.168.1.1").To4()
)

// roundTripPacket serialises layers into bytes and parses them back.
func roundTripEth(t *testing.T, ls ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// ── buildEthLayer ─────────────────────────────────────────────────────────────

func TestBuildEthLayer_Defaults(t *testing.T) {
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	assert.Equal(t, testMAC1, net.HardwareAddr(eth.SrcMAC))
	assert.Equal(t, testMAC2, net.HardwareAddr(eth.DstMAC))
	assert.Equal(t, layers.EthernetTypeIPv4, eth.EthernetType)
}

func TestBuildEthLayer_OverrideSrc(t *testing.T) {
	p := EthParams{Src: testMAC3}
	eth := buildEthLayer(p, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	assert.Equal(t, testMAC3, net.HardwareAddr(eth.SrcMAC))
	assert.Equal(t, testMAC2, net.HardwareAddr(eth.DstMAC))
}

func TestBuildEthLayer_OverrideDst(t *testing.T) {
	p := EthParams{Dst: testMAC3}
	eth := buildEthLayer(p, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	assert.Equal(t, testMAC1, net.HardwareAddr(eth.SrcMAC))
	assert.Equal(t, testMAC3, net.HardwareAddr(eth.DstMAC))
}

func TestBuildEthLayer_OverrideBoth(t *testing.T) {
	p := EthParams{Src: testMAC3, Dst: testMAC3}
	eth := buildEthLayer(p, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	assert.Equal(t, testMAC3, net.HardwareAddr(eth.SrcMAC))
	assert.Equal(t, testMAC3, net.HardwareAddr(eth.DstMAC))
}

func TestBuildEthLayer_ARPType(t *testing.T) {
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeARP)
	assert.Equal(t, layers.EthernetTypeARP, eth.EthernetType)
}

// ── buildARPLayer ─────────────────────────────────────────────────────────────

func TestBuildARPLayer_Defaults(t *testing.T) {
	arp := buildARPLayer(ARPParams{}, testMAC1, testIP1, testIP2)
	assert.Equal(t, uint16(layers.ARPRequest), arp.Operation)
	assert.Equal(t, []byte(testMAC1), arp.SourceHwAddress)
	assert.Equal(t, []byte(testIP1), arp.SourceProtAddress)
	assert.Equal(t, []byte(testIP2), arp.DstProtAddress)
	// default dst MAC is all zeros
	assert.Equal(t, net.HardwareAddr{0, 0, 0, 0, 0, 0}, net.HardwareAddr(arp.DstHwAddress))
}

func TestBuildARPLayer_OverrideOperation(t *testing.T) {
	arp := buildARPLayer(ARPParams{Op: uint16(layers.ARPReply)}, testMAC1, testIP1, testIP2)
	assert.Equal(t, uint16(layers.ARPReply), arp.Operation)
}

func TestBuildARPLayer_OverrideSrcMAC(t *testing.T) {
	arp := buildARPLayer(ARPParams{SrcMAC: testMAC3}, testMAC1, testIP1, testIP2)
	assert.Equal(t, []byte(testMAC3), arp.SourceHwAddress)
}

func TestBuildARPLayer_OverrideSrcIP(t *testing.T) {
	arp := buildARPLayer(ARPParams{SrcIP: testIP3}, testMAC1, testIP1, testIP2)
	assert.Equal(t, []byte(testIP3), arp.SourceProtAddress)
}

func TestBuildARPLayer_OverrideDstMAC(t *testing.T) {
	arp := buildARPLayer(ARPParams{DstMAC: testMAC2}, testMAC1, testIP1, testIP2)
	assert.Equal(t, []byte(testMAC2), arp.DstHwAddress)
}

func TestBuildARPLayer_OverrideDstIP(t *testing.T) {
	arp := buildARPLayer(ARPParams{DstIP: testIP3}, testMAC1, testIP1, testIP2)
	assert.Equal(t, []byte(testIP3), arp.DstProtAddress)
}

func TestBuildARPLayer_FixedFields(t *testing.T) {
	arp := buildARPLayer(ARPParams{}, testMAC1, testIP1, testIP2)
	assert.Equal(t, layers.LinkTypeEthernet, arp.AddrType)
	assert.Equal(t, layers.EthernetTypeIPv4, arp.Protocol)
	assert.Equal(t, uint8(6), arp.HwAddressSize)
	assert.Equal(t, uint8(4), arp.ProtAddressSize)
}

func TestBuildARPLayer_SerializationRoundTrip(t *testing.T) {
	// Serialize the ARP layer to bytes and re-parse to catch any wire-format
	// regression (field ordering, endianness, incorrect sizes).
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeARP)
	arp := buildARPLayer(ARPParams{Op: uint16(layers.ARPReply), DstMAC: testMAC2}, testMAC1, testIP1, testIP2)

	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	arpParsed, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	require.True(t, ok, "ARP layer should survive serialization round-trip")

	assert.Equal(t, uint16(layers.ARPReply), arpParsed.Operation)
	assert.Equal(t, []byte(testMAC1), arpParsed.SourceHwAddress)
	assert.Equal(t, []byte(testIP1), arpParsed.SourceProtAddress)
	assert.Equal(t, []byte(testMAC2), arpParsed.DstHwAddress)
	assert.Equal(t, []byte(testIP2), arpParsed.DstProtAddress)
	assert.Equal(t, uint8(6), arpParsed.HwAddressSize)
	assert.Equal(t, uint8(4), arpParsed.ProtAddressSize)
}

// ── buildIPv4Layer ────────────────────────────────────────────────────────────

func TestBuildIPv4Layer_Defaults(t *testing.T) {
	ip4 := buildIPv4Layer(IPv4Params{}, testIP1, testIP2, layers.IPProtocolICMPv4)
	assert.Equal(t, uint8(4), ip4.Version)
	assert.Equal(t, uint8(64), ip4.TTL)   // default TTL
	assert.Equal(t, uint8(0), ip4.TOS)
	assert.Equal(t, layers.IPProtocolICMPv4, ip4.Protocol)
	assert.Equal(t, testIP1, net.IP(ip4.SrcIP))
	assert.Equal(t, testIP2, net.IP(ip4.DstIP))
}

func TestBuildIPv4Layer_OverrideSrcIP(t *testing.T) {
	ip4 := buildIPv4Layer(IPv4Params{Src: testIP3}, testIP1, testIP2, layers.IPProtocolICMPv4)
	assert.Equal(t, testIP3, net.IP(ip4.SrcIP))
}

func TestBuildIPv4Layer_OverrideTTL(t *testing.T) {
	ip4 := buildIPv4Layer(IPv4Params{TTL: 128}, testIP1, testIP2, layers.IPProtocolICMPv4)
	assert.Equal(t, uint8(128), ip4.TTL)
}

func TestBuildIPv4Layer_ZeroTTLUsesDefault(t *testing.T) {
	ip4 := buildIPv4Layer(IPv4Params{TTL: 0}, testIP1, testIP2, layers.IPProtocolICMPv4)
	assert.Equal(t, uint8(64), ip4.TTL)
}

func TestBuildIPv4Layer_TCPProtocol(t *testing.T) {
	ip4 := buildIPv4Layer(IPv4Params{}, testIP1, testIP2, layers.IPProtocolTCP)
	assert.Equal(t, layers.IPProtocolTCP, ip4.Protocol)
}

func TestBuildIPv4Layer_ChecksumRoundTrip(t *testing.T) {
	// Serialise + parse to verify the IPv4 layer survives the round-trip intact.
	ip4 := buildIPv4Layer(IPv4Params{}, testIP1, testIP2, layers.IPProtocolICMPv4)
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	icmp := buildICMPv4Layer(ICMPv4Params{})
	pkt := roundTripEth(t, &eth, &ip4, &icmp)
	ip4Parsed, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok)
	assert.True(t, net.IP(ip4Parsed.SrcIP).Equal(testIP1))
	assert.True(t, net.IP(ip4Parsed.DstIP).Equal(testIP2))
}

// ── buildICMPv4Layer ──────────────────────────────────────────────────────────

func TestBuildICMPv4Layer_Defaults(t *testing.T) {
	icmp := buildICMPv4Layer(ICMPv4Params{})
	// Default type is EchoRequest (gopacket constants are untyped int; cast to uint8).
	assert.Equal(t, uint8(layers.ICMPv4TypeEchoRequest), icmp.TypeCode.Type())
	assert.Equal(t, uint8(0), icmp.TypeCode.Code())
	assert.Equal(t, uint16(1), icmp.Id)
	assert.Equal(t, uint16(1), icmp.Seq)
}

func TestBuildICMPv4Layer_OverrideTypeCode(t *testing.T) {
	tc := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)
	icmp := buildICMPv4Layer(ICMPv4Params{TypeCode: tc, HasTypeCode: true})
	assert.Equal(t, uint8(layers.ICMPv4TypeEchoReply), icmp.TypeCode.Type())
}

func TestBuildICMPv4Layer_ZeroIDWithHasID(t *testing.T) {
	icmp := buildICMPv4Layer(ICMPv4Params{ID: 0, HasID: true})
	assert.Equal(t, uint16(0), icmp.Id)
}

func TestBuildICMPv4Layer_ZeroSeqWithHasSeq(t *testing.T) {
	icmp := buildICMPv4Layer(ICMPv4Params{Seq: 0, HasSeq: true})
	assert.Equal(t, uint16(0), icmp.Seq)
}

func TestBuildICMPv4Layer_OverrideIDAndSeq(t *testing.T) {
	icmp := buildICMPv4Layer(ICMPv4Params{ID: 42, Seq: 7, HasID: true, HasSeq: true})
	assert.Equal(t, uint16(42), icmp.Id)
	assert.Equal(t, uint16(7), icmp.Seq)
}

func TestBuildICMPv4Layer_ChecksumRoundTrip(t *testing.T) {
	// Serialise + parse to verify the ICMP layer survives the round-trip intact.
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	ip4 := buildIPv4Layer(IPv4Params{}, testIP1, testIP2, layers.IPProtocolICMPv4)
	icmp := buildICMPv4Layer(ICMPv4Params{ID: 3, Seq: 5, HasID: true, HasSeq: true})
	pkt := roundTripEth(t, &eth, &ip4, &icmp)
	icmpParsed, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	require.True(t, ok)
	assert.Equal(t, uint16(3), icmpParsed.Id)
	assert.Equal(t, uint16(5), icmpParsed.Seq)
}
