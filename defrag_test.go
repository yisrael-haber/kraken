package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildARPPacket creates a minimal ARP packet (non-IPv4) for passthrough tests.
func buildARPPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeARP)
	arp := buildARPLayer(ARPParams{}, testMAC1, testIP1, testIP2)
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildICMPPacket creates a normal (unfragmented) IPv4/ICMP packet.
func buildICMPPacket(t *testing.T, id, seq uint16) gopacket.Packet {
	t.Helper()
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeIPv4)
	ip4 := buildIPv4Layer(IPv4Params{}, testIP1, testIP2, layers.IPProtocolICMPv4)
	icmp := buildICMPv4Layer(ICMPv4Params{ID: id, Seq: seq, HasID: true, HasSeq: true})
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &ip4, &icmp))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildIPFragment creates a raw IPv4 fragment packet carrying arbitrary payload.
// fragOffset is in 8-byte units (matching the wire encoding).
func buildIPFragment(t *testing.T, id uint16, fragOffset uint16, moreFragments bool, payload []byte) gopacket.Packet {
	t.Helper()
	eth := buildEthLayer(EthParams{}, testMAC1, testMAC2, layers.EthernetTypeIPv4)

	flags := layers.IPv4Flag(0)
	if moreFragments {
		flags = layers.IPv4MoreFragments
	}
	ip4 := layers.IPv4{
		Version:    4,
		TTL:        64,
		Protocol:   layers.IPProtocolICMPv4,
		SrcIP:      testIP1,
		DstIP:      testIP2,
		Id:         id,
		Flags:      flags,
		FragOffset: fragOffset,
	}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&eth, &ip4, gopacket.Payload(payload),
	))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// ── Non-IPv4 passthrough ──────────────────────────────────────────────────────

func TestDefrag_NonIPv4PassesThrough(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()
	pkt := buildARPPacket(t)

	out, err := defragPacket(df, pkt)
	require.NoError(t, err)
	require.NotNil(t, out)

	// The returned packet must still contain an ARP layer.
	_, ok := out.Layer(layers.LayerTypeARP).(*layers.ARP)
	assert.True(t, ok)
}

// ── Unfragmented IPv4 passthrough ─────────────────────────────────────────────

func TestDefrag_UnfragmentedIPv4PassesThrough(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()
	pkt := buildICMPPacket(t, 10, 1)

	out, err := defragPacket(df, pkt)
	require.NoError(t, err)
	require.NotNil(t, out)

	icmp, ok := out.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	require.True(t, ok)
	assert.Equal(t, uint16(10), icmp.Id)
	assert.Equal(t, uint16(1), icmp.Seq)
}

// ── Fragment buffering ────────────────────────────────────────────────────────

func TestDefrag_FirstFragmentBuffered(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()
	// Fragment 1: offset 0, MoreFragments=true → should be buffered.
	frag1 := buildIPFragment(t, 0x1234, 0, true, make([]byte, 8))

	out, err := defragPacket(df, frag1)
	require.NoError(t, err)
	assert.Nil(t, out, "first fragment should be buffered, not returned")
}

// ── Fragment reassembly ───────────────────────────────────────────────────────

func TestDefrag_TwoFragmentsReassemble(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()

	const ipID = uint16(0xABCD)
	// Build 16 bytes of payload split into two 8-byte fragments.
	payload := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	frag1 := buildIPFragment(t, ipID, 0, true, payload[:8])
	frag2 := buildIPFragment(t, ipID, 1, false, payload[8:]) // offset 1 = 8 bytes

	// First fragment: buffered.
	out1, err := defragPacket(df, frag1)
	require.NoError(t, err)
	assert.Nil(t, out1)

	// Second fragment: reassembly completes.
	out2, err := defragPacket(df, frag2)
	require.NoError(t, err)
	require.NotNil(t, out2, "reassembly should complete after second fragment")

	// The reassembled packet must have an IPv4 layer with the correct addresses.
	ip4, ok := out2.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok)
	assert.True(t, net.IP(ip4.SrcIP).Equal(testIP1))
	assert.True(t, net.IP(ip4.DstIP).Equal(testIP2))

	// The reassembled payload must contain all 16 bytes.
	assert.Equal(t, payload, ip4.Payload)
}

func TestDefrag_ThreeFragmentsReassemble(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()

	const ipID = uint16(0x5555)
	payload := make([]byte, 24)
	for i := range payload {
		payload[i] = byte(i)
	}

	f1 := buildIPFragment(t, ipID, 0, true, payload[0:8])
	f2 := buildIPFragment(t, ipID, 1, true, payload[8:16])
	f3 := buildIPFragment(t, ipID, 2, false, payload[16:])

	out, err := defragPacket(df, f1)
	require.NoError(t, err)
	assert.Nil(t, out)

	out, err = defragPacket(df, f2)
	require.NoError(t, err)
	assert.Nil(t, out)

	out, err = defragPacket(df, f3)
	require.NoError(t, err)
	require.NotNil(t, out)

	ip4, ok := out.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok)
	assert.Equal(t, payload, ip4.Payload)
}

func TestDefrag_IndependentIDsDoNotMix(t *testing.T) {
	df := ip4defrag.NewIPv4Defragmenter()

	// Fragment from datagram A (never completed).
	fragA := buildIPFragment(t, 0xAAAA, 0, true, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	outA, err := defragPacket(df, fragA)
	require.NoError(t, err)
	assert.Nil(t, outA)

	// Separate complete two-fragment datagram B.
	payloadB := []byte{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
		0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF}
	f1B := buildIPFragment(t, 0xBBBB, 0, true, payloadB[:8])
	f2B := buildIPFragment(t, 0xBBBB, 1, false, payloadB[8:])

	outB1, err := defragPacket(df, f1B)
	require.NoError(t, err)
	assert.Nil(t, outB1)

	outB2, err := defragPacket(df, f2B)
	require.NoError(t, err)
	require.NotNil(t, outB2)

	ip4B, ok := outB2.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok)
	assert.Equal(t, payloadB, ip4B.Payload)
}
