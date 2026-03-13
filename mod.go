package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetMod holds per-adopted-IP outbound header overrides applied in
// runOutbound before each packet leaves the wire. Nil/zero fields are
// ignored — only explicitly set fields override the stack's values.
//
// L2 (Ethernet) fields are applied when building the Ethernet frame.
// A non-nil EthDst bypasses ARP lookup entirely.
//
// L3 (IPv4) and L4 (TCP) fields are applied to the raw IP bytes produced
// by gVisor; checksums are recomputed after any modification.
type packetMod struct {
	// L2
	EthSrc net.HardwareAddr
	EthDst net.HardwareAddr // non-nil skips ARP resolution

	// L3
	IPSrc net.IP
	IPDst net.IP
	TTL   *uint8
	TOS   *uint8

	// L4 TCP
	TCPSrcPort *uint16
	TCPDstPort *uint16
	Window     *uint16
}

func (m packetMod) hasL3() bool {
	return m.IPSrc != nil || m.IPDst != nil || m.TTL != nil || m.TOS != nil
}

func (m packetMod) hasL4() bool {
	return m.TCPSrcPort != nil || m.TCPDstPort != nil || m.Window != nil
}

// applyPacketMod applies L3 and L4 field overrides to a raw IPv4 packet
// and returns new bytes with recomputed IP and TCP checksums.
// If no L3/L4 fields are set the original slice is returned unchanged.
func applyPacketMod(ipBytes []byte, mod packetMod) []byte {
	if !mod.hasL3() && !mod.hasL4() {
		return ipBytes
	}

	pkt := gopacket.NewPacket(ipBytes, layers.LayerTypeIPv4, gopacket.Default)
	ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return ipBytes
	}

	if mod.IPSrc != nil {
		ip4.SrcIP = mod.IPSrc.To4()
	}
	if mod.IPDst != nil {
		ip4.DstIP = mod.IPDst.To4()
	}
	if mod.TTL != nil {
		ip4.TTL = *mod.TTL
	}
	if mod.TOS != nil {
		ip4.TOS = *mod.TOS
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	tcp, hasTCP := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if hasTCP {
		if mod.TCPSrcPort != nil {
			tcp.SrcPort = layers.TCPPort(*mod.TCPSrcPort)
		}
		if mod.TCPDstPort != nil {
			tcp.DstPort = layers.TCPPort(*mod.TCPDstPort)
		}
		if mod.Window != nil {
			tcp.Window = *mod.Window
		}
		tcp.SetNetworkLayerForChecksum(ip4)
		if err := gopacket.SerializeLayers(buf, opts, ip4, tcp, gopacket.Payload(tcp.Payload)); err != nil {
			return ipBytes
		}
	} else {
		if err := gopacket.SerializeLayers(buf, opts, ip4, gopacket.Payload(ip4.Payload)); err != nil {
			return ipBytes
		}
	}
	return buf.Bytes()
}
