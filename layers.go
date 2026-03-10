package main

import (
	"net"

	"github.com/google/gopacket/layers"
)

// EthParams holds overridable Ethernet layer fields.
// Zero/nil values mean "use the command default".
type EthParams struct {
	Src net.HardwareAddr
	Dst net.HardwareAddr
}

// IPv4Params holds overridable IPv4 layer fields.
// Zero values mean "use the command default".
type IPv4Params struct {
	Src        net.IP
	TTL        uint8
	TOS        uint8
	ID         uint16
	Flags      layers.IPv4Flag
	FragOffset uint16
}

// ICMPv4Params holds overridable ICMPv4 layer fields.
type ICMPv4Params struct {
	TypeCode layers.ICMPv4TypeCode
	ID       uint16
	Seq      uint16
	Data     []byte
	// explicit flags so zero-value ID/Seq/TypeCode are distinguishable from unset
	HasTypeCode bool
	HasID       bool
	HasSeq      bool
}

// ARPParams holds overridable ARP layer fields.
type ARPParams struct {
	Op     uint16
	SrcMAC net.HardwareAddr
	SrcIP  net.IP
	DstMAC net.HardwareAddr
	DstIP  net.IP
}

func buildEthLayer(p EthParams, defaultSrc, defaultDst net.HardwareAddr, etherType layers.EthernetType) layers.Ethernet {
	src := defaultSrc
	if p.Src != nil {
		src = p.Src
	}
	dst := defaultDst
	if p.Dst != nil {
		dst = p.Dst
	}
	return layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: etherType}
}

func buildARPLayer(p ARPParams, defaultSrcMAC net.HardwareAddr, defaultSrcIP, defaultDstIP net.IP) layers.ARP {
	op := uint16(layers.ARPRequest)
	if p.Op != 0 {
		op = p.Op
	}
	srcMAC := defaultSrcMAC
	if p.SrcMAC != nil {
		srcMAC = p.SrcMAC
	}
	srcIP := defaultSrcIP
	if p.SrcIP != nil {
		srcIP = p.SrcIP
	}
	dstMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if p.DstMAC != nil {
		dstMAC = p.DstMAC
	}
	dstIP := defaultDstIP
	if p.DstIP != nil {
		dstIP = p.DstIP
	}
	return layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
}

func buildIPv4Layer(p IPv4Params, defaultSrcIP, dstIP net.IP, proto layers.IPProtocol) layers.IPv4 {
	srcIP := defaultSrcIP
	if p.Src != nil {
		srcIP = p.Src
	}
	ttl := uint8(64)
	if p.TTL != 0 {
		ttl = p.TTL
	}
	return layers.IPv4{
		Version:    4,
		TTL:        ttl,
		TOS:        p.TOS,
		Id:         p.ID,
		Flags:      p.Flags,
		FragOffset: p.FragOffset,
		Protocol:   proto,
		SrcIP:      srcIP,
		DstIP:      dstIP.To4(),
	}
}

func buildICMPv4Layer(p ICMPv4Params) layers.ICMPv4 {
	typeCode := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	if p.HasTypeCode {
		typeCode = p.TypeCode
	}
	id := uint16(1)
	if p.HasID {
		id = p.ID
	}
	seq := uint16(1)
	if p.HasSeq {
		seq = p.Seq
	}
	return layers.ICMPv4{TypeCode: typeCode, Id: id, Seq: seq}
}

// TCPParams holds overridable TCP layer fields.
// Zero values mean "use the command default".
type TCPParams struct {
	Window uint16 // default: 65535
}

func buildTCPLayer(p TCPParams, srcPort, dstPort uint16, seq, ackNum uint32, syn, ack, psh, fin, rst bool) layers.TCP {
	window := uint16(65535)
	if p.Window != 0 {
		window = p.Window
	}
	return layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ackNum,
		SYN:        syn,
		ACK:        ack,
		PSH:        psh,
		FIN:        fin,
		RST:        rst,
		Window:     window,
		DataOffset: 5,
	}
}
