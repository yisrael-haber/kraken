package script

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	broadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroHardwareAddr      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

func NewMutableARPRequestPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) (*MutablePacket, error) {
	sourceIP = sourceIP.To4()
	targetIP = targetIP.To4()

	return newMutablePacketFromLayers(0,
		&layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       broadcastHardwareAddr,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPRequest),
			SourceHwAddress:   sourceMAC,
			SourceProtAddress: sourceIP,
			DstHwAddress:      zeroHardwareAddr,
			DstProtAddress:    targetIP,
		},
	)
}

func NewMutableICMPEchoPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) (*MutablePacket, error) {
	sourceIP = sourceIP.To4()
	targetIP = targetIP.To4()
	clonedPayload := append([]byte(nil), payload...)

	return newMutablePacketFromLayers(len(clonedPayload),
		&layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    sourceIP,
			DstIP:    targetIP,
		},
		&layers.ICMPv4{
			TypeCode: typeCode,
			Id:       id,
			Seq:      sequence,
		},
		gopacket.Payload(clonedPayload),
	)
}

func newMutablePacketFromLayers(payloadSize int, items ...gopacket.SerializableLayer) (*MutablePacket, error) {
	buffer := gopacket.NewSerializeBufferExpectedSize(64, payloadSize)
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, items...); err != nil {
		return nil, err
	}
	return NewMutablePacket(append([]byte(nil), buffer.Bytes()...))
}
