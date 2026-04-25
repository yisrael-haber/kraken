package script

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

var (
	broadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroHardwareAddr      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

func NewMutableARPRequestPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) (*MutablePacket, error) {
	clonedSourceIP := common.CloneIPv4(sourceIP)
	clonedSourceMAC := common.CloneHardwareAddr(sourceMAC)
	clonedTargetIP := common.CloneIPv4(targetIP)

	return newMutablePacketFromLayers(0,
		&layers.Ethernet{
			SrcMAC:       clonedSourceMAC,
			DstMAC:       broadcastHardwareAddr,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPRequest),
			SourceHwAddress:   clonedSourceMAC,
			SourceProtAddress: clonedSourceIP,
			DstHwAddress:      zeroHardwareAddr,
			DstProtAddress:    clonedTargetIP,
		},
	)
}

func NewMutableICMPEchoPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) (*MutablePacket, error) {
	clonedSourceIP := common.CloneIPv4(sourceIP)
	clonedSourceMAC := common.CloneHardwareAddr(sourceMAC)
	clonedTargetIP := common.CloneIPv4(targetIP)
	clonedTargetMAC := common.CloneHardwareAddr(targetMAC)
	clonedPayload := append([]byte(nil), payload...)

	return newMutablePacketFromLayers(len(clonedPayload),
		&layers.Ethernet{
			SrcMAC:       clonedSourceMAC,
			DstMAC:       clonedTargetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    clonedSourceIP,
			DstIP:    clonedTargetIP,
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
