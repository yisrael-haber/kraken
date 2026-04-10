package capture

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket/layers"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

type pooledICMPEchoPacket struct {
	packet    packetpkg.OutboundPacket
	ethernet  layers.Ethernet
	ipv4      layers.IPv4
	icmpv4    layers.ICMPv4
	sourceIP  [4]byte
	targetIP  [4]byte
	sourceMAC [6]byte
	targetMAC [6]byte
	payload   []byte
}

func newPooledICMPEchoPacket() *pooledICMPEchoPacket {
	return &pooledICMPEchoPacket{}
}

func (packet *pooledICMPEchoPacket) init(
	sourceIP net.IP,
	sourceMAC net.HardwareAddr,
	targetIP net.IP,
	targetMAC net.HardwareAddr,
	typeCode layers.ICMPv4TypeCode,
	id uint16,
	sequence uint16,
	payload []byte,
) *packetpkg.OutboundPacket {
	copyIPv4Bytes(&packet.sourceIP, sourceIP)
	copyIPv4Bytes(&packet.targetIP, targetIP)
	copyHardwareAddrBytes(&packet.sourceMAC, sourceMAC)
	copyHardwareAddrBytes(&packet.targetMAC, targetMAC)
	packet.payload = append(packet.payload[:0], payload...)

	packet.ethernet = layers.Ethernet{
		SrcMAC:       packet.sourceMAC[:],
		DstMAC:       packet.targetMAC[:],
		EthernetType: layers.EthernetTypeIPv4,
	}
	packet.ipv4 = layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    packet.sourceIP[:],
		DstIP:    packet.targetIP[:],
	}
	packet.icmpv4 = layers.ICMPv4{
		TypeCode: typeCode,
		Id:       id,
		Seq:      sequence,
	}

	packet.packet = packetpkg.OutboundPacket{
		Ethernet: &packet.ethernet,
		IPv4:     &packet.ipv4,
		ICMPv4:   &packet.icmpv4,
		Payload:  packet.payload,
		Trusted:  true,
	}

	return &packet.packet
}

func (packet *pooledICMPEchoPacket) reset() {
	packet.packet = packetpkg.OutboundPacket{}
	packet.payload = packet.payload[:0]
}

func copyIPv4Bytes(dst *[4]byte, src net.IP) {
	clear(dst[:])
	copy(dst[:], src.To4())
}

func copyHardwareAddrBytes(dst *[6]byte, src net.HardwareAddr) {
	clear(dst[:])
	copy(dst[:], src)
}

func (listener *pcapAdoptionListener) writeFastICMPEchoPacket(
	sourceIP net.IP,
	sourceMAC net.HardwareAddr,
	targetIP net.IP,
	targetMAC net.HardwareAddr,
	typeCode layers.ICMPv4TypeCode,
	id uint16,
	sequence uint16,
	payload []byte,
) error {
	frame := listener.takeICMPEchoFrame(len(payload))
	frame = marshalICMPEchoFrame(
		frame,
		sourceIP,
		sourceMAC,
		targetIP,
		targetMAC,
		typeCode,
		id,
		sequence,
		payload,
	)
	defer listener.releaseICMPEchoFrame(frame)

	return listener.writePacket(frame)
}

func (listener *pcapAdoptionListener) takeICMPEchoFrame(payloadLen int) []byte {
	size := 14 + 20 + 8 + payloadLen
	if frame, _ := listener.icmpFramePool.Get().([]byte); cap(frame) >= size {
		return frame[:size]
	}

	return make([]byte, size)
}

func (listener *pcapAdoptionListener) releaseICMPEchoFrame(frame []byte) {
	if frame == nil {
		return
	}

	listener.icmpFramePool.Put(frame[:0])
}

func marshalICMPEchoFrame(
	frame []byte,
	sourceIP net.IP,
	sourceMAC net.HardwareAddr,
	targetIP net.IP,
	targetMAC net.HardwareAddr,
	typeCode layers.ICMPv4TypeCode,
	id uint16,
	sequence uint16,
	payload []byte,
) []byte {
	frameLen := 14 + 20 + 8 + len(payload)
	if len(frame) < frameLen {
		frame = make([]byte, frameLen)
	} else {
		frame = frame[:frameLen]
	}

	copy(frame[0:6], targetMAC)
	copy(frame[6:12], sourceMAC)
	frame[12] = 0x08
	frame[13] = 0x00

	ipHeader := frame[14:34]
	clear(ipHeader)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(ipHeader)+8+len(payload)))
	ipHeader[8] = 64
	ipHeader[9] = 1
	copy(ipHeader[12:16], sourceIP.To4())
	copy(ipHeader[16:20], targetIP.To4())
	binary.BigEndian.PutUint16(ipHeader[10:12], internetChecksum(ipHeader))

	icmpMessage := frame[34:]
	clear(icmpMessage[:8])
	icmpMessage[0] = uint8(typeCode.Type())
	icmpMessage[1] = uint8(typeCode.Code())
	binary.BigEndian.PutUint16(icmpMessage[4:6], id)
	binary.BigEndian.PutUint16(icmpMessage[6:8], sequence)
	copy(icmpMessage[8:], payload)
	binary.BigEndian.PutUint16(icmpMessage[2:4], internetChecksum(icmpMessage))

	return frame
}

func internetChecksum(payload []byte) uint16 {
	var sum uint32
	length := len(payload)

	for index := 0; index+1 < length; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[index : index+2]))
	}
	if length%2 != 0 {
		sum += uint32(payload[length-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
