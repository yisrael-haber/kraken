package packet

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type PacketSerializationOptions struct {
	FixLengths       bool
	ComputeChecksums bool
}

type OutboundPacket struct {
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	ARP      *layers.ARP
	ICMPv4   *layers.ICMPv4
	Payload  []byte

	serializationOptions    PacketSerializationOptions
	serializationConfigured bool
}

var (
	broadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroHardwareAddr      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

func BuildARPReplyPacket(adoptedIP net.IP, adoptedMAC net.HardwareAddr, requesterIP net.IP, requesterMAC net.HardwareAddr) *OutboundPacket {
	sourceIP := common.CloneIPv4(adoptedIP)
	sourceMAC := common.CloneHardwareAddr(adoptedMAC)
	targetIP := common.CloneIPv4(requesterIP)
	targetMAC := common.CloneHardwareAddr(requesterMAC)

	return &OutboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPReply),
			SourceHwAddress:   sourceMAC,
			SourceProtAddress: sourceIP,
			DstHwAddress:      targetMAC,
			DstProtAddress:    targetIP,
		},
	}
}

func BuildARPRequestPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) *OutboundPacket {
	clonedSourceIP := common.CloneIPv4(sourceIP)
	clonedSourceMAC := common.CloneHardwareAddr(sourceMAC)
	clonedTargetIP := common.CloneIPv4(targetIP)

	return &OutboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       clonedSourceMAC,
			DstMAC:       broadcastHardwareAddr,
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
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
	}
}

func BuildICMPEchoPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) *OutboundPacket {
	clonedSourceIP := common.CloneIPv4(sourceIP)
	clonedSourceMAC := common.CloneHardwareAddr(sourceMAC)
	clonedTargetIP := common.CloneIPv4(targetIP)
	clonedTargetMAC := common.CloneHardwareAddr(targetMAC)
	clonedPayload := append([]byte(nil), payload...)

	return &OutboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       clonedSourceMAC,
			DstMAC:       clonedTargetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		IPv4: &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    clonedSourceIP,
			DstIP:    clonedTargetIP,
		},
		ICMPv4: &layers.ICMPv4{
			TypeCode: typeCode,
			Id:       id,
			Seq:      sequence,
		},
		Payload: clonedPayload,
	}
}

func defaultPacketSerializationOptions() PacketSerializationOptions {
	return PacketSerializationOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
}

func (packet *OutboundPacket) SerializationOptions() PacketSerializationOptions {
	if packet == nil || !packet.serializationConfigured {
		return defaultPacketSerializationOptions()
	}

	return packet.serializationOptions
}

func (packet *OutboundPacket) SetSerializationOptions(options PacketSerializationOptions) {
	if packet == nil {
		return
	}

	packet.serializationOptions = options
	packet.serializationConfigured = true
}

func ParsePayloadHex(value string) ([]byte, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil, nil
	}

	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ':' || r == ';'
	})
	if len(tokens) > 1 {
		payload := make([]byte, 0, len(tokens))
		for _, token := range tokens {
			normalized := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(token), "0x"))
			if normalized == "" || len(normalized) > 2 {
				return nil, fmt.Errorf("invalid byte %q", token)
			}
			if len(normalized) == 1 {
				normalized = "0" + normalized
			}

			parsed, err := strconv.ParseUint(normalized, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid byte %q", token)
			}
			payload = append(payload, byte(parsed))
		}

		return payload, nil
	}

	normalized := strings.TrimPrefix(strings.ToLower(text), "0x")
	if len(normalized)%2 != 0 {
		return nil, fmt.Errorf("hex payload must contain an even number of digits")
	}

	payload, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid hex payload: %w", err)
	}

	return payload, nil
}

func FormatPayloadHex(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	parts := make([]string, len(payload))
	for index, value := range payload {
		parts[index] = fmt.Sprintf("%02X", value)
	}

	return strings.Join(parts, " ")
}

func (packet *OutboundPacket) SerializeValidatedInto(buffer gopacket.SerializeBuffer) error {
	if err := buffer.Clear(); err != nil {
		return err
	}

	packetOptions := packet.SerializationOptions()
	options := gopacket.SerializeOptions{
		FixLengths:       packetOptions.FixLengths,
		ComputeChecksums: packetOptions.ComputeChecksums,
	}

	var items [5]gopacket.SerializableLayer
	count := 0
	if packet.Ethernet != nil {
		items[count] = packet.Ethernet
		count++
	}
	if packet.ARP != nil {
		items[count] = packet.ARP
		count++
	} else {
		if packet.IPv4 != nil {
			items[count] = packet.IPv4
			count++
		}
		if packet.ICMPv4 != nil {
			items[count] = packet.ICMPv4
			count++
		}
		if len(packet.Payload) != 0 {
			items[count] = gopacket.Payload(packet.Payload)
			count++
		}
	}

	if err := gopacket.SerializeLayers(buffer, options, items[:count]...); err != nil {
		return err
	}

	return nil
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}

	return append([]byte(nil), value...)
}
