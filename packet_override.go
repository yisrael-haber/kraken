package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const storedPacketOverrideFolder = "stored_packet_overrides"

type StoredPacketOverride struct {
	Name   string               `json:"name"`
	Layers PacketOverrideLayers `json:"layers,omitempty"`
}

type PacketOverrideLayers struct {
	Ethernet *PacketOverrideEthernet `json:"Ethernet,omitempty"`
	IPv4     *PacketOverrideIPv4     `json:"IPv4,omitempty"`
	ARP      *PacketOverrideARP      `json:"ARP,omitempty"`
	ICMPv4   *PacketOverrideICMPv4   `json:"ICMPv4,omitempty"`
}

type PacketOverrideEthernet struct {
	SrcMAC string `json:"SrcMAC,omitempty"`
	DstMAC string `json:"DstMAC,omitempty"`
}

type PacketOverrideIPv4 struct {
	SrcIP string `json:"SrcIP,omitempty"`
	DstIP string `json:"DstIP,omitempty"`
	TTL   *int   `json:"TTL,omitempty"`
	TOS   *int   `json:"TOS,omitempty"`
	Id    *int   `json:"Id,omitempty"`
}

type PacketOverrideARP struct {
	Operation         *int   `json:"Operation,omitempty"`
	SourceHwAddress   string `json:"SourceHwAddress,omitempty"`
	SourceProtAddress string `json:"SourceProtAddress,omitempty"`
	DstHwAddress      string `json:"DstHwAddress,omitempty"`
	DstProtAddress    string `json:"DstProtAddress,omitempty"`
}

type PacketOverrideICMPv4 struct {
	TypeCode string `json:"TypeCode,omitempty"`
	Id       *int   `json:"Id,omitempty"`
	Seq      *int   `json:"Seq,omitempty"`
}

type outboundPacket struct {
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	ARP      *layers.ARP
	ICMPv4   *layers.ICMPv4
	Payload  []byte
}

func normalizeStoredPacketOverride(override StoredPacketOverride) (StoredPacketOverride, error) {
	name, err := normalizeAdoptionLabel(override.Name)
	if err != nil {
		return StoredPacketOverride{}, err
	}

	layersOverride, err := normalizePacketOverrideLayers(override.Layers)
	if err != nil {
		return StoredPacketOverride{}, err
	}
	if layersOverride.Ethernet == nil &&
		layersOverride.IPv4 == nil &&
		layersOverride.ARP == nil &&
		layersOverride.ICMPv4 == nil {
		return StoredPacketOverride{}, fmt.Errorf("at least one layer override is required")
	}

	return StoredPacketOverride{
		Name:   name,
		Layers: layersOverride,
	}, nil
}

func normalizePacketOverrideLayers(value PacketOverrideLayers) (PacketOverrideLayers, error) {
	normalized := PacketOverrideLayers{}

	if value.Ethernet != nil {
		layer, err := normalizePacketOverrideEthernet(*value.Ethernet)
		if err != nil {
			return PacketOverrideLayers{}, err
		}
		normalized.Ethernet = layer
	}

	if value.IPv4 != nil {
		layer, err := normalizePacketOverrideIPv4(*value.IPv4)
		if err != nil {
			return PacketOverrideLayers{}, err
		}
		normalized.IPv4 = layer
	}

	if value.ARP != nil {
		layer, err := normalizePacketOverrideARP(*value.ARP)
		if err != nil {
			return PacketOverrideLayers{}, err
		}
		normalized.ARP = layer
	}

	if value.ICMPv4 != nil {
		layer, err := normalizePacketOverrideICMPv4(*value.ICMPv4)
		if err != nil {
			return PacketOverrideLayers{}, err
		}
		normalized.ICMPv4 = layer
	}

	return normalized, nil
}

func normalizePacketOverrideEthernet(value PacketOverrideEthernet) (*PacketOverrideEthernet, error) {
	layer := PacketOverrideEthernet{
		SrcMAC: strings.TrimSpace(value.SrcMAC),
		DstMAC: strings.TrimSpace(value.DstMAC),
	}

	if layer.SrcMAC != "" {
		if _, err := net.ParseMAC(layer.SrcMAC); err != nil {
			return nil, fmt.Errorf("Ethernet.SrcMAC: %w", err)
		}
	}
	if layer.DstMAC != "" {
		if _, err := net.ParseMAC(layer.DstMAC); err != nil {
			return nil, fmt.Errorf("Ethernet.DstMAC: %w", err)
		}
	}

	if layer.SrcMAC == "" && layer.DstMAC == "" {
		return nil, nil
	}

	return &layer, nil
}

func normalizePacketOverrideIPv4(value PacketOverrideIPv4) (*PacketOverrideIPv4, error) {
	layer := PacketOverrideIPv4{
		SrcIP: strings.TrimSpace(value.SrcIP),
		DstIP: strings.TrimSpace(value.DstIP),
		TTL:   cloneOptionalInt(value.TTL),
		TOS:   cloneOptionalInt(value.TOS),
		Id:    cloneOptionalInt(value.Id),
	}

	if layer.SrcIP != "" {
		ip, err := normalizeAdoptionIP(layer.SrcIP)
		if err != nil {
			return nil, fmt.Errorf("IPv4.SrcIP: %w", err)
		}
		layer.SrcIP = ip.String()
	}
	if layer.DstIP != "" {
		ip, err := normalizeAdoptionIP(layer.DstIP)
		if err != nil {
			return nil, fmt.Errorf("IPv4.DstIP: %w", err)
		}
		layer.DstIP = ip.String()
	}
	if layer.TTL != nil {
		if err := validateOptionalIntRange(*layer.TTL, 0, 255, "IPv4.TTL"); err != nil {
			return nil, err
		}
	}
	if layer.TOS != nil {
		if err := validateOptionalIntRange(*layer.TOS, 0, 255, "IPv4.TOS"); err != nil {
			return nil, err
		}
	}
	if layer.Id != nil {
		if err := validateOptionalIntRange(*layer.Id, 0, 65535, "IPv4.Id"); err != nil {
			return nil, err
		}
	}

	if layer.SrcIP == "" && layer.DstIP == "" && layer.TTL == nil && layer.TOS == nil && layer.Id == nil {
		return nil, nil
	}

	return &layer, nil
}

func normalizePacketOverrideARP(value PacketOverrideARP) (*PacketOverrideARP, error) {
	layer := PacketOverrideARP{
		Operation:         cloneOptionalInt(value.Operation),
		SourceHwAddress:   strings.TrimSpace(value.SourceHwAddress),
		SourceProtAddress: strings.TrimSpace(value.SourceProtAddress),
		DstHwAddress:      strings.TrimSpace(value.DstHwAddress),
		DstProtAddress:    strings.TrimSpace(value.DstProtAddress),
	}

	if layer.Operation != nil {
		if err := validateOptionalIntRange(*layer.Operation, 0, 65535, "ARP.Operation"); err != nil {
			return nil, err
		}
	}
	if layer.SourceHwAddress != "" {
		if _, err := net.ParseMAC(layer.SourceHwAddress); err != nil {
			return nil, fmt.Errorf("ARP.SourceHwAddress: %w", err)
		}
	}
	if layer.SourceProtAddress != "" {
		ip, err := normalizeAdoptionIP(layer.SourceProtAddress)
		if err != nil {
			return nil, fmt.Errorf("ARP.SourceProtAddress: %w", err)
		}
		layer.SourceProtAddress = ip.String()
	}
	if layer.DstHwAddress != "" {
		if _, err := net.ParseMAC(layer.DstHwAddress); err != nil {
			return nil, fmt.Errorf("ARP.DstHwAddress: %w", err)
		}
	}
	if layer.DstProtAddress != "" {
		ip, err := normalizeAdoptionIP(layer.DstProtAddress)
		if err != nil {
			return nil, fmt.Errorf("ARP.DstProtAddress: %w", err)
		}
		layer.DstProtAddress = ip.String()
	}

	if layer.Operation == nil &&
		layer.SourceHwAddress == "" &&
		layer.SourceProtAddress == "" &&
		layer.DstHwAddress == "" &&
		layer.DstProtAddress == "" {
		return nil, nil
	}

	return &layer, nil
}

func normalizePacketOverrideICMPv4(value PacketOverrideICMPv4) (*PacketOverrideICMPv4, error) {
	layer := PacketOverrideICMPv4{
		TypeCode: strings.TrimSpace(value.TypeCode),
		Id:       cloneOptionalInt(value.Id),
		Seq:      cloneOptionalInt(value.Seq),
	}

	if layer.TypeCode != "" {
		if _, err := parseICMPv4TypeCode(layer.TypeCode); err != nil {
			return nil, fmt.Errorf("ICMPv4.TypeCode: %w", err)
		}
	}
	if layer.Id != nil {
		if err := validateOptionalIntRange(*layer.Id, 0, 65535, "ICMPv4.Id"); err != nil {
			return nil, err
		}
	}
	if layer.Seq != nil {
		if err := validateOptionalIntRange(*layer.Seq, 0, 65535, "ICMPv4.Seq"); err != nil {
			return nil, err
		}
	}

	if layer.TypeCode == "" && layer.Id == nil && layer.Seq == nil {
		return nil, nil
	}

	return &layer, nil
}

func cloneOptionalInt(value *int) *int {
	if value == nil {
		return nil
	}

	cloned := *value
	return &cloned
}

func validateOptionalIntRange(value, min, max int, field string) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d", field, min, max)
	}

	return nil
}

func parseICMPv4TypeCode(value string) (layers.ICMPv4TypeCode, error) {
	switch strings.TrimSpace(value) {
	case "EchoRequest":
		return layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), nil
	case "EchoReply":
		return layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0), nil
	default:
		return layers.ICMPv4TypeCode(0), fmt.Errorf("unsupported type code %q", value)
	}
}

func buildARPReplyPacket(adoptedIP net.IP, adoptedMAC net.HardwareAddr, requesterIP net.IP, requesterMAC net.HardwareAddr) *outboundPacket {
	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       cloneHardwareAddr(adoptedMAC),
			DstMAC:       cloneHardwareAddr(requesterMAC),
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPReply),
			SourceHwAddress:   cloneHardwareAddr(adoptedMAC),
			SourceProtAddress: cloneIPv4(adoptedIP),
			DstHwAddress:      cloneHardwareAddr(requesterMAC),
			DstProtAddress:    cloneIPv4(requesterIP),
		},
	}
}

func buildARPRequestPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) *outboundPacket {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       cloneHardwareAddr(sourceMAC),
			DstMAC:       cloneHardwareAddr(broadcastMAC),
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPRequest),
			SourceHwAddress:   cloneHardwareAddr(sourceMAC),
			SourceProtAddress: cloneIPv4(sourceIP),
			DstHwAddress:      make([]byte, 6),
			DstProtAddress:    cloneIPv4(targetIP),
		},
	}
}

func buildICMPEchoPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) *outboundPacket {
	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       cloneHardwareAddr(sourceMAC),
			DstMAC:       cloneHardwareAddr(targetMAC),
			EthernetType: layers.EthernetTypeIPv4,
		},
		IPv4: &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    cloneIPv4(sourceIP),
			DstIP:    cloneIPv4(targetIP),
		},
		ICMPv4: &layers.ICMPv4{
			TypeCode: typeCode,
			Id:       id,
			Seq:      sequence,
		},
		Payload: append([]byte(nil), payload...),
	}
}

func (packet *outboundPacket) applyOverride(override StoredPacketOverride) error {
	if packet == nil {
		return nil
	}

	if packet.Ethernet != nil && override.Layers.Ethernet != nil {
		if override.Layers.Ethernet.SrcMAC != "" {
			mac, err := net.ParseMAC(override.Layers.Ethernet.SrcMAC)
			if err != nil {
				return err
			}
			packet.Ethernet.SrcMAC = cloneHardwareAddr(mac)
		}
		if override.Layers.Ethernet.DstMAC != "" {
			mac, err := net.ParseMAC(override.Layers.Ethernet.DstMAC)
			if err != nil {
				return err
			}
			packet.Ethernet.DstMAC = cloneHardwareAddr(mac)
		}
	}

	if packet.IPv4 != nil && override.Layers.IPv4 != nil {
		if override.Layers.IPv4.SrcIP != "" {
			packet.IPv4.SrcIP = cloneIPv4(net.ParseIP(override.Layers.IPv4.SrcIP))
		}
		if override.Layers.IPv4.DstIP != "" {
			packet.IPv4.DstIP = cloneIPv4(net.ParseIP(override.Layers.IPv4.DstIP))
		}
		if override.Layers.IPv4.TTL != nil {
			packet.IPv4.TTL = uint8(*override.Layers.IPv4.TTL)
		}
		if override.Layers.IPv4.TOS != nil {
			packet.IPv4.TOS = uint8(*override.Layers.IPv4.TOS)
		}
		if override.Layers.IPv4.Id != nil {
			packet.IPv4.Id = uint16(*override.Layers.IPv4.Id)
		}
	}

	if packet.ARP != nil && override.Layers.ARP != nil {
		if override.Layers.ARP.Operation != nil {
			packet.ARP.Operation = uint16(*override.Layers.ARP.Operation)
		}
		if override.Layers.ARP.SourceHwAddress != "" {
			mac, err := net.ParseMAC(override.Layers.ARP.SourceHwAddress)
			if err != nil {
				return err
			}
			packet.ARP.SourceHwAddress = cloneHardwareAddr(mac)
		}
		if override.Layers.ARP.SourceProtAddress != "" {
			packet.ARP.SourceProtAddress = cloneIPv4(net.ParseIP(override.Layers.ARP.SourceProtAddress))
		}
		if override.Layers.ARP.DstHwAddress != "" {
			mac, err := net.ParseMAC(override.Layers.ARP.DstHwAddress)
			if err != nil {
				return err
			}
			packet.ARP.DstHwAddress = cloneHardwareAddr(mac)
		}
		if override.Layers.ARP.DstProtAddress != "" {
			packet.ARP.DstProtAddress = cloneIPv4(net.ParseIP(override.Layers.ARP.DstProtAddress))
		}
	}

	if packet.ICMPv4 != nil && override.Layers.ICMPv4 != nil {
		if override.Layers.ICMPv4.TypeCode != "" {
			typeCode, err := parseICMPv4TypeCode(override.Layers.ICMPv4.TypeCode)
			if err != nil {
				return err
			}
			packet.ICMPv4.TypeCode = typeCode
		}
		if override.Layers.ICMPv4.Id != nil {
			packet.ICMPv4.Id = uint16(*override.Layers.ICMPv4.Id)
		}
		if override.Layers.ICMPv4.Seq != nil {
			packet.ICMPv4.Seq = uint16(*override.Layers.ICMPv4.Seq)
		}
	}

	return nil
}

func (packet *outboundPacket) validate() error {
	if packet == nil {
		return nil
	}

	if packet.Ethernet != nil {
		if len(packet.Ethernet.SrcMAC) == 0 {
			return fmt.Errorf("Ethernet.SrcMAC is required")
		}
		if len(packet.Ethernet.DstMAC) == 0 {
			return fmt.Errorf("Ethernet.DstMAC is required")
		}
	}

	if packet.IPv4 != nil {
		if normalizeIPv4(packet.IPv4.SrcIP) == nil {
			return fmt.Errorf("IPv4.SrcIP is required")
		}
		if normalizeIPv4(packet.IPv4.DstIP) == nil {
			return fmt.Errorf("IPv4.DstIP is required")
		}
	}

	if packet.ARP != nil {
		if len(packet.ARP.SourceHwAddress) != 6 {
			return fmt.Errorf("ARP.SourceHwAddress must be 6 bytes")
		}
		if len(packet.ARP.SourceProtAddress) != 4 {
			return fmt.Errorf("ARP.SourceProtAddress must be 4 bytes")
		}
		if len(packet.ARP.DstHwAddress) != 6 {
			return fmt.Errorf("ARP.DstHwAddress must be 6 bytes")
		}
		if len(packet.ARP.DstProtAddress) != 4 {
			return fmt.Errorf("ARP.DstProtAddress must be 4 bytes")
		}
	}

	return nil
}

func (packet *outboundPacket) serialize() ([]byte, error) {
	if err := packet.validate(); err != nil {
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	items := make([]gopacket.SerializableLayer, 0, 5)
	if packet.Ethernet != nil {
		items = append(items, packet.Ethernet)
	}
	if packet.ARP != nil {
		items = append(items, packet.ARP)
	} else {
		if packet.IPv4 != nil {
			items = append(items, packet.IPv4)
		}
		if packet.ICMPv4 != nil {
			items = append(items, packet.ICMPv4)
		}
		if len(packet.Payload) != 0 {
			items = append(items, gopacket.Payload(append([]byte(nil), packet.Payload...)))
		}
	}

	if err := gopacket.SerializeLayers(buffer, options, items...); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
