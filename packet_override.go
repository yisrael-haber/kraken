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
	Name     string               `json:"name"`
	Layers   PacketOverrideLayers `json:"layers,omitempty"`
	compiled *compiledPacketOverride
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
	trusted  bool
}

type compiledPacketOverride struct {
	Ethernet *compiledPacketOverrideEthernet
	IPv4     *compiledPacketOverrideIPv4
	ARP      *compiledPacketOverrideARP
	ICMPv4   *compiledPacketOverrideICMPv4
}

type compiledPacketOverrideEthernet struct {
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
}

type compiledPacketOverrideIPv4 struct {
	SrcIP net.IP
	DstIP net.IP
	TTL   *uint8
	TOS   *uint8
	Id    *uint16
}

type compiledPacketOverrideARP struct {
	Operation         *uint16
	SourceHwAddress   net.HardwareAddr
	SourceProtAddress net.IP
	DstHwAddress      net.HardwareAddr
	DstProtAddress    net.IP
}

type compiledPacketOverrideICMPv4 struct {
	TypeCode *layers.ICMPv4TypeCode
	Id       *uint16
	Seq      *uint16
}

var (
	broadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroHardwareAddr      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

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

	compiled, err := compilePacketOverrideLayers(layersOverride)
	if err != nil {
		return StoredPacketOverride{}, err
	}

	return StoredPacketOverride{
		Name:     name,
		Layers:   layersOverride,
		compiled: compiled,
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

func compilePacketOverrideLayers(value PacketOverrideLayers) (*compiledPacketOverride, error) {
	compiled := &compiledPacketOverride{}

	if value.Ethernet != nil {
		layer := &compiledPacketOverrideEthernet{}
		if value.Ethernet.SrcMAC != "" {
			mac, err := net.ParseMAC(value.Ethernet.SrcMAC)
			if err != nil {
				return nil, err
			}
			layer.SrcMAC = mac
		}
		if value.Ethernet.DstMAC != "" {
			mac, err := net.ParseMAC(value.Ethernet.DstMAC)
			if err != nil {
				return nil, err
			}
			layer.DstMAC = mac
		}
		compiled.Ethernet = layer
	}

	if value.IPv4 != nil {
		layer := &compiledPacketOverrideIPv4{}
		if value.IPv4.SrcIP != "" {
			layer.SrcIP = normalizeIPv4(net.ParseIP(value.IPv4.SrcIP))
		}
		if value.IPv4.DstIP != "" {
			layer.DstIP = normalizeIPv4(net.ParseIP(value.IPv4.DstIP))
		}
		if value.IPv4.TTL != nil {
			layer.TTL = newUint8Override(*value.IPv4.TTL)
		}
		if value.IPv4.TOS != nil {
			layer.TOS = newUint8Override(*value.IPv4.TOS)
		}
		if value.IPv4.Id != nil {
			layer.Id = newUint16Override(*value.IPv4.Id)
		}
		compiled.IPv4 = layer
	}

	if value.ARP != nil {
		layer := &compiledPacketOverrideARP{}
		if value.ARP.Operation != nil {
			layer.Operation = newUint16Override(*value.ARP.Operation)
		}
		if value.ARP.SourceHwAddress != "" {
			mac, err := net.ParseMAC(value.ARP.SourceHwAddress)
			if err != nil {
				return nil, err
			}
			layer.SourceHwAddress = mac
		}
		if value.ARP.SourceProtAddress != "" {
			layer.SourceProtAddress = normalizeIPv4(net.ParseIP(value.ARP.SourceProtAddress))
		}
		if value.ARP.DstHwAddress != "" {
			mac, err := net.ParseMAC(value.ARP.DstHwAddress)
			if err != nil {
				return nil, err
			}
			layer.DstHwAddress = mac
		}
		if value.ARP.DstProtAddress != "" {
			layer.DstProtAddress = normalizeIPv4(net.ParseIP(value.ARP.DstProtAddress))
		}
		compiled.ARP = layer
	}

	if value.ICMPv4 != nil {
		layer := &compiledPacketOverrideICMPv4{}
		if value.ICMPv4.TypeCode != "" {
			typeCode, err := parseICMPv4TypeCode(value.ICMPv4.TypeCode)
			if err != nil {
				return nil, err
			}
			layer.TypeCode = &typeCode
		}
		if value.ICMPv4.Id != nil {
			layer.Id = newUint16Override(*value.ICMPv4.Id)
		}
		if value.ICMPv4.Seq != nil {
			layer.Seq = newUint16Override(*value.ICMPv4.Seq)
		}
		compiled.ICMPv4 = layer
	}

	return compiled, nil
}

func newUint8Override(value int) *uint8 {
	compiled := uint8(value)
	return &compiled
}

func newUint16Override(value int) *uint16 {
	compiled := uint16(value)
	return &compiled
}

func buildARPReplyPacket(adoptedIP net.IP, adoptedMAC net.HardwareAddr, requesterIP net.IP, requesterMAC net.HardwareAddr) *outboundPacket {
	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       adoptedMAC,
			DstMAC:       requesterMAC,
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         uint16(layers.ARPReply),
			SourceHwAddress:   adoptedMAC,
			SourceProtAddress: adoptedIP,
			DstHwAddress:      requesterMAC,
			DstProtAddress:    requesterIP,
		},
		trusted: true,
	}
}

func buildARPRequestPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP) *outboundPacket {
	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       broadcastHardwareAddr,
			EthernetType: layers.EthernetTypeARP,
		},
		ARP: &layers.ARP{
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
		trusted: true,
	}
}

func buildICMPEchoPacket(sourceIP net.IP, sourceMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr, typeCode layers.ICMPv4TypeCode, id, sequence uint16, payload []byte) *outboundPacket {
	return &outboundPacket{
		Ethernet: &layers.Ethernet{
			SrcMAC:       sourceMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		IPv4: &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    sourceIP,
			DstIP:    targetIP,
		},
		ICMPv4: &layers.ICMPv4{
			TypeCode: typeCode,
			Id:       id,
			Seq:      sequence,
		},
		Payload: payload,
		trusted: true,
	}
}

func (packet *outboundPacket) applyOverride(override StoredPacketOverride) error {
	if packet == nil {
		return nil
	}

	compiled := override.compiled
	if compiled == nil {
		var err error
		compiled, err = compilePacketOverrideLayers(override.Layers)
		if err != nil {
			return err
		}
	}

	if packet.Ethernet != nil && compiled.Ethernet != nil {
		if len(compiled.Ethernet.SrcMAC) != 0 {
			packet.Ethernet.SrcMAC = compiled.Ethernet.SrcMAC
		}
		if len(compiled.Ethernet.DstMAC) != 0 {
			packet.Ethernet.DstMAC = compiled.Ethernet.DstMAC
		}
	}

	if packet.IPv4 != nil && compiled.IPv4 != nil {
		if len(compiled.IPv4.SrcIP) != 0 {
			packet.IPv4.SrcIP = compiled.IPv4.SrcIP
		}
		if len(compiled.IPv4.DstIP) != 0 {
			packet.IPv4.DstIP = compiled.IPv4.DstIP
		}
		if compiled.IPv4.TTL != nil {
			packet.IPv4.TTL = *compiled.IPv4.TTL
		}
		if compiled.IPv4.TOS != nil {
			packet.IPv4.TOS = *compiled.IPv4.TOS
		}
		if compiled.IPv4.Id != nil {
			packet.IPv4.Id = *compiled.IPv4.Id
		}
	}

	if packet.ARP != nil && compiled.ARP != nil {
		if compiled.ARP.Operation != nil {
			packet.ARP.Operation = *compiled.ARP.Operation
		}
		if len(compiled.ARP.SourceHwAddress) != 0 {
			packet.ARP.SourceHwAddress = compiled.ARP.SourceHwAddress
		}
		if len(compiled.ARP.SourceProtAddress) != 0 {
			packet.ARP.SourceProtAddress = compiled.ARP.SourceProtAddress
		}
		if len(compiled.ARP.DstHwAddress) != 0 {
			packet.ARP.DstHwAddress = compiled.ARP.DstHwAddress
		}
		if len(compiled.ARP.DstProtAddress) != 0 {
			packet.ARP.DstProtAddress = compiled.ARP.DstProtAddress
		}
	}

	if packet.ICMPv4 != nil && compiled.ICMPv4 != nil {
		if compiled.ICMPv4.TypeCode != nil {
			packet.ICMPv4.TypeCode = *compiled.ICMPv4.TypeCode
		}
		if compiled.ICMPv4.Id != nil {
			packet.ICMPv4.Id = *compiled.ICMPv4.Id
		}
		if compiled.ICMPv4.Seq != nil {
			packet.ICMPv4.Seq = *compiled.ICMPv4.Seq
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

	buffer := gopacket.NewSerializeBufferExpectedSize(64, len(packet.Payload))
	if err := packet.serializeValidatedInto(buffer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (packet *outboundPacket) serializeValidatedInto(buffer gopacket.SerializeBuffer) error {
	if err := buffer.Clear(); err != nil {
		return err
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
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
