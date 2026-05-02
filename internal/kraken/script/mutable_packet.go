package script

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type MutablePacket struct {
	data []byte

	decoded []gopacket.LayerType

	ethernet layers.Ethernet
	arp      layers.ARP
	ipv4     layers.IPv4
	icmpv4   layers.ICMPv4
	tcp      layers.TCP
	udp      layers.UDP
	payload  []byte

	dirty            bool
	fixLengths       bool
	computeChecksums bool

	dropped bool
}

type mutableLayerValue struct {
	packet *MutablePacket
	name   string
}

func NewMutablePacket(frame []byte) (*MutablePacket, error) {
	packet, err := decodePacketLayers(frame)
	if err != nil {
		return nil, err
	}
	if end := packet.payloadEnd(); end > 0 && end < len(frame) {
		packet, err = decodePacketLayers(frame[:end])
		if err != nil {
			return nil, err
		}
	}
	return packet, nil
}

func decodePacketLayers(frame []byte) (*MutablePacket, error) {
	packet := &MutablePacket{
		data:             frame,
		fixLengths:       true,
		computeChecksums: true,
	}
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&packet.ethernet,
		&packet.arp,
		&packet.ipv4,
		&packet.tcp,
		&packet.udp,
		&packet.icmpv4,
		(*gopacket.Payload)(&packet.payload),
	)
	parser.IgnorePanic = true
	parser.IgnoreUnsupported = true
	if err := parser.DecodeLayers(frame, &packet.decoded); err != nil {
		return nil, err
	}
	if len(packet.decoded) == 0 {
		return nil, fmt.Errorf("unsupported packet layout")
	}
	return packet, nil
}

func (packet *MutablePacket) Bytes() []byte {
	return packet.data
}

func (packet *MutablePacket) Drop() {
	packet.dropped = true
}

func (packet *MutablePacket) Dropped() bool {
	return packet.dropped
}

func (packet *MutablePacket) Release() {}

func (packet *MutablePacket) HasApplicationFlow() bool {
	return packet.hasLayer(layers.LayerTypeTCP) || packet.hasLayer(layers.LayerTypeUDP)
}

func (packet *MutablePacket) setPayloadBytes(payload []byte) error {
	packet.payload = append(packet.payload[:0], payload...)
	packet.dirty = true
	return nil
}

func (packet *MutablePacket) payloadEnd() int {
	if start := packet.layerStart(layers.LayerTypeARP); start >= 0 {
		return start + len(packet.arp.Contents)
	}
	if start := packet.layerStart(layers.LayerTypeIPv4); start >= 0 {
		return start + int(packet.ipv4.Length)
	}
	return len(packet.data)
}

func (packet *MutablePacket) finalize() error {
	if !packet.dirty {
		return nil
	}
	if packet.hasLayer(layers.LayerTypeIPv4) {
		if packet.hasLayer(layers.LayerTypeTCP) {
			if err := packet.tcp.SetNetworkLayerForChecksum(&packet.ipv4); err != nil {
				return err
			}
		}
		if packet.hasLayer(layers.LayerTypeUDP) {
			if err := packet.udp.SetNetworkLayerForChecksum(&packet.ipv4); err != nil {
				return err
			}
		}
	}

	buffer := gopacket.NewSerializeBufferExpectedSize(len(packet.data), len(packet.payload))
	items := make([]gopacket.SerializableLayer, 0, len(packet.decoded)+1)
	for _, layerType := range packet.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			items = append(items, &packet.ethernet)
		case layers.LayerTypeARP:
			items = append(items, &packet.arp)
		case layers.LayerTypeIPv4:
			items = append(items, &packet.ipv4)
		case layers.LayerTypeICMPv4:
			items = append(items, &packet.icmpv4)
		case layers.LayerTypeTCP:
			items = append(items, &packet.tcp)
		case layers.LayerTypeUDP:
			items = append(items, &packet.udp)
		}
	}
	if packet.payload != nil {
		items = append(items, gopacket.Payload(packet.payload))
	}
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       packet.fixLengths,
		ComputeChecksums: packet.computeChecksums,
	}, items...); err != nil {
		return err
	}

	packet.data = append(packet.data[:0], buffer.Bytes()...)
	packet.dirty = false
	return nil
}

func (packet *MutablePacket) hasLayer(layerType gopacket.LayerType) bool {
	return slices.Contains(packet.decoded, layerType)
}

func (packet *MutablePacket) layerStart(layerType gopacket.LayerType) int {
	offset := 0
	for _, decoded := range packet.decoded {
		if decoded == layerType {
			return offset
		}
		switch decoded {
		case layers.LayerTypeEthernet:
			offset += len(packet.ethernet.Contents)
		case layers.LayerTypeARP:
			offset += len(packet.arp.Contents)
		case layers.LayerTypeIPv4:
			offset += len(packet.ipv4.Contents)
		case layers.LayerTypeICMPv4:
			offset += len(packet.icmpv4.Contents)
		case layers.LayerTypeTCP:
			offset += len(packet.tcp.Contents)
		case layers.LayerTypeUDP:
			offset += len(packet.udp.Contents)
		}
	}
	return -1
}

func (packet *MutablePacket) layerNames() []string {
	names := make([]string, 0, len(packet.decoded))
	for _, layerType := range packet.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			names = append(names, "ethernet")
		case layers.LayerTypeARP:
			names = append(names, "arp")
		case layers.LayerTypeIPv4:
			names = append(names, "ipv4")
		case layers.LayerTypeICMPv4:
			names = append(names, "icmpv4")
		case layers.LayerTypeTCP:
			names = append(names, "tcp")
		case layers.LayerTypeUDP:
			names = append(names, "udp")
		}
	}
	return names
}

func (packet *MutablePacket) FragmentIPv4ByPayload(maxPayloadSize int) ([]*MutablePacket, error) {
	if maxPayloadSize <= 0 {
		return nil, fmt.Errorf("fragment size must be greater than zero")
	}
	if err := packet.finalize(); err != nil {
		return nil, err
	}
	if !packet.hasLayer(layers.LayerTypeIPv4) {
		return nil, fmt.Errorf("fragmentation requires an IPv4 packet")
	}

	if packet.ipv4.FragOffset != 0 || packet.ipv4.Flags&layers.IPv4MoreFragments != 0 {
		return nil, fmt.Errorf("packet is already fragmented")
	}

	prefixLen := packet.layerStart(layers.LayerTypeIPv4)
	headerLen := len(packet.ipv4.Contents)
	payloadStart := prefixLen + headerLen
	payloadEnd := packet.payloadEnd()
	if payloadEnd < payloadStart {
		payloadEnd = payloadStart
	}
	if payloadEnd > len(packet.data) {
		payloadEnd = len(packet.data)
	}

	ipPayload := packet.data[payloadStart:payloadEnd]
	if len(ipPayload) == 0 {
		cloned, err := NewMutablePacket(append([]byte(nil), packet.data...))
		if err != nil {
			return nil, err
		}
		cloned.fixLengths = packet.fixLengths
		cloned.computeChecksums = packet.computeChecksums
		return []*MutablePacket{cloned}, nil
	}

	chunkSize := maxPayloadSize
	if len(ipPayload) > maxPayloadSize {
		chunkSize &= ^7
		if chunkSize == 0 {
			return nil, fmt.Errorf("fragment size must be at least 8 bytes when multiple fragments are required")
		}
	}

	prefix := packet.data[:prefixLen]
	headerTemplate := packet.data[prefixLen:payloadStart]
	fragments := make([]*MutablePacket, 0, (len(ipPayload)+chunkSize-1)/chunkSize)

	for offset := 0; offset < len(ipPayload); {
		size := len(ipPayload) - offset
		if size > maxPayloadSize {
			size = chunkSize
		}

		moreFragments := offset+size < len(ipPayload)
		frame := make([]byte, len(prefix)+len(headerTemplate)+size)
		copy(frame, prefix)
		copy(frame[prefixLen:], headerTemplate)
		copy(frame[prefixLen+headerLen:], ipPayload[offset:offset+size])

		fragmentHeader := header.IPv4(frame[prefixLen : prefixLen+headerLen])
		binary.BigEndian.PutUint16(fragmentHeader[2:4], uint16(headerLen+size))

		flags := uint16(packet.ipv4.Flags) &^ uint16(layers.IPv4MoreFragments)
		if moreFragments {
			flags |= uint16(layers.IPv4MoreFragments)
		}
		binary.BigEndian.PutUint16(fragmentHeader[6:8], uint16(flags<<13)|uint16(offset/8))
		fragmentHeader.SetChecksum(0)
		fragmentHeader.SetChecksum(^fragmentHeader.CalculateChecksum())

		fragment, err := NewMutablePacket(frame)
		if err != nil {
			for _, item := range fragments {
				item.Release()
			}
			return nil, err
		}
		fragment.fixLengths = packet.fixLengths
		fragment.computeChecksums = packet.computeChecksums
		fragments = append(fragments, fragment)
		offset += size
	}

	return fragments, nil
}

func (packet *MutablePacket) setTCPOptions(options []layers.TCPOption) error {
	packet.tcp.Options = options
	packet.dirty = true
	return nil
}

func (packet *MutablePacket) String() string       { return "<packet>" }
func (packet *MutablePacket) Type() string         { return "packet" }
func (packet *MutablePacket) Freeze()              {}
func (packet *MutablePacket) Truth() starlark.Bool { return true }
func (packet *MutablePacket) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", packet.Type())
}

func (packet *MutablePacket) Attr(name string) (starlark.Value, error) {
	switch name {
	case "fixLengths":
		return starlark.Bool(packet.fixLengths), nil
	case "computeChecksums":
		return starlark.Bool(packet.computeChecksums), nil
	case "ethernet":
		if !packet.hasLayer(layers.LayerTypeEthernet) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "ethernet"}, nil
	case "arp":
		if !packet.hasLayer(layers.LayerTypeARP) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "arp"}, nil
	case "ipv4":
		if !packet.hasLayer(layers.LayerTypeIPv4) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "ipv4"}, nil
	case "icmpv4":
		if !packet.hasLayer(layers.LayerTypeICMPv4) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "icmpv4"}, nil
	case "tcp":
		if !packet.hasLayer(layers.LayerTypeTCP) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "tcp"}, nil
	case "udp":
		if !packet.hasLayer(layers.LayerTypeUDP) {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "udp"}, nil
	case "payload":
		return &byteBuffer{
			data:  packet.payload,
			owned: true,
			onSet: func() { packet.dirty = true },
		}, nil
	case "layers":
		names := packet.layerNames()
		items := make([]starlark.Value, 0, len(names))
		for _, name := range names {
			items = append(items, starlark.String(name))
		}
		return starlark.NewList(items), nil
	case "layer":
		return starlark.NewBuiltin("packet.layer", packet.layerByName), nil
	case "drop":
		return starlark.NewBuiltin("packet.drop", packet.dropBuiltin), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("packet has no .%s attribute", name))
	}
}

func (packet *MutablePacket) AttrNames() []string {
	return []string{"ethernet", "arp", "ipv4", "icmpv4", "tcp", "udp", "payload", "fixLengths", "computeChecksums", "layers", "layer", "drop"}
}

func (packet *MutablePacket) SetField(name string, fieldValue starlark.Value) error {
	switch name {
	case "payload":
		payload, err := parseOptionalBytes(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.payload: %w", err)
		}
		return packet.setPayloadBytes(payload)
	case "fixLengths", "computeChecksums":
		boolean, err := parseOptionalBool(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.%s: %w", name, err)
		}
		if boolean == nil {
			return fmt.Errorf("packet.%s: value is required", name)
		}
		if name == "fixLengths" {
			packet.fixLengths = *boolean
		} else {
			packet.computeChecksums = *boolean
		}
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("packet has no writable .%s attribute", name))
	}
}

func (packet *MutablePacket) layerByName(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	layerValue, err := packet.Attr(strings.TrimSpace(name))
	if err != nil {
		if isNoSuchAttr(err) {
			return starlark.None, nil
		}
		return nil, err
	}
	if layerValue == nil {
		return starlark.None, nil
	}
	return layerValue, nil
}

func (packet *MutablePacket) dropBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs("packet.drop", args, kwargs, 0); err != nil {
		return nil, err
	}
	packet.Drop()
	return starlark.None, nil
}

func (value *mutableLayerValue) String() string       { return fmt.Sprintf("<packet.%s>", value.name) }
func (value *mutableLayerValue) Type() string         { return "packet." + value.name }
func (value *mutableLayerValue) Freeze()              {}
func (value *mutableLayerValue) Truth() starlark.Bool { return true }
func (value *mutableLayerValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func (value *mutableLayerValue) Attr(name string) (starlark.Value, error) {
	switch value.name {
	case "ethernet":
		return value.ethernetAttr(name)
	case "arp":
		return value.arpAttr(name)
	case "ipv4":
		return value.ipv4Attr(name)
	case "icmpv4":
		return value.icmpv4Attr(name)
	case "tcp":
		return value.tcpAttr(name)
	case "udp":
		return value.udpAttr(name)
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) AttrNames() []string {
	switch value.name {
	case "ethernet":
		return []string{"srcMAC", "dstMAC", "ethernetType", "length"}
	case "arp":
		return []string{"addrType", "protocol", "hwAddressSize", "protAddressSize", "operation", "sourceHwAddress", "sourceProtAddress", "dstHwAddress", "dstProtAddress"}
	case "ipv4":
		return []string{"srcIP", "dstIP", "version", "ihl", "tos", "length", "id", "flags", "fragOffset", "ttl", "protocol", "checksum", "options", "padding"}
	case "icmpv4":
		return []string{"typeCode", "type", "code", "checksum", "id", "seq"}
	case "tcp":
		return []string{"srcPort", "dstPort", "seq", "ack", "dataOffset", "flags", "window", "checksum", "urgentPointer", "options"}
	case "udp":
		return []string{"srcPort", "dstPort", "length", "checksum"}
	default:
		return nil
	}
}

func (value *mutableLayerValue) SetField(name string, fieldValue starlark.Value) error {
	switch value.name {
	case "ethernet":
		return value.setEthernetField(name, fieldValue)
	case "arp":
		return value.setARPField(name, fieldValue)
	case "ipv4":
		return value.setIPv4Field(name, fieldValue)
	case "icmpv4":
		return value.setICMPv4Field(name, fieldValue)
	case "tcp":
		return value.setTCPField(name, fieldValue)
	case "udp":
		return value.setUDPField(name, fieldValue)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) ethernetAttr(name string) (starlark.Value, error) {
	ethernet := value.packet.ethernet
	switch name {
	case "srcMAC":
		return starlark.String(ethernet.SrcMAC.String()), nil
	case "dstMAC":
		return starlark.String(ethernet.DstMAC.String()), nil
	case "ethernetType":
		return starlark.MakeUint64(uint64(ethernet.EthernetType)), nil
	case "length":
		return starlark.MakeUint64(uint64(ethernet.Length)), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setEthernetField(name string, fieldValue starlark.Value) error {
	ethernet := &value.packet.ethernet
	switch name {
	case "srcMAC":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.ethernet.srcMAC: %w", err)
		}
		ethernet.SrcMAC = append(ethernet.SrcMAC[:0], mac...)
	case "dstMAC":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.ethernet.dstMAC: %w", err)
		}
		ethernet.DstMAC = append(ethernet.DstMAC[:0], mac...)
	case "ethernetType":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ethernet.ethernetType: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ethernet.ethernetType: value is required")
		}
		ethernet.EthernetType = layers.EthernetType(*number)
	case "length":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ethernet.length: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ethernet.length: value is required")
		}
		ethernet.Length = *number
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}

func (value *mutableLayerValue) arpAttr(name string) (starlark.Value, error) {
	arp := value.packet.arp
	switch name {
	case "addrType":
		return starlark.MakeUint64(uint64(arp.AddrType)), nil
	case "protocol":
		return starlark.MakeUint64(uint64(arp.Protocol)), nil
	case "hwAddressSize":
		return starlark.MakeUint64(uint64(arp.HwAddressSize)), nil
	case "protAddressSize":
		return starlark.MakeUint64(uint64(arp.ProtAddressSize)), nil
	case "operation":
		return starlark.MakeUint64(uint64(arp.Operation)), nil
	case "sourceHwAddress":
		return starlark.String(net.HardwareAddr(arp.SourceHwAddress).String()), nil
	case "sourceProtAddress":
		return starlark.String(net.IP(arp.SourceProtAddress).String()), nil
	case "dstHwAddress":
		return starlark.String(net.HardwareAddr(arp.DstHwAddress).String()), nil
	case "dstProtAddress":
		return starlark.String(net.IP(arp.DstProtAddress).String()), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setARPField(name string, fieldValue starlark.Value) error {
	arp := &value.packet.arp
	switch name {
	case "addrType":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.addrType: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.addrType: value is required")
		}
		arp.AddrType = layers.LinkType(*number)
	case "protocol":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.protocol: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.protocol: value is required")
		}
		arp.Protocol = layers.EthernetType(*number)
	case "hwAddressSize":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.hwAddressSize: %w", err)
		}
		if number == nil || *number != 6 {
			return fmt.Errorf("packet.arp.hwAddressSize: only Ethernet size 6 is supported")
		}
		arp.HwAddressSize = *number
	case "protAddressSize":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.protAddressSize: %w", err)
		}
		if number == nil || *number != 4 {
			return fmt.Errorf("packet.arp.protAddressSize: only IPv4 size 4 is supported")
		}
		arp.ProtAddressSize = *number
	case "operation":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.operation: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.operation: value is required")
		}
		arp.Operation = *number
	case "sourceHwAddress":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.arp.sourceHwAddress: %w", err)
		}
		arp.SourceHwAddress = append(arp.SourceHwAddress[:0], mac...)
	case "sourceProtAddress":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.sourceProtAddress: %w", err)
		}
		arp.SourceProtAddress = append(arp.SourceProtAddress[:0], ip.To4()...)
	case "dstHwAddress":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.arp.dstHwAddress: %w", err)
		}
		arp.DstHwAddress = append(arp.DstHwAddress[:0], mac...)
	case "dstProtAddress":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.dstProtAddress: %w", err)
		}
		arp.DstProtAddress = append(arp.DstProtAddress[:0], ip.To4()...)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}

func (value *mutableLayerValue) ipv4Attr(name string) (starlark.Value, error) {
	ipv4 := value.packet.ipv4
	switch name {
	case "srcIP":
		return starlark.String(ipv4.SrcIP.String()), nil
	case "dstIP":
		return starlark.String(ipv4.DstIP.String()), nil
	case "version":
		return starlark.MakeUint64(uint64(ipv4.Version)), nil
	case "ihl":
		return starlark.MakeUint64(uint64(ipv4.IHL)), nil
	case "tos":
		return starlark.MakeUint64(uint64(ipv4.TOS)), nil
	case "length":
		return starlark.MakeUint64(uint64(ipv4.Length)), nil
	case "id":
		return starlark.MakeUint64(uint64(ipv4.Id)), nil
	case "flags":
		return starlark.MakeUint64(uint64(ipv4.Flags)), nil
	case "fragOffset":
		return starlark.MakeUint64(uint64(ipv4.FragOffset)), nil
	case "ttl":
		return starlark.MakeUint64(uint64(ipv4.TTL)), nil
	case "protocol":
		return starlark.MakeUint64(uint64(ipv4.Protocol)), nil
	case "checksum":
		return starlark.MakeUint64(uint64(ipv4.Checksum)), nil
	case "options":
		return value.ipv4OptionsValue(), nil
	case "padding":
		return starlark.Bytes(string(value.packet.ipv4.Padding)), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) ipv4OptionsValue() starlark.Value {
	options := make([]starlark.Value, 0, len(value.packet.ipv4.Options))
	for _, option := range value.packet.ipv4.Options {
		options = append(options, newScriptObject("packet.ipv4.option", false, starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   starlark.Bytes(string(option.OptionData)),
		}))
	}
	return starlark.NewList(options)
}

func (value *mutableLayerValue) setIPv4Field(name string, fieldValue starlark.Value) error {
	ipv4 := &value.packet.ipv4
	switch name {
	case "srcIP":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.srcIP: %w", err)
		}
		normalized := ip.To4()
		if normalized == nil {
			return fmt.Errorf("packet.ipv4.srcIP: value is required")
		}
		ipv4.SrcIP = append(ipv4.SrcIP[:0], normalized...)
	case "dstIP":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.dstIP: %w", err)
		}
		normalized := ip.To4()
		if normalized == nil {
			return fmt.Errorf("packet.ipv4.dstIP: value is required")
		}
		ipv4.DstIP = append(ipv4.DstIP[:0], normalized...)
	case "version":
		number, err := parseOptionalUint8Range(fieldValue, 0, 15)
		if err != nil {
			return fmt.Errorf("packet.ipv4.version: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.version: value is required")
		}
		ipv4.Version = *number
	case "ihl":
		number, err := parseOptionalUint8Range(fieldValue, 0, 15)
		if err != nil {
			return fmt.Errorf("packet.ipv4.ihl: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.ihl: value is required")
		}
		ipv4.IHL = *number
	case "tos":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.tos: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.tos: value is required")
		}
		ipv4.TOS = *number
	case "length":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.length: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.length: value is required")
		}
		ipv4.Length = *number
	case "id":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.id: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.id: value is required")
		}
		ipv4.Id = *number
	case "flags":
		number, err := parseOptionalUint8Range(fieldValue, 0, 7)
		if err != nil {
			return fmt.Errorf("packet.ipv4.flags: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.flags: value is required")
		}
		ipv4.Flags = layers.IPv4Flag(*number)
	case "fragOffset":
		number, err := parseOptionalUint16Range(fieldValue, 0, 8191)
		if err != nil {
			return fmt.Errorf("packet.ipv4.fragOffset: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.fragOffset: value is required")
		}
		ipv4.FragOffset = *number
	case "ttl":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.ttl: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.ttl: value is required")
		}
		ipv4.TTL = *number
	case "protocol":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.protocol: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.protocol: value is required")
		}
		ipv4.Protocol = layers.IPProtocol(*number)
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.checksum: value is required")
		}
		ipv4.Checksum = *number
	case "options", "padding":
		return fmt.Errorf("packet.ipv4.%s: IPv4 option editing is not supported on the hot path", name)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}

func (value *mutableLayerValue) icmpv4Attr(name string) (starlark.Value, error) {
	icmp := value.packet.icmpv4
	switch name {
	case "typeCode":
		return starlark.String(icmpTypeCodeText(icmp.TypeCode)), nil
	case "type":
		return starlark.MakeUint64(uint64(icmp.TypeCode.Type())), nil
	case "code":
		return starlark.MakeUint64(uint64(icmp.TypeCode.Code())), nil
	case "checksum":
		return starlark.MakeUint64(uint64(icmp.Checksum)), nil
	case "id":
		return starlark.MakeUint64(uint64(icmp.Id)), nil
	case "seq":
		return starlark.MakeUint64(uint64(icmp.Seq)), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setICMPv4Field(name string, fieldValue starlark.Value) error {
	icmp := &value.packet.icmpv4
	switch name {
	case "typeCode":
		typeCode, err := parseOptionalICMPTypeCode(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.typeCode: %w", err)
		}
		if typeCode == nil {
			return fmt.Errorf("packet.icmpv4.typeCode: value is required")
		}
		icmp.TypeCode = *typeCode
	case "type":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.type: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.type: value is required")
		}
		icmp.TypeCode = layers.CreateICMPv4TypeCode(*number, icmp.TypeCode.Code())
	case "code":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.code: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.code: value is required")
		}
		icmp.TypeCode = layers.CreateICMPv4TypeCode(icmp.TypeCode.Type(), *number)
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.checksum: value is required")
		}
		icmp.Checksum = *number
	case "id":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.id: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.id: value is required")
		}
		icmp.Id = *number
	case "seq":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.seq: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.seq: value is required")
		}
		icmp.Seq = *number
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}

func (value *mutableLayerValue) tcpAttr(name string) (starlark.Value, error) {
	tcp := value.packet.tcp
	switch name {
	case "srcPort":
		return starlark.MakeUint64(uint64(tcp.SrcPort)), nil
	case "dstPort":
		return starlark.MakeUint64(uint64(tcp.DstPort)), nil
	case "seq":
		return starlark.MakeUint64(uint64(tcp.Seq)), nil
	case "ack":
		return starlark.MakeUint64(uint64(tcp.Ack)), nil
	case "dataOffset":
		return starlark.MakeUint64(uint64(tcp.DataOffset) * 4), nil
	case "flags":
		return starlark.MakeUint64(uint64(tcpFlags(tcp))), nil
	case "window":
		return starlark.MakeUint64(uint64(tcp.Window)), nil
	case "checksum":
		return starlark.MakeUint64(uint64(tcp.Checksum)), nil
	case "urgentPointer":
		return starlark.MakeUint64(uint64(tcp.Urgent)), nil
	case "options":
		return value.tcpOptionsValue(), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func tcpFlags(tcp layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= 0x01
	}
	if tcp.SYN {
		flags |= 0x02
	}
	if tcp.RST {
		flags |= 0x04
	}
	if tcp.PSH {
		flags |= 0x08
	}
	if tcp.ACK {
		flags |= 0x10
	}
	if tcp.URG {
		flags |= 0x20
	}
	if tcp.ECE {
		flags |= 0x40
	}
	if tcp.CWR {
		flags |= 0x80
	}
	return flags
}

func setTCPFlags(tcp *layers.TCP, flags uint8) {
	tcp.FIN = flags&0x01 != 0
	tcp.SYN = flags&0x02 != 0
	tcp.RST = flags&0x04 != 0
	tcp.PSH = flags&0x08 != 0
	tcp.ACK = flags&0x10 != 0
	tcp.URG = flags&0x20 != 0
	tcp.ECE = flags&0x40 != 0
	tcp.CWR = flags&0x80 != 0
}

func (value *mutableLayerValue) tcpOptionsValue() starlark.Value {
	options := make([]starlark.Value, 0, len(value.packet.tcp.Options))
	for _, option := range value.packet.tcp.Options {
		options = append(options, newScriptObject("packet.tcp.option", false, starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   starlark.Bytes(string(option.OptionData)),
		}))
	}
	return starlark.NewList(options)
}

func (value *mutableLayerValue) setTCPField(name string, fieldValue starlark.Value) error {
	tcp := &value.packet.tcp
	switch name {
	case "srcPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.srcPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.srcPort: value is required")
		}
		tcp.SrcPort = layers.TCPPort(*number)
	case "dstPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.dstPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.dstPort: value is required")
		}
		tcp.DstPort = layers.TCPPort(*number)
	case "seq":
		number, err := integerValue(fieldValue)
		if err != nil || number < 0 || number > 0xffffffff {
			return fmt.Errorf("packet.tcp.seq: must be between 0 and 4294967295")
		}
		tcp.Seq = uint32(number)
	case "ack":
		number, err := integerValue(fieldValue)
		if err != nil || number < 0 || number > 0xffffffff {
			return fmt.Errorf("packet.tcp.ack: must be between 0 and 4294967295")
		}
		tcp.Ack = uint32(number)
	case "dataOffset":
		number, err := parseOptionalUint8Range(fieldValue, header.TCPMinimumSize, header.TCPHeaderMaximumSize)
		if err != nil {
			return fmt.Errorf("packet.tcp.dataOffset: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.dataOffset: value is required")
		}
		if *number%4 != 0 {
			return fmt.Errorf("packet.tcp.dataOffset: must be a multiple of 4")
		}
		tcp.DataOffset = *number / 4
	case "flags":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.flags: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.flags: value is required")
		}
		setTCPFlags(tcp, *number)
	case "window":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.window: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.window: value is required")
		}
		tcp.Window = *number
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.checksum: value is required")
		}
		tcp.Checksum = *number
	case "urgentPointer":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.urgentPointer: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.urgentPointer: value is required")
		}
		tcp.Urgent = *number
	case "options":
		options, err := parseTCPOptionsValue(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.options: %w", err)
		}
		if err := value.packet.setTCPOptions(options); err != nil {
			return err
		}
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}

func (value *mutableLayerValue) udpAttr(name string) (starlark.Value, error) {
	udp := value.packet.udp
	switch name {
	case "srcPort":
		return starlark.MakeUint64(uint64(udp.SrcPort)), nil
	case "dstPort":
		return starlark.MakeUint64(uint64(udp.DstPort)), nil
	case "length":
		return starlark.MakeUint64(uint64(udp.Length)), nil
	case "checksum":
		return starlark.MakeUint64(uint64(udp.Checksum)), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setUDPField(name string, fieldValue starlark.Value) error {
	udp := &value.packet.udp
	switch name {
	case "srcPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.srcPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.srcPort: value is required")
		}
		udp.SrcPort = layers.UDPPort(*number)
	case "dstPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.dstPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.dstPort: value is required")
		}
		udp.DstPort = layers.UDPPort(*number)
	case "length":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.length: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.length: value is required")
		}
		udp.Length = *number
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.checksum: value is required")
		}
		udp.Checksum = *number
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}
