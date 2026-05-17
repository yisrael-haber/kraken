package script

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type MutablePacket struct {
	data []byte

	decoded []gopacket.LayerType

	packetLayers

	dirty            bool
	fixLengths       bool
	computeChecksums bool

	dropped bool
}

type packetLayers struct {
	ethernet layers.Ethernet
	arp      layers.ARP
	ipv4     layers.IPv4
	icmpv4   layers.ICMPv4
	tcp      layers.TCP
	udp      layers.UDP
	payload  []byte
}

type mutableLayerValue struct {
	packet *MutablePacket
	name   string
}

var (
	packetAttrNames   = []string{"ethernet", "arp", "ipv4", "icmpv4", "tcp", "udp", "payload", "fixLengths", "computeChecksums", "layers", "layer", "drop"}
	ethernetAttrNames = []string{"srcMAC", "dstMAC", "ethernetType", "length"}
	arpAttrNames      = []string{"addrType", "protocol", "hwAddressSize", "protAddressSize", "operation", "sourceHwAddress", "sourceProtAddress", "dstHwAddress", "dstProtAddress"}
	ipv4AttrNames     = []string{"srcIP", "dstIP", "version", "ihl", "tos", "length", "id", "flags", "fragOffset", "ttl", "protocol", "checksum", "options", "padding"}
	icmpv4AttrNames   = []string{"typeCode", "type", "code", "checksum", "id", "seq"}
	tcpAttrNames      = []string{"srcPort", "dstPort", "seq", "ack", "dataOffset", "flags", "window", "checksum", "urgentPointer", "options"}
	udpAttrNames      = []string{"srcPort", "dstPort", "length", "checksum"}
)

type packetDecodeWorkspace struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	layers  packetLayers
}

var packetDecodeWorkspacePool = sync.Pool{
	New: func() any {
		workspace := &packetDecodeWorkspace{
			decoded: make([]gopacket.LayerType, 0, 8),
		}
		workspace.parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&workspace.layers.ethernet,
			&workspace.layers.arp,
			&workspace.layers.ipv4,
			&workspace.layers.tcp,
			&workspace.layers.udp,
			&workspace.layers.icmpv4,
			(*gopacket.Payload)(&workspace.layers.payload),
		)
		workspace.parser.IgnorePanic = true
		workspace.parser.IgnoreUnsupported = true
		return workspace
	},
}

func NewMutablePacket(frame []byte) (*MutablePacket, error) {
	workspace := packetDecodeWorkspacePool.Get().(*packetDecodeWorkspace)
	defer packetDecodeWorkspacePool.Put(workspace)

	workspace.layers = packetLayers{}

	if err := workspace.parser.DecodeLayers(frame, &workspace.decoded); err != nil {
		return nil, err
	}
	if len(workspace.decoded) == 0 {
		return nil, fmt.Errorf("unsupported packet layout")
	}

	packet := &MutablePacket{
		data:             frame,
		decoded:          append([]gopacket.LayerType(nil), workspace.decoded...),
		packetLayers:     workspace.layers,
		fixLengths:       true,
		computeChecksums: true,
	}
	if end := packet.protocolFrameEnd(); end > 0 && end < len(frame) {
		packet.data = packet.data[:end]
	}
	return packet, nil
}

func (packet *MutablePacket) Bytes() []byte {
	return packet.data
}

func (packet *MutablePacket) protocolFrameEnd() int {
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

	buffer := gopacket.NewSerializeBufferExpectedSize(len(packet.payload), 0)
	var layerStack [7]gopacket.SerializableLayer
	items := layerStack[:0]
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

	packet.data = buffer.Bytes()
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

func (packet *MutablePacket) layerNamesList() starlark.Value {
	items := make([]starlark.Value, 0, len(packet.decoded))
	for _, layerType := range packet.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			items = append(items, starlark.String("ethernet"))
		case layers.LayerTypeARP:
			items = append(items, starlark.String("arp"))
		case layers.LayerTypeIPv4:
			items = append(items, starlark.String("ipv4"))
		case layers.LayerTypeICMPv4:
			items = append(items, starlark.String("icmpv4"))
		case layers.LayerTypeTCP:
			items = append(items, starlark.String("tcp"))
		case layers.LayerTypeUDP:
			items = append(items, starlark.String("udp"))
		}
	}
	return starlark.NewList(items)
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
	payloadEnd := packet.protocolFrameEnd()
	if payloadEnd < payloadStart {
		payloadEnd = payloadStart
	}
	if payloadEnd > len(packet.data) {
		payloadEnd = len(packet.data)
	}

	ipPayload := packet.data[payloadStart:payloadEnd]
	if len(ipPayload) == 0 {
		cloned, err := NewMutablePacket(packet.data)
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
			return nil, err
		}
		fragment.fixLengths = packet.fixLengths
		fragment.computeChecksums = packet.computeChecksums
		fragments = append(fragments, fragment)
		offset += size
	}

	return fragments, nil
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
		return packet.layerValue("ethernet", layers.LayerTypeEthernet), nil
	case "arp":
		return packet.layerValue("arp", layers.LayerTypeARP), nil
	case "ipv4":
		return packet.layerValue("ipv4", layers.LayerTypeIPv4), nil
	case "icmpv4":
		return packet.layerValue("icmpv4", layers.LayerTypeICMPv4), nil
	case "tcp":
		return packet.layerValue("tcp", layers.LayerTypeTCP), nil
	case "udp":
		return packet.layerValue("udp", layers.LayerTypeUDP), nil
	case "payload":
		return &byteBuffer{
			data:  packet.payload,
			onSet: func() { packet.dirty = true },
		}, nil
	case "layers":
		return packet.layerNamesList(), nil
	case "layer":
		return starlark.NewBuiltin("packet.layer", packet.layerByName), nil
	case "drop":
		return starlark.NewBuiltin("packet.drop", packet.dropBuiltin), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("packet has no .%s attribute", name))
	}
}

func (packet *MutablePacket) layerValue(name string, layerType gopacket.LayerType) starlark.Value {
	if !packet.hasLayer(layerType) {
		return starlark.None
	}
	return &mutableLayerValue{packet: packet, name: name}
}

func (packet *MutablePacket) AttrNames() []string {
	return packetAttrNames
}

func (packet *MutablePacket) SetField(name string, fieldValue starlark.Value) error {
	switch name {
	case "payload":
		payload, err := byteSliceFromValue(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.payload: %w", err)
		}
		packet.payload = payload
		packet.dirty = true
		return nil
	case "fixLengths", "computeChecksums":
		boolean, err := requiredBool("packet."+name, fieldValue)
		if err != nil {
			return err
		}
		if name == "fixLengths" {
			packet.fixLengths = boolean
		} else {
			packet.computeChecksums = boolean
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
	return layerValue, nil
}

func (packet *MutablePacket) dropBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs("packet.drop", args, kwargs, 0); err != nil {
		return nil, err
	}
	packet.dropped = true
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
		return ethernetAttrNames
	case "arp":
		return arpAttrNames
	case "ipv4":
		return ipv4AttrNames
	case "icmpv4":
		return icmpv4AttrNames
	case "tcp":
		return tcpAttrNames
	case "udp":
		return udpAttrNames
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
	label := "packet.ethernet." + name
	switch name {
	case "srcMAC", "dstMAC":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if name == "srcMAC" {
			ethernet.SrcMAC = mac
		} else {
			ethernet.DstMAC = mac
		}
	case "ethernetType", "length":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "ethernetType" {
			ethernet.EthernetType = layers.EthernetType(number)
		} else {
			ethernet.Length = number
		}
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
	label := "packet.arp." + name
	switch name {
	case "addrType", "protocol", "operation":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		switch name {
		case "addrType":
			arp.AddrType = layers.LinkType(number)
		case "protocol":
			arp.Protocol = layers.EthernetType(number)
		default:
			arp.Operation = number
		}
	case "hwAddressSize", "protAddressSize":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "hwAddressSize" {
			arp.HwAddressSize = number
		} else {
			arp.ProtAddressSize = number
		}
	case "sourceHwAddress", "dstHwAddress":
		address, err := parseScriptHardwareAddr(fieldValue, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if name == "sourceHwAddress" {
			arp.SourceHwAddress = address
		} else {
			arp.DstHwAddress = address
		}
	case "sourceProtAddress", "dstProtAddress":
		address, err := parseScriptProtocolAddress(fieldValue)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if name == "sourceProtAddress" {
			arp.SourceProtAddress = address
		} else {
			arp.DstProtAddress = address
		}
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
	label := "packet.ipv4." + name
	switch name {
	case "srcIP", "dstIP":
		ip, err := requiredIPv4(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "srcIP" {
			ipv4.SrcIP = ip
		} else {
			ipv4.DstIP = ip
		}
	case "version", "ihl":
		number, err := requiredUint8Range(label, fieldValue, 0, 15)
		if err != nil {
			return err
		}
		if name == "version" {
			ipv4.Version = number
		} else {
			ipv4.IHL = number
		}
	case "tos", "ttl":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "tos" {
			ipv4.TOS = number
		} else {
			ipv4.TTL = number
		}
	case "length", "id", "checksum":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		switch name {
		case "length":
			ipv4.Length = number
		case "id":
			ipv4.Id = number
		default:
			ipv4.Checksum = number
		}
	case "flags":
		number, err := requiredUint8Range(label, fieldValue, 0, 7)
		if err != nil {
			return err
		}
		ipv4.Flags = layers.IPv4Flag(number)
	case "fragOffset":
		number, err := requiredUint16Range(label, fieldValue, 0, 8191)
		if err != nil {
			return err
		}
		ipv4.FragOffset = number
	case "protocol":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		ipv4.Protocol = layers.IPProtocol(number)
	case "options":
		options, err := parseIPv4OptionsValue(fieldValue)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		ipv4.Options = options
	case "padding":
		padding, err := byteSliceFromValue(fieldValue)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		ipv4.Padding = padding
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
	label := "packet.icmpv4." + name
	switch name {
	case "typeCode":
		typeCode, err := requiredICMPTypeCode(label, fieldValue)
		if err != nil {
			return err
		}
		icmp.TypeCode = typeCode
	case "type":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		icmp.TypeCode = layers.CreateICMPv4TypeCode(number, icmp.TypeCode.Code())
	case "code":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		icmp.TypeCode = layers.CreateICMPv4TypeCode(icmp.TypeCode.Type(), number)
	case "checksum", "id", "seq":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		switch name {
		case "checksum":
			icmp.Checksum = number
		case "id":
			icmp.Id = number
		default:
			icmp.Seq = number
		}
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
	label := "packet.tcp." + name
	switch name {
	case "srcPort", "dstPort":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "srcPort" {
			tcp.SrcPort = layers.TCPPort(number)
		} else {
			tcp.DstPort = layers.TCPPort(number)
		}
	case "seq", "ack":
		number, err := requiredUint32Range(label, fieldValue, 0, 0xffffffff)
		if err != nil {
			return err
		}
		if name == "seq" {
			tcp.Seq = number
		} else {
			tcp.Ack = number
		}
	case "dataOffset":
		number, err := requiredUint8Range(label, fieldValue, header.TCPMinimumSize, header.TCPHeaderMaximumSize)
		if err != nil {
			return err
		}
		if number%4 != 0 {
			return fmt.Errorf("packet.tcp.dataOffset: must be a multiple of 4")
		}
		tcp.DataOffset = number / 4
	case "flags":
		number, err := requiredUint8(label, fieldValue)
		if err != nil {
			return err
		}
		setTCPFlags(tcp, number)
	case "window", "checksum", "urgentPointer":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		switch name {
		case "window":
			tcp.Window = number
		case "checksum":
			tcp.Checksum = number
		default:
			tcp.Urgent = number
		}
	case "options":
		options, err := parseTCPOptionsValue(fieldValue)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		tcp.Options = options
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
	label := "packet.udp." + name
	switch name {
	case "srcPort", "dstPort":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "srcPort" {
			udp.SrcPort = layers.UDPPort(number)
		} else {
			udp.DstPort = layers.UDPPort(number)
		}
	case "length", "checksum":
		number, err := requiredUint16(label, fieldValue)
		if err != nil {
			return err
		}
		if name == "length" {
			udp.Length = number
		} else {
			udp.Checksum = number
		}
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty = true
	return nil
}
