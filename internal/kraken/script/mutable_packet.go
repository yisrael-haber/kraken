package script

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type mutablePacket struct {
	packetLayers

	frame   []byte
	send    func([]byte) error
	mutated bool
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

type ethernetValue struct{ packet *mutablePacket }
type arpValue struct{ packet *mutablePacket }
type ipv4Value struct{ packet *mutablePacket }
type icmpv4Value struct{ packet *mutablePacket }
type tcpValue struct{ packet *mutablePacket }
type udpValue struct{ packet *mutablePacket }

var (
	packetAttrNames   = []string{"ethernet", "arp", "ipv4", "icmpv4", "tcp", "udp", "payload", "copy", "create_fragments", "pad_payload", "truncate_payload", "send"}
	ethernetAttrNames = []string{"srcMAC", "dstMAC", "ethernetType", "length"}
	arpAttrNames      = []string{"addrType", "protocol", "hwAddressSize", "protAddressSize", "operation", "sourceHwAddress", "sourceProtAddress", "dstHwAddress", "dstProtAddress"}
	ipv4AttrNames     = []string{"srcIP", "dstIP", "version", "ihl", "tos", "length", "id", "flags", "fragOffset", "ttl", "protocol", "checksum", "options", "padding"}
	icmpv4AttrNames   = []string{"typeCode", "type", "code", "checksum", "id", "seq"}
	tcpAttrNames      = []string{"srcPort", "dstPort", "seq", "ack", "dataOffset", "flags", "window", "checksum", "urgentPointer", "options"}
	udpAttrNames      = []string{"srcPort", "dstPort", "length", "checksum"}
)

type packetDecoder struct {
	parser         *gopacket.DecodingLayerParser
	decodedScratch []gopacket.LayerType
	layers         packetLayers
}

var packetDecoderPool = sync.Pool{New: func() any { return newPacketDecoder() }}

func newPacketDecoder() *packetDecoder {
	decoder := &packetDecoder{decodedScratch: make([]gopacket.LayerType, 0, 8)}
	decoder.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&decoder.layers.ethernet,
		&decoder.layers.arp,
		&decoder.layers.ipv4,
		&decoder.layers.tcp,
		&decoder.layers.udp,
		&decoder.layers.icmpv4,
	)
	decoder.parser.IgnoreUnsupported = true
	return decoder
}

func newMutablePacket(frame []byte, send func([]byte) error) (*mutablePacket, error) {
	decoder := packetDecoderPool.Get().(*packetDecoder)
	defer packetDecoderPool.Put(decoder)

	decoder.layers = packetLayers{}

	if err := decoder.parser.DecodeLayers(frame, &decoder.decodedScratch); err != nil {
		return nil, err
	}
	switch {
	case len(decoder.layers.tcp.Contents) != 0:
		decoder.layers.payload = decoder.layers.tcp.Payload
	case len(decoder.layers.udp.Contents) != 0:
		decoder.layers.payload = decoder.layers.udp.Payload
	case len(decoder.layers.icmpv4.Contents) != 0:
		decoder.layers.payload = decoder.layers.icmpv4.Payload
	case len(decoder.layers.ipv4.Contents) != 0:
		decoder.layers.payload = decoder.layers.ipv4.Payload
	}
	return &mutablePacket{
		packetLayers: decoder.layers,
		frame:        frame,
		send:         send,
	}, nil
}

func (packet *mutablePacket) finalize(options gopacket.SerializeOptions) ([]byte, error) {
	if !packet.mutated && !options.FixLengths && !options.ComputeChecksums {
		return packet.frame, nil
	}

	return packet.serialize(options)
}

func (packet *mutablePacket) clone() (*mutablePacket, error) {
	out, err := packet.finalize(gopacket.SerializeOptions{})
	if err != nil {
		return nil, err
	}
	return newMutablePacket(append([]byte(nil), out...), packet.send)
}

func (packet *mutablePacket) fragments(mtu int) ([]starlark.Value, error) {
	if !packet.hasIPv4() {
		return nil, fmt.Errorf("packet.create_fragments requires an IPv4 packet")
	}
	frame, err := packet.finalize(gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
	if err != nil {
		return nil, err
	}
	const ethernetHeaderLength = header.EthernetMinimumSize
	if len(frame) < ethernetHeaderLength+header.IPv4MinimumSize {
		return nil, fmt.Errorf("packet.create_fragments requires a complete Ethernet/IPv4 frame")
	}
	ipv4 := header.IPv4(frame[ethernetHeaderLength:])
	ipHeaderLength := int(ipv4.HeaderLength())
	totalLength := int(ipv4.TotalLength())
	if ipHeaderLength < header.IPv4MinimumSize || totalLength < ipHeaderLength || ethernetHeaderLength+totalLength > len(frame) {
		return nil, fmt.Errorf("packet.create_fragments requires a valid IPv4 length")
	}
	if totalLength <= mtu {
		out, err := newMutablePacket(append([]byte(nil), frame...), packet.send)
		return []starlark.Value{out}, err
	}

	fragmentPayloadLimit := ((mtu - ipHeaderLength) / 8) * 8
	if fragmentPayloadLimit <= 0 {
		return nil, fmt.Errorf("packet.create_fragments MTU leaves no IPv4 fragment payload")
	}

	payload := frame[ethernetHeaderLength+ipHeaderLength : ethernetHeaderLength+totalLength]
	baseOffset := int(ipv4.FragmentOffset())
	baseFlags := ipv4.Flags() &^ (header.IPv4FlagDontFragment | header.IPv4FlagMoreFragments)
	items := make([]starlark.Value, 0, (len(payload)+fragmentPayloadLimit-1)/fragmentPayloadLimit)
	for offset := 0; offset < len(payload); offset += fragmentPayloadLimit {
		end := min(offset+fragmentPayloadLimit, len(payload))
		moreFragments := end < len(payload) || ipv4.More()
		fragment, err := packet.fragment(frame, payload[offset:end], ipHeaderLength, baseOffset+offset, baseFlags, moreFragments)
		if err != nil {
			return nil, err
		}
		items = append(items, fragment)
	}
	return items, nil
}

func (packet *mutablePacket) fragment(frame, payload []byte, ipHeaderLength, offset int, flags uint8, moreFragments bool) (*mutablePacket, error) {
	if offset > 0xffff {
		return nil, fmt.Errorf("packet.create_fragments fragment offset exceeds IPv4 range")
	}
	const ethernetHeaderLength = header.EthernetMinimumSize
	fragment := make([]byte, ethernetHeaderLength+ipHeaderLength+len(payload))
	copy(fragment[:ethernetHeaderLength+ipHeaderLength], frame[:ethernetHeaderLength+ipHeaderLength])
	copy(fragment[ethernetHeaderLength+ipHeaderLength:], payload)

	ipv4 := header.IPv4(fragment[ethernetHeaderLength:])
	if moreFragments {
		flags |= header.IPv4FlagMoreFragments
	}
	ipv4.SetTotalLength(uint16(ipHeaderLength + len(payload)))
	ipv4.SetFlagsFragmentOffset(flags, uint16(offset))
	ipv4.SetChecksum(0)
	ipv4.SetChecksum(^ipv4.CalculateChecksum())

	out, err := newMutablePacket(fragment, packet.send)
	if err != nil {
		return nil, err
	}
	out.icmpv4 = layers.ICMPv4{}
	out.tcp = layers.TCP{}
	out.udp = layers.UDP{}
	out.payload = append([]byte(nil), payload...)
	return out, nil
}

func (packet *mutablePacket) serialize(options gopacket.SerializeOptions) ([]byte, error) {
	buffer := gopacket.NewSerializeBufferExpectedSize(len(packet.payload), 0)
	var layerStack [7]gopacket.SerializableLayer
	items := layerStack[:0]
	items = append(items, &packet.ethernet)
	if packet.hasARP() {
		items = append(items, &packet.arp)
	} else if packet.hasIPv4() {
		items = append(items, &packet.ipv4)
		if packet.hasICMPv4() {
			items = append(items, &packet.icmpv4)
		}
		if packet.hasTCP() {
			items = append(items, &packet.tcp)
		}
		if packet.hasUDP() {
			items = append(items, &packet.udp)
		}
	}
	if packet.payload != nil {
		items = append(items, gopacket.Payload(packet.payload))
	}
	if options.ComputeChecksums {
		if err := packet.prepareTransportChecksums(); err != nil {
			return nil, err
		}
	}
	if err := gopacket.SerializeLayers(buffer, options, items...); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (packet *mutablePacket) prepareTransportChecksums() error {
	if !packet.hasIPv4() {
		return nil
	}
	if packet.hasTCP() {
		if err := packet.tcp.SetNetworkLayerForChecksum(&packet.ipv4); err != nil {
			return err
		}
	}
	if packet.hasUDP() {
		if err := packet.udp.SetNetworkLayerForChecksum(&packet.ipv4); err != nil {
			return err
		}
	}
	return nil
}

func (packet *mutablePacket) hasARP() bool    { return len(packet.arp.Contents) != 0 }
func (packet *mutablePacket) hasIPv4() bool   { return len(packet.ipv4.Contents) != 0 }
func (packet *mutablePacket) hasICMPv4() bool { return len(packet.icmpv4.Contents) != 0 }
func (packet *mutablePacket) hasTCP() bool    { return len(packet.tcp.Contents) != 0 }
func (packet *mutablePacket) hasUDP() bool    { return len(packet.udp.Contents) != 0 }

func (packet *mutablePacket) String() string       { return "<packet>" }
func (packet *mutablePacket) Type() string         { return "packet" }
func (packet *mutablePacket) Freeze()              {}
func (packet *mutablePacket) Truth() starlark.Bool { return true }
func (packet *mutablePacket) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", packet.Type())
}

func (packet *mutablePacket) Attr(name string) (starlark.Value, error) {
	switch name {
	case "ethernet":
		return &ethernetValue{packet: packet}, nil
	case "arp":
		if !packet.hasARP() {
			return starlark.None, nil
		}
		return &arpValue{packet: packet}, nil
	case "ipv4":
		if !packet.hasIPv4() {
			return starlark.None, nil
		}
		return &ipv4Value{packet: packet}, nil
	case "icmpv4":
		if !packet.hasICMPv4() {
			return starlark.None, nil
		}
		return &icmpv4Value{packet: packet}, nil
	case "tcp":
		if !packet.hasTCP() {
			return starlark.None, nil
		}
		return &tcpValue{packet: packet}, nil
	case "udp":
		if !packet.hasUDP() {
			return starlark.None, nil
		}
		return &udpValue{packet: packet}, nil
	case "payload":
		return &byteBuffer{data: packet.payload}, nil
	case "copy":
		return starlark.NewBuiltin("packet.copy", packet.copyCurrent), nil
	case "create_fragments":
		return starlark.NewBuiltin("packet.create_fragments", packet.createFragments), nil
	case "pad_payload":
		return starlark.NewBuiltin("packet.pad_payload", packet.padPayload), nil
	case "send":
		return starlark.NewBuiltin("packet.send", packet.sendCurrent), nil
	case "truncate_payload":
		return starlark.NewBuiltin("packet.truncate_payload", packet.truncatePayload), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("packet has no .%s attribute", name))
	}
}

func (packet *mutablePacket) AttrNames() []string {
	return packetAttrNames
}

func (packet *mutablePacket) SetField(name string, fieldValue starlark.Value) error {
	switch name {
	case "payload":
		payload, err := byteSliceFromValue(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.payload: %w", err)
		}
		packet.payload = payload
		packet.mutated = true
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("packet has no writable .%s attribute", name))
	}
}

func (packet *mutablePacket) createFragments(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var mtuValue starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &mtuValue); err != nil {
		return nil, err
	}
	mtu, err := integerInRange(mtuValue, 1, 65535)
	if err != nil {
		return nil, fmt.Errorf("packet.create_fragments MTU: %w", err)
	}
	fragments, err := packet.fragments(int(mtu))
	if err != nil {
		return nil, err
	}
	return starlark.NewList(fragments), nil
}

func (packet *mutablePacket) padPayload(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var lengthValue starlark.Value
	padByte := 0
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "length", &lengthValue, "byte?", &padByte); err != nil {
		return nil, err
	}
	length, err := integerInRange(lengthValue, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("packet.pad_payload length: %w", err)
	}
	if padByte < 0 || padByte > 255 {
		return nil, fmt.Errorf("packet.pad_payload byte: must be between 0 and 255")
	}
	targetLength := int(length)
	if targetLength > len(packet.payload) {
		for len(packet.payload) < targetLength {
			packet.payload = append(packet.payload, byte(padByte))
		}
		packet.mutated = true
	}
	return starlark.None, nil
}

func (packet *mutablePacket) truncatePayload(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var lengthValue starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &lengthValue); err != nil {
		return nil, err
	}
	length, err := integerInRange(lengthValue, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("packet.truncate_payload length: %w", err)
	}
	targetLength := int(length)
	if targetLength < len(packet.payload) {
		packet.payload = packet.payload[:targetLength]
		packet.mutated = true
	}
	return starlark.None, nil
}

func (packet *mutablePacket) copyCurrent(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	return packet.clone()
}

func (packet *mutablePacket) sendCurrent(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	fixLengths, fixChecksums := true, true
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "fix_lengths?", &fixLengths, "fix_checksums?", &fixChecksums); err != nil {
		return nil, err
	}
	out, err := packet.finalize(gopacket.SerializeOptions{FixLengths: fixLengths, ComputeChecksums: fixChecksums})
	if err != nil {
		return nil, err
	}
	return starlark.None, packet.send(out)
}

func (value *ethernetValue) String() string       { return "<packet.ethernet>" }
func (value *ethernetValue) Type() string         { return "packet.ethernet" }
func (value *ethernetValue) Freeze()              {}
func (value *ethernetValue) Truth() starlark.Bool { return true }
func (value *ethernetValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}
func (value *ethernetValue) AttrNames() []string { return ethernetAttrNames }

func (value *ethernetValue) Attr(name string) (starlark.Value, error) {
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

func (value *ethernetValue) SetField(name string, fieldValue starlark.Value) error {
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
	value.packet.mutated = true
	return nil
}

func (value *arpValue) String() string        { return "<packet.arp>" }
func (value *arpValue) Type() string          { return "packet.arp" }
func (value *arpValue) Freeze()               {}
func (value *arpValue) Truth() starlark.Bool  { return true }
func (value *arpValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", value.Type()) }
func (value *arpValue) AttrNames() []string   { return arpAttrNames }

func (value *arpValue) Attr(name string) (starlark.Value, error) {
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

func (value *arpValue) SetField(name string, fieldValue starlark.Value) error {
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
	value.packet.mutated = true
	return nil
}

func (value *ipv4Value) String() string        { return "<packet.ipv4>" }
func (value *ipv4Value) Type() string          { return "packet.ipv4" }
func (value *ipv4Value) Freeze()               {}
func (value *ipv4Value) Truth() starlark.Bool  { return true }
func (value *ipv4Value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", value.Type()) }
func (value *ipv4Value) AttrNames() []string   { return ipv4AttrNames }

func (value *ipv4Value) Attr(name string) (starlark.Value, error) {
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

func (value *ipv4Value) ipv4OptionsValue() starlark.Value {
	options := make([]starlark.Value, 0, len(value.packet.ipv4.Options))
	for _, option := range value.packet.ipv4.Options {
		options = append(options, &scriptObject{typeName: "packet.ipv4.option", fields: starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   starlark.Bytes(string(option.OptionData)),
		}})
	}
	return starlark.NewList(options)
}

func (value *ipv4Value) SetField(name string, fieldValue starlark.Value) error {
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
	value.packet.mutated = true
	return nil
}

func (value *icmpv4Value) String() string       { return "<packet.icmpv4>" }
func (value *icmpv4Value) Type() string         { return "packet.icmpv4" }
func (value *icmpv4Value) Freeze()              {}
func (value *icmpv4Value) Truth() starlark.Bool { return true }
func (value *icmpv4Value) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}
func (value *icmpv4Value) AttrNames() []string { return icmpv4AttrNames }

func (value *icmpv4Value) Attr(name string) (starlark.Value, error) {
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

func (value *icmpv4Value) SetField(name string, fieldValue starlark.Value) error {
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
	value.packet.mutated = true
	return nil
}

func (value *tcpValue) String() string        { return "<packet.tcp>" }
func (value *tcpValue) Type() string          { return "packet.tcp" }
func (value *tcpValue) Freeze()               {}
func (value *tcpValue) Truth() starlark.Bool  { return true }
func (value *tcpValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", value.Type()) }
func (value *tcpValue) AttrNames() []string   { return tcpAttrNames }

func (value *tcpValue) Attr(name string) (starlark.Value, error) {
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

func (value *tcpValue) tcpOptionsValue() starlark.Value {
	options := make([]starlark.Value, 0, len(value.packet.tcp.Options))
	for _, option := range value.packet.tcp.Options {
		options = append(options, &scriptObject{typeName: "packet.tcp.option", fields: starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   starlark.Bytes(string(option.OptionData)),
		}})
	}
	return starlark.NewList(options)
}

func (value *tcpValue) SetField(name string, fieldValue starlark.Value) error {
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
		number, err := requiredUint32(label, fieldValue)
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
	value.packet.mutated = true
	return nil
}

func (value *udpValue) String() string        { return "<packet.udp>" }
func (value *udpValue) Type() string          { return "packet.udp" }
func (value *udpValue) Freeze()               {}
func (value *udpValue) Truth() starlark.Bool  { return true }
func (value *udpValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", value.Type()) }
func (value *udpValue) AttrNames() []string   { return udpAttrNames }

func (value *udpValue) Attr(name string) (starlark.Value, error) {
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

func (value *udpValue) SetField(name string, fieldValue starlark.Value) error {
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
	value.packet.mutated = true
	return nil
}
