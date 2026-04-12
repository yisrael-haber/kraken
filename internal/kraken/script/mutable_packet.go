package script

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"go.starlark.net/starlark"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type mutablePacketDirty uint32

const (
	dirtyNone mutablePacketDirty = 0
	dirtyLink mutablePacketDirty = 1 << iota
	dirtyNetwork
	dirtyTransport
	dirtyPayload
)

type packetLayout struct {
	names              []string
	arp                bool
	ipv4               bool
	icmpv4             bool
	tcp                bool
	udp                bool
	ethernetStart      int
	arpStart           int
	arpLen             int
	ipv4Start          int
	ipv4HeaderLen      int
	transportStart     int
	transportHeaderLen int
	payloadStart       int
}

type packetDecoderState struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	ethernet layers.Ethernet
	arp      layers.ARP
	ipv4     layers.IPv4
	icmpv4   layers.ICMPv4
	tcp      layers.TCP
	udp      layers.UDP
	payload  gopacket.Payload
}

type MutablePacket struct {
	data []byte

	decoder   *packetDecoderState
	decodeErr error
	decoded   bool
	layout    packetLayout

	dirty            mutablePacketDirty
	fixLengths       bool
	computeChecksums bool

	packetValue        *mutablePacketValue
	serializationValue *mutableSerializationValue
	payloadValue       *packetPayloadBuffer
}

type mutablePacketValue struct {
	packet *MutablePacket
}

type mutableLayerValue struct {
	packet *MutablePacket
	name   string
}

type mutableSerializationValue struct {
	packet *MutablePacket
}

type packetPayloadBuffer struct {
	packet *MutablePacket
}

var packetDecoderPool = sync.Pool{
	New: func() any {
		state := &packetDecoderState{}
		state.parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&state.ethernet,
			&state.arp,
			&state.ipv4,
			&state.tcp,
			&state.udp,
			&state.icmpv4,
			&state.payload,
		)
		state.parser.IgnorePanic = true
		state.parser.IgnoreUnsupported = true
		return state
	},
}

func NewMutablePacket(frame []byte) (*MutablePacket, error) {
	packet := &MutablePacket{
		data:             frame,
		fixLengths:       true,
		computeChecksums: true,
	}
	if err := packet.ensureDecoded(); err != nil {
		return packet, nil
	}
	if end := packet.payloadEnd(); end > 0 && end < len(packet.data) {
		packet.data = packet.data[:end]
		packet.invalidateDecode()
	}
	return packet, packet.ensureDecoded()
}

func (packet *MutablePacket) Bytes() []byte {
	if packet == nil {
		return nil
	}
	return packet.data
}

func (packet *MutablePacket) Release() {
	if packet == nil || packet.decoder == nil {
		return
	}

	packet.decoder.decoded = packet.decoder.decoded[:0]
	packetDecoderPool.Put(packet.decoder)
	packet.decoder = nil
}

func (packet *MutablePacket) ensureDecoded() error {
	if packet == nil {
		return nil
	}
	if packet.decoded {
		return packet.decodeErr
	}

	if packet.decoder == nil {
		packet.decoder = packetDecoderPool.Get().(*packetDecoderState)
	}
	packet.decoder.decoded = packet.decoder.decoded[:0]
	packet.decodeErr = packet.decoder.parser.DecodeLayers(packet.data, &packet.decoder.decoded)
	packet.layout = packet.buildLayout()
	packet.decoded = true

	if packet.decodeErr == nil && len(packet.layout.names) == 0 && len(packet.data) != 0 {
		packet.decodeErr = fmt.Errorf("unsupported packet layout")
	}
	return packet.decodeErr
}

func (packet *MutablePacket) invalidateDecode() {
	packet.decoded = false
	packet.decodeErr = nil
}

func (packet *MutablePacket) buildLayout() packetLayout {
	layout := packetLayout{}
	if packet.decoder == nil {
		return layout
	}

	for _, layerType := range packet.decoder.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			layout.names = append(layout.names, "ethernet")
			layout.ethernetStart = 0
		case layers.LayerTypeARP:
			layout.names = append(layout.names, "arp")
			layout.arp = true
			layout.arpStart = header.EthernetMinimumSize
			layout.arpLen = len(packet.decoder.arp.Contents)
			layout.payloadStart = layout.arpStart + layout.arpLen
		case layers.LayerTypeIPv4:
			layout.names = append(layout.names, "ipv4")
			layout.ipv4 = true
			layout.ipv4Start = header.EthernetMinimumSize
			layout.ipv4HeaderLen = len(packet.decoder.ipv4.Contents)
			layout.transportStart = layout.ipv4Start + layout.ipv4HeaderLen
			layout.payloadStart = layout.transportStart
		case layers.LayerTypeICMPv4:
			layout.names = append(layout.names, "icmpv4")
			layout.icmpv4 = true
			layout.transportHeaderLen = len(packet.decoder.icmpv4.Contents)
			layout.payloadStart = layout.transportStart + layout.transportHeaderLen
		case layers.LayerTypeTCP:
			layout.names = append(layout.names, "tcp")
			layout.tcp = true
			layout.transportHeaderLen = len(packet.decoder.tcp.Contents)
			layout.payloadStart = layout.transportStart + layout.transportHeaderLen
		case layers.LayerTypeUDP:
			layout.names = append(layout.names, "udp")
			layout.udp = true
			layout.transportHeaderLen = len(packet.decoder.udp.Contents)
			layout.payloadStart = layout.transportStart + layout.transportHeaderLen
		}
	}

	if layout.payloadStart == 0 && len(packet.data) >= header.EthernetMinimumSize {
		layout.payloadStart = len(packet.data)
	}
	if layout.payloadStart > len(packet.data) {
		layout.payloadStart = len(packet.data)
	}
	return layout
}

func (packet *MutablePacket) payloadBytes() []byte {
	if packet == nil {
		return nil
	}
	if err := packet.ensureDecoded(); err != nil {
		return nil
	}
	if packet.layout.payloadStart > len(packet.data) {
		return nil
	}
	end := packet.payloadEnd()
	if end < packet.layout.payloadStart {
		end = packet.layout.payloadStart
	}
	if end > len(packet.data) {
		end = len(packet.data)
	}
	return packet.data[packet.layout.payloadStart:end]
}

func (packet *MutablePacket) setPayloadBytes(payload []byte) error {
	if packet == nil {
		return nil
	}
	if err := packet.ensureDecoded(); err != nil {
		return err
	}

	start := packet.layout.payloadStart
	if start > len(packet.data) {
		return fmt.Errorf("packet payload is unavailable")
	}

	newLen := start + len(payload)
	if cap(packet.data) < newLen {
		grown := make([]byte, newLen)
		copy(grown, packet.data[:start])
		packet.data = grown
	} else {
		packet.data = packet.data[:newLen]
	}
	copy(packet.data[start:], payload)
	packet.dirty |= dirtyPayload | dirtyTransport | dirtyNetwork
	packet.invalidateDecode()
	return packet.ensureDecoded()
}

func (packet *MutablePacket) payloadEnd() int {
	if packet == nil {
		return 0
	}

	switch {
	case packet.layout.arp:
		return packet.layout.arpStart + packet.layout.arpLen
	case packet.layout.ipv4:
		ipv4Header, err := packet.rawIPv4()
		if err == nil {
			return packet.layout.ipv4Start + int(ipv4Header.TotalLength())
		}
	}
	return len(packet.data)
}

func (packet *MutablePacket) finalize() error {
	if packet == nil || packet.dirty == dirtyNone {
		return nil
	}
	if err := packet.ensureDecoded(); err != nil {
		return err
	}

	if packet.fixLengths {
		packet.repairLengths()
	}
	if packet.computeChecksums {
		packet.repairChecksums()
	}

	packet.dirty = dirtyNone
	packet.invalidateDecode()
	return packet.ensureDecoded()
}

func (packet *MutablePacket) repairLengths() {
	if packet == nil {
		return
	}

	if packet.layout.ipv4 {
		ipv4Header, err := packet.rawIPv4()
		if err == nil {
			ipv4Header.SetTotalLength(uint16(len(packet.data) - packet.layout.ipv4Start))
		}
	}
	if packet.layout.udp {
		udpHeader, err := packet.rawUDP()
		if err == nil {
			udpHeader.SetLength(uint16(len(packet.data) - packet.layout.transportStart))
		}
	}
}

func (packet *MutablePacket) repairChecksums() {
	if packet == nil {
		return
	}

	if packet.layout.ipv4 {
		ipv4Header, err := packet.rawIPv4()
		if err == nil && !ipv4Header.IsChecksumValid() {
			ipv4Header.SetChecksum(0)
			ipv4Header.SetChecksum(^ipv4Header.CalculateChecksum())
		}
	}

	if !packet.layout.ipv4 {
		return
	}

	src, dst, err := packet.ipv4Addresses()
	if err != nil {
		return
	}

	payloadChecksum := checksum.Checksum(packet.payloadBytes(), 0)

	switch {
	case packet.layout.icmpv4:
		icmpHeader, err := packet.rawICMPv4()
		if err != nil {
			return
		}
		current := icmpHeader.Checksum()
		expected := header.ICMPv4Checksum(icmpHeader, payloadChecksum)
		if current != expected {
			icmpHeader.SetChecksum(expected)
		}
	case packet.layout.udp:
		udpHeader, err := packet.rawUDP()
		if err != nil {
			return
		}
		if !udpHeader.IsChecksumValid(src, dst, payloadChecksum) {
			udpHeader.SetChecksum(0)
			partial := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, udpHeader.Length())
			partial = checksum.Combine(partial, payloadChecksum)
			udpHeader.SetChecksum(^udpHeader.CalculateChecksum(partial))
		}
	case packet.layout.tcp:
		tcpHeader, err := packet.rawTCP()
		if err != nil {
			return
		}
		payloadLength := uint16(len(packet.payloadBytes()))
		if !tcpHeader.IsChecksumValid(src, dst, payloadChecksum, payloadLength) {
			tcpHeader.SetChecksum(0)
			totalLen := uint16(len(packet.data) - packet.layout.transportStart)
			partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, totalLen)
			partial = checksum.Combine(partial, payloadChecksum)
			tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(partial))
		}
	}
}

func (packet *MutablePacket) ipv4Addresses() (tcpip.Address, tcpip.Address, error) {
	ipv4Header, err := packet.rawIPv4()
	if err != nil {
		return tcpip.Address{}, tcpip.Address{}, err
	}
	return ipv4Header.SourceAddress(), ipv4Header.DestinationAddress(), nil
}

func (packet *MutablePacket) rawIPv4() (header.IPv4, error) {
	if err := packet.ensureDecoded(); err != nil {
		return nil, err
	}
	if !packet.layout.ipv4 {
		return nil, fmt.Errorf("packet.ipv4: layer is not present")
	}
	end := packet.layout.ipv4Start + packet.layout.ipv4HeaderLen
	if end > len(packet.data) {
		return nil, fmt.Errorf("packet.ipv4: header is truncated")
	}
	return header.IPv4(packet.data[packet.layout.ipv4Start:end]), nil
}

func (packet *MutablePacket) rawARP() (header.ARP, error) {
	if err := packet.ensureDecoded(); err != nil {
		return nil, err
	}
	if !packet.layout.arp {
		return nil, fmt.Errorf("packet.arp: layer is not present")
	}
	end := packet.layout.arpStart + packet.layout.arpLen
	if end > len(packet.data) {
		return nil, fmt.Errorf("packet.arp: header is truncated")
	}
	return header.ARP(packet.data[packet.layout.arpStart:end]), nil
}

func (packet *MutablePacket) rawICMPv4() (header.ICMPv4, error) {
	if err := packet.ensureDecoded(); err != nil {
		return nil, err
	}
	if !packet.layout.icmpv4 {
		return nil, fmt.Errorf("packet.icmpv4: layer is not present")
	}
	end := packet.layout.transportStart + packet.layout.transportHeaderLen
	if end > len(packet.data) {
		return nil, fmt.Errorf("packet.icmpv4: header is truncated")
	}
	return header.ICMPv4(packet.data[packet.layout.transportStart:end]), nil
}

func (packet *MutablePacket) rawTCP() (header.TCP, error) {
	if err := packet.ensureDecoded(); err != nil {
		return nil, err
	}
	if !packet.layout.tcp {
		return nil, fmt.Errorf("packet.tcp: layer is not present")
	}
	end := packet.layout.transportStart + packet.layout.transportHeaderLen
	if end > len(packet.data) {
		return nil, fmt.Errorf("packet.tcp: header is truncated")
	}
	return header.TCP(packet.data[packet.layout.transportStart:end]), nil
}

func (packet *MutablePacket) rawUDP() (header.UDP, error) {
	if err := packet.ensureDecoded(); err != nil {
		return nil, err
	}
	if !packet.layout.udp {
		return nil, fmt.Errorf("packet.udp: layer is not present")
	}
	end := packet.layout.transportStart + packet.layout.transportHeaderLen
	if end > len(packet.data) {
		return nil, fmt.Errorf("packet.udp: header is truncated")
	}
	return header.UDP(packet.data[packet.layout.transportStart:end]), nil
}

func (packet *MutablePacket) payloadBuffer() *packetPayloadBuffer {
	if packet.payloadValue == nil {
		packet.payloadValue = &packetPayloadBuffer{packet: packet}
	}
	return packet.payloadValue
}

func newMutablePacketValue(packet *MutablePacket) (starlark.Value, error) {
	if packet == nil {
		packet = &MutablePacket{fixLengths: true, computeChecksums: true}
	}
	return &mutablePacketValue{packet: packet}, nil
}

func (value *mutablePacketValue) String() string       { return "<packet>" }
func (value *mutablePacketValue) Type() string         { return "packet" }
func (value *mutablePacketValue) Freeze()              {}
func (value *mutablePacketValue) Truth() starlark.Bool { return true }
func (value *mutablePacketValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func (value *mutablePacketValue) Attr(name string) (starlark.Value, error) {
	packet := value.packet
	if packet == nil {
		return starlark.None, nil
	}
	if err := packet.ensureDecoded(); err != nil && name != "payload" && name != "serialization" {
		return nil, err
	}

	switch name {
	case "ethernet":
		if len(packet.data) < header.EthernetMinimumSize {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "ethernet"}, nil
	case "arp":
		if !packet.layout.arp {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "arp"}, nil
	case "ipv4":
		if !packet.layout.ipv4 {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "ipv4"}, nil
	case "icmpv4":
		if !packet.layout.icmpv4 {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "icmpv4"}, nil
	case "tcp":
		if !packet.layout.tcp {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "tcp"}, nil
	case "udp":
		if !packet.layout.udp {
			return starlark.None, nil
		}
		return &mutableLayerValue{packet: packet, name: "udp"}, nil
	case "payload":
		return packet.payloadBuffer(), nil
	case "serialization":
		if packet.serializationValue == nil {
			packet.serializationValue = &mutableSerializationValue{packet: packet}
		}
		return packet.serializationValue, nil
	case "layers":
		items := make([]starlark.Value, 0, len(packet.layout.names))
		for _, name := range packet.layout.names {
			items = append(items, starlark.String(name))
		}
		return starlark.NewList(items), nil
	case "layer":
		return starlark.NewBuiltin("packet.layer", value.layerByName), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("packet has no .%s attribute", name))
	}
}

func (value *mutablePacketValue) AttrNames() []string {
	return []string{"ethernet", "arp", "ipv4", "icmpv4", "tcp", "udp", "payload", "serialization", "layers", "layer"}
}

func (value *mutablePacketValue) SetField(name string, fieldValue starlark.Value) error {
	switch name {
	case "payload":
		payload, err := parseOptionalBytes(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.payload: %w", err)
		}
		return value.packet.setPayloadBytes(payload)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("packet has no writable .%s attribute", name))
	}
}

func (value *mutablePacketValue) layerByName(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	layerValue, err := value.Attr(strings.TrimSpace(name))
	if err != nil {
		var noSuchAttr starlark.NoSuchAttrError
		if errorAsNoSuchAttr(err, &noSuchAttr) {
			return starlark.None, nil
		}
		return nil, err
	}
	if layerValue == nil {
		return starlark.None, nil
	}
	return layerValue, nil
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
		return []string{"srcPort", "dstPort", "seq", "ack", "flags", "window", "checksum"}
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
	if len(value.packet.data) < header.EthernetMinimumSize {
		return starlark.None, nil
	}
	switch name {
	case "srcMAC":
		return starlark.String(net.HardwareAddr(value.packet.data[6:12]).String()), nil
	case "dstMAC":
		return starlark.String(net.HardwareAddr(value.packet.data[0:6]).String()), nil
	case "ethernetType":
		return starlark.MakeUint64(uint64(binary.BigEndian.Uint16(value.packet.data[12:14]))), nil
	case "length":
		return starlark.MakeUint64(0), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setEthernetField(name string, fieldValue starlark.Value) error {
	if len(value.packet.data) < header.EthernetMinimumSize {
		return fmt.Errorf("packet.ethernet: header is not present")
	}
	switch name {
	case "srcMAC":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.ethernet.srcMAC: %w", err)
		}
		copy(value.packet.data[6:12], mac)
	case "dstMAC":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.ethernet.dstMAC: %w", err)
		}
		copy(value.packet.data[0:6], mac)
	case "ethernetType":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ethernet.ethernetType: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ethernet.ethernetType: value is required")
		}
		binary.BigEndian.PutUint16(value.packet.data[12:14], *number)
	case "length":
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyLink
	return nil
}

func (value *mutableLayerValue) arpAttr(name string) (starlark.Value, error) {
	arpHeader, err := value.packet.rawARP()
	if err != nil {
		return nil, err
	}
	switch name {
	case "addrType":
		return starlark.MakeUint64(uint64(binary.BigEndian.Uint16(arpHeader[0:2]))), nil
	case "protocol":
		return starlark.MakeUint64(uint64(binary.BigEndian.Uint16(arpHeader[2:4]))), nil
	case "hwAddressSize":
		return starlark.MakeUint64(uint64(arpHeader[4])), nil
	case "protAddressSize":
		return starlark.MakeUint64(uint64(arpHeader[5])), nil
	case "operation":
		return starlark.MakeUint64(uint64(binary.BigEndian.Uint16(arpHeader[6:8]))), nil
	case "sourceHwAddress":
		return starlark.String(net.HardwareAddr(arpHeader.HardwareAddressSender()).String()), nil
	case "sourceProtAddress":
		return starlark.String(net.IP(arpHeader.ProtocolAddressSender()).String()), nil
	case "dstHwAddress":
		return starlark.String(net.HardwareAddr(arpHeader.HardwareAddressTarget()).String()), nil
	case "dstProtAddress":
		return starlark.String(net.IP(arpHeader.ProtocolAddressTarget()).String()), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setARPField(name string, fieldValue starlark.Value) error {
	arpHeader, err := value.packet.rawARP()
	if err != nil {
		return err
	}
	switch name {
	case "addrType":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.addrType: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.addrType: value is required")
		}
		binary.BigEndian.PutUint16(arpHeader[0:2], *number)
	case "protocol":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.protocol: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.protocol: value is required")
		}
		binary.BigEndian.PutUint16(arpHeader[2:4], *number)
	case "hwAddressSize":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.hwAddressSize: %w", err)
		}
		if number == nil || *number != 6 {
			return fmt.Errorf("packet.arp.hwAddressSize: only Ethernet size 6 is supported")
		}
	case "protAddressSize":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.protAddressSize: %w", err)
		}
		if number == nil || *number != 4 {
			return fmt.Errorf("packet.arp.protAddressSize: only IPv4 size 4 is supported")
		}
	case "operation":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.operation: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.arp.operation: value is required")
		}
		binary.BigEndian.PutUint16(arpHeader[6:8], *number)
	case "sourceHwAddress":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.arp.sourceHwAddress: %w", err)
		}
		copy(arpHeader.HardwareAddressSender(), mac)
	case "sourceProtAddress":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.sourceProtAddress: %w", err)
		}
		copy(arpHeader.ProtocolAddressSender(), common.NormalizeIPv4(ip))
	case "dstHwAddress":
		mac, err := parseScriptHardwareAddr(fieldValue, 6)
		if err != nil {
			return fmt.Errorf("packet.arp.dstHwAddress: %w", err)
		}
		copy(arpHeader.HardwareAddressTarget(), mac)
	case "dstProtAddress":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.arp.dstProtAddress: %w", err)
		}
		copy(arpHeader.ProtocolAddressTarget(), common.NormalizeIPv4(ip))
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyNetwork
	return nil
}

func (value *mutableLayerValue) ipv4Attr(name string) (starlark.Value, error) {
	ipv4Header, err := value.packet.rawIPv4()
	if err != nil {
		return nil, err
	}
	switch name {
	case "srcIP":
		source := ipv4Header.SourceAddress()
		return starlark.String(net.IP(source.AsSlice()).String()), nil
	case "dstIP":
		destination := ipv4Header.DestinationAddress()
		return starlark.String(net.IP(destination.AsSlice()).String()), nil
	case "version":
		return starlark.MakeUint64(uint64(ipv4Header[0] >> 4)), nil
	case "ihl":
		return starlark.MakeUint64(uint64(ipv4Header[0] & 0x0f)), nil
	case "tos":
		return starlark.MakeUint64(uint64(ipv4Header[1])), nil
	case "length":
		return starlark.MakeUint64(uint64(ipv4Header.TotalLength())), nil
	case "id":
		return starlark.MakeUint64(uint64(ipv4Header.ID())), nil
	case "flags":
		return starlark.MakeUint64(uint64(ipv4Header.Flags())), nil
	case "fragOffset":
		return starlark.MakeUint64(uint64(ipv4Header.FragmentOffset())), nil
	case "ttl":
		return starlark.MakeUint64(uint64(ipv4Header.TTL())), nil
	case "protocol":
		return starlark.MakeUint64(uint64(ipv4Header.TransportProtocol())), nil
	case "checksum":
		return starlark.MakeUint64(uint64(ipv4Header.Checksum())), nil
	case "options":
		return value.ipv4OptionsValue(), nil
	case "padding":
		return newOwnedByteBuffer(append([]byte(nil), value.packet.decoder.ipv4.Padding...)), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) ipv4OptionsValue() starlark.Value {
	options := make([]starlark.Value, 0, len(value.packet.decoder.ipv4.Options))
	for _, option := range value.packet.decoder.ipv4.Options {
		options = append(options, newScriptObject("packet.ipv4.option", false, starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   newOwnedByteBuffer(append([]byte(nil), option.OptionData...)),
		}))
	}
	return starlark.NewList(options)
}

func (value *mutableLayerValue) setIPv4Field(name string, fieldValue starlark.Value) error {
	ipv4Header, err := value.packet.rawIPv4()
	if err != nil {
		return err
	}
	switch name {
	case "srcIP":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.srcIP: %w", err)
		}
		normalized := common.NormalizeIPv4(ip)
		if normalized == nil {
			return fmt.Errorf("packet.ipv4.srcIP: value is required")
		}
		ipv4Header.SetSourceAddress(tcpip.AddrFrom4Slice(normalized.To4()))
	case "dstIP":
		ip, err := parseScriptIPv4(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.dstIP: %w", err)
		}
		normalized := common.NormalizeIPv4(ip)
		if normalized == nil {
			return fmt.Errorf("packet.ipv4.dstIP: value is required")
		}
		ipv4Header.SetDestinationAddress(tcpip.AddrFrom4Slice(normalized.To4()))
	case "version":
		number, err := parseOptionalUint8Range(fieldValue, 0, 15)
		if err != nil {
			return fmt.Errorf("packet.ipv4.version: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.version: value is required")
		}
		ipv4Header[0] = (ipv4Header[0] & 0x0f) | (*number << 4)
	case "ihl":
		number, err := parseOptionalUint8Range(fieldValue, 0, 15)
		if err != nil {
			return fmt.Errorf("packet.ipv4.ihl: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.ihl: value is required")
		}
		if *number != ipv4Header.HeaderLength()/4 {
			return fmt.Errorf("packet.ipv4.ihl: IPv4 option resizing is not supported on the hot path")
		}
	case "tos":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.tos: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.tos: value is required")
		}
		ipv4Header.SetTOS(*number, 0)
	case "length":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.length: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.length: value is required")
		}
		ipv4Header.SetTotalLength(*number)
	case "id":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.id: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.id: value is required")
		}
		ipv4Header.SetID(*number)
	case "flags":
		number, err := parseOptionalUint8Range(fieldValue, 0, 7)
		if err != nil {
			return fmt.Errorf("packet.ipv4.flags: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.flags: value is required")
		}
		flagsOffset := (uint16(*number) << 13) | ipv4Header.FragmentOffset()
		binary.BigEndian.PutUint16(ipv4Header[6:8], flagsOffset)
	case "fragOffset":
		number, err := parseOptionalUint16Range(fieldValue, 0, 8191)
		if err != nil {
			return fmt.Errorf("packet.ipv4.fragOffset: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.fragOffset: value is required")
		}
		flagsOffset := (uint16(ipv4Header.Flags()) << 13) | *number
		binary.BigEndian.PutUint16(ipv4Header[6:8], flagsOffset)
	case "ttl":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.ttl: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.ttl: value is required")
		}
		ipv4Header.SetTTL(*number)
	case "protocol":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.protocol: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.protocol: value is required")
		}
		ipv4Header[9] = *number
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.ipv4.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.ipv4.checksum: value is required")
		}
		ipv4Header.SetChecksum(*number)
	case "options", "padding":
		return fmt.Errorf("packet.ipv4.%s: IPv4 option editing is not supported on the hot path", name)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyNetwork
	if name == "srcIP" || name == "dstIP" || name == "protocol" {
		value.packet.dirty |= dirtyTransport
	}
	return nil
}

func (value *mutableLayerValue) icmpv4Attr(name string) (starlark.Value, error) {
	icmpHeader, err := value.packet.rawICMPv4()
	if err != nil {
		return nil, err
	}
	switch name {
	case "typeCode":
		typeCode := layers.CreateICMPv4TypeCode(uint8(icmpHeader.Type()), uint8(icmpHeader.Code()))
		return starlark.String(icmpTypeCodeText(typeCode)), nil
	case "type":
		return starlark.MakeUint64(uint64(icmpHeader.Type())), nil
	case "code":
		return starlark.MakeUint64(uint64(icmpHeader.Code())), nil
	case "checksum":
		return starlark.MakeUint64(uint64(icmpHeader.Checksum())), nil
	case "id":
		return starlark.MakeUint64(uint64(icmpHeader.Ident())), nil
	case "seq":
		return starlark.MakeUint64(uint64(icmpHeader.Sequence())), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setICMPv4Field(name string, fieldValue starlark.Value) error {
	icmpHeader, err := value.packet.rawICMPv4()
	if err != nil {
		return err
	}
	switch name {
	case "typeCode":
		typeCode, err := parseOptionalICMPTypeCode(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.typeCode: %w", err)
		}
		if typeCode == nil {
			return fmt.Errorf("packet.icmpv4.typeCode: value is required")
		}
		icmpHeader.SetType(header.ICMPv4Type(typeCode.Type()))
		icmpHeader.SetCode(header.ICMPv4Code(typeCode.Code()))
	case "type":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.type: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.type: value is required")
		}
		icmpHeader.SetType(header.ICMPv4Type(*number))
	case "code":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.code: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.code: value is required")
		}
		icmpHeader.SetCode(header.ICMPv4Code(*number))
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.checksum: value is required")
		}
		icmpHeader.SetChecksum(*number)
	case "id":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.id: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.id: value is required")
		}
		icmpHeader.SetIdent(*number)
	case "seq":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.icmpv4.seq: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.icmpv4.seq: value is required")
		}
		icmpHeader.SetSequence(*number)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyTransport
	return nil
}

func (value *mutableLayerValue) tcpAttr(name string) (starlark.Value, error) {
	tcpHeader, err := value.packet.rawTCP()
	if err != nil {
		return nil, err
	}
	switch name {
	case "srcPort":
		return starlark.MakeUint64(uint64(tcpHeader.SourcePort())), nil
	case "dstPort":
		return starlark.MakeUint64(uint64(tcpHeader.DestinationPort())), nil
	case "seq":
		return starlark.MakeUint64(uint64(tcpHeader.SequenceNumber())), nil
	case "ack":
		return starlark.MakeUint64(uint64(tcpHeader.AckNumber())), nil
	case "flags":
		return starlark.MakeUint64(uint64(tcpHeader.Flags())), nil
	case "window":
		return starlark.MakeUint64(uint64(tcpHeader.WindowSize())), nil
	case "checksum":
		return starlark.MakeUint64(uint64(tcpHeader.Checksum())), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setTCPField(name string, fieldValue starlark.Value) error {
	tcpHeader, err := value.packet.rawTCP()
	if err != nil {
		return err
	}
	switch name {
	case "srcPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.srcPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.srcPort: value is required")
		}
		tcpHeader.SetSourcePort(*number)
	case "dstPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.dstPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.dstPort: value is required")
		}
		tcpHeader.SetDestinationPort(*number)
	case "seq":
		number, err := integerValue(fieldValue)
		if err != nil || number < 0 || number > 0xffffffff {
			return fmt.Errorf("packet.tcp.seq: must be between 0 and 4294967295")
		}
		tcpHeader.SetSequenceNumber(uint32(number))
	case "ack":
		number, err := integerValue(fieldValue)
		if err != nil || number < 0 || number > 0xffffffff {
			return fmt.Errorf("packet.tcp.ack: must be between 0 and 4294967295")
		}
		tcpHeader.SetAckNumber(uint32(number))
	case "flags":
		number, err := parseOptionalUint8(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.flags: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.flags: value is required")
		}
		tcpHeader.SetFlags(*number)
	case "window":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.window: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.window: value is required")
		}
		tcpHeader.SetWindowSize(*number)
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.tcp.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.tcp.checksum: value is required")
		}
		tcpHeader.SetChecksum(*number)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyTransport
	return nil
}

func (value *mutableLayerValue) udpAttr(name string) (starlark.Value, error) {
	udpHeader, err := value.packet.rawUDP()
	if err != nil {
		return nil, err
	}
	switch name {
	case "srcPort":
		return starlark.MakeUint64(uint64(udpHeader.SourcePort())), nil
	case "dstPort":
		return starlark.MakeUint64(uint64(udpHeader.DestinationPort())), nil
	case "length":
		return starlark.MakeUint64(uint64(udpHeader.Length())), nil
	case "checksum":
		return starlark.MakeUint64(uint64(udpHeader.Checksum())), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableLayerValue) setUDPField(name string, fieldValue starlark.Value) error {
	udpHeader, err := value.packet.rawUDP()
	if err != nil {
		return err
	}
	switch name {
	case "srcPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.srcPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.srcPort: value is required")
		}
		udpHeader.SetSourcePort(*number)
	case "dstPort":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.dstPort: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.dstPort: value is required")
		}
		udpHeader.SetDestinationPort(*number)
	case "length":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.length: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.length: value is required")
		}
		udpHeader.SetLength(*number)
	case "checksum":
		number, err := parseOptionalUint16(fieldValue)
		if err != nil {
			return fmt.Errorf("packet.udp.checksum: %w", err)
		}
		if number == nil {
			return fmt.Errorf("packet.udp.checksum: value is required")
		}
		udpHeader.SetChecksum(*number)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	value.packet.dirty |= dirtyTransport
	return nil
}

func (value *mutableSerializationValue) String() string       { return "<packet.serialization>" }
func (value *mutableSerializationValue) Type() string         { return "packet.serialization" }
func (value *mutableSerializationValue) Freeze()              {}
func (value *mutableSerializationValue) Truth() starlark.Bool { return true }
func (value *mutableSerializationValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func (value *mutableSerializationValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "fixLengths":
		return starlark.Bool(value.packet.fixLengths), nil
	case "computeChecksums":
		return starlark.Bool(value.packet.computeChecksums), nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
	}
}

func (value *mutableSerializationValue) AttrNames() []string {
	return []string{"fixLengths", "computeChecksums"}
}

func (value *mutableSerializationValue) SetField(name string, fieldValue starlark.Value) error {
	boolean, err := parseOptionalBool(fieldValue)
	if err != nil {
		return fmt.Errorf("packet.serialization.%s: %w", name, err)
	}
	if boolean == nil {
		return fmt.Errorf("packet.serialization.%s: value is required", name)
	}
	switch name {
	case "fixLengths":
		value.packet.fixLengths = *boolean
	case "computeChecksums":
		value.packet.computeChecksums = *boolean
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("%s has no writable .%s attribute", value.Type(), name))
	}
	return nil
}

func (buffer *packetPayloadBuffer) Bytes() []byte {
	return buffer.packet.payloadBytes()
}

func (buffer *packetPayloadBuffer) String() string {
	return starlark.Bytes(string(buffer.Bytes())).String()
}

func (buffer *packetPayloadBuffer) Type() string         { return "kraken.bytes" }
func (buffer *packetPayloadBuffer) Freeze()              {}
func (buffer *packetPayloadBuffer) Truth() starlark.Bool { return len(buffer.Bytes()) > 0 }
func (buffer *packetPayloadBuffer) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", buffer.Type())
}

func (buffer *packetPayloadBuffer) Len() int {
	return len(buffer.Bytes())
}

func (buffer *packetPayloadBuffer) Index(index int) starlark.Value {
	return starlark.MakeInt(int(buffer.Bytes()[index]))
}

func (buffer *packetPayloadBuffer) Slice(start, end, step int) starlark.Value {
	data := buffer.Bytes()
	if step == 1 {
		return newOwnedByteBuffer(append([]byte(nil), data[start:end]...))
	}

	sign := 1
	if step < 0 {
		sign = -1
	}
	sliced := make([]byte, 0, max(0, end-start))
	for index := start; sign*(end-index) > 0; index += step {
		sliced = append(sliced, data[index])
	}
	return newOwnedByteBuffer(sliced)
}

func (buffer *packetPayloadBuffer) Iterate() starlark.Iterator {
	return &byteBufferIterator{data: buffer.Bytes()}
}

func (buffer *packetPayloadBuffer) SetIndex(index int, value starlark.Value) error {
	converted, err := byteValueFromStarlark(value)
	if err != nil {
		return err
	}
	payload := buffer.Bytes()
	payload[index] = converted
	buffer.packet.dirty |= dirtyPayload | dirtyTransport | dirtyNetwork
	return nil
}

func (buffer *packetPayloadBuffer) Has(value starlark.Value) (bool, error) {
	return newBorrowedByteBuffer(buffer.Bytes()).Has(value)
}
