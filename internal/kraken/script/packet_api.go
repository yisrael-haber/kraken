package script

import (
	"fmt"
	"net"
	"strings"

	"github.com/dop251/goja"
	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

func newPacketValue(vm *goja.Runtime, packet *packetpkg.OutboundPacket) (*goja.Object, error) {
	value := vm.NewObject()

	if packet == nil {
		return value, nil
	}

	if packet.Ethernet != nil {
		layer := vm.NewObject()
		_ = layer.Set("srcMAC", packet.Ethernet.SrcMAC.String())
		_ = layer.Set("dstMAC", packet.Ethernet.DstMAC.String())
		_ = value.Set("ethernet", layer)
	} else {
		_ = value.Set("ethernet", goja.Null())
	}

	if packet.IPv4 != nil {
		layer := vm.NewObject()
		_ = layer.Set("srcIP", common.IPString(packet.IPv4.SrcIP))
		_ = layer.Set("dstIP", common.IPString(packet.IPv4.DstIP))
		_ = layer.Set("ttl", int64(packet.IPv4.TTL))
		_ = layer.Set("tos", int64(packet.IPv4.TOS))
		_ = layer.Set("id", int64(packet.IPv4.Id))
		_ = value.Set("ipv4", layer)
	} else {
		_ = value.Set("ipv4", goja.Null())
	}

	if packet.ARP != nil {
		layer := vm.NewObject()
		_ = layer.Set("operation", int64(packet.ARP.Operation))
		_ = layer.Set("sourceHwAddress", net.HardwareAddr(packet.ARP.SourceHwAddress).String())
		_ = layer.Set("sourceProtAddress", common.IPString(net.IP(packet.ARP.SourceProtAddress)))
		_ = layer.Set("dstHwAddress", net.HardwareAddr(packet.ARP.DstHwAddress).String())
		_ = layer.Set("dstProtAddress", common.IPString(net.IP(packet.ARP.DstProtAddress)))
		_ = value.Set("arp", layer)
	} else {
		_ = value.Set("arp", goja.Null())
	}

	if packet.ICMPv4 != nil {
		layer := vm.NewObject()
		_ = layer.Set("typeCode", icmpTypeCodeText(packet.ICMPv4.TypeCode))
		_ = layer.Set("id", int64(packet.ICMPv4.Id))
		_ = layer.Set("seq", int64(packet.ICMPv4.Seq))
		_ = value.Set("icmpv4", layer)
	} else {
		_ = value.Set("icmpv4", goja.Null())
	}

	payloadValue, err := vm.New(vm.Get("Uint8Array"), vm.ToValue(vm.NewArrayBuffer(packet.Payload)))
	if err != nil {
		return nil, err
	}
	_ = value.Set("payload", payloadValue)

	return value, nil
}

func applyPacketValue(vm *goja.Runtime, value *goja.Object, packet *packetpkg.OutboundPacket) error {
	if packet == nil || value == nil {
		return nil
	}

	if err := applyEthernetValue(vm, value.Get("ethernet"), packet); err != nil {
		return err
	}
	if err := applyIPv4Value(vm, value.Get("ipv4"), packet); err != nil {
		return err
	}
	if err := applyARPValue(vm, value.Get("arp"), packet); err != nil {
		return err
	}
	if err := applyICMPValue(vm, value.Get("icmpv4"), packet); err != nil {
		return err
	}
	if err := applyPayloadValue(vm, value.Get("payload"), packet); err != nil {
		return err
	}

	syncPacketTypes(packet)
	return nil
}

func applyEthernetValue(vm *goja.Runtime, value goja.Value, packet *packetpkg.OutboundPacket) error {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		packet.Ethernet = nil
		return nil
	}

	object := value.ToObject(vm)
	if packet.Ethernet == nil {
		packet.Ethernet = &layers.Ethernet{}
	}

	srcMAC, err := parseOptionalMAC(object.Get("srcMAC"))
	if err != nil {
		return fmt.Errorf("packet.ethernet.srcMAC: %w", err)
	}
	dstMAC, err := parseOptionalMAC(object.Get("dstMAC"))
	if err != nil {
		return fmt.Errorf("packet.ethernet.dstMAC: %w", err)
	}

	packet.Ethernet.SrcMAC = srcMAC
	packet.Ethernet.DstMAC = dstMAC

	return nil
}

func applyIPv4Value(vm *goja.Runtime, value goja.Value, packet *packetpkg.OutboundPacket) error {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		packet.IPv4 = nil
		return nil
	}

	object := value.ToObject(vm)
	if packet.IPv4 == nil {
		packet.IPv4 = &layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolICMPv4,
		}
	}

	srcIP, err := parseOptionalIPv4(object.Get("srcIP"))
	if err != nil {
		return fmt.Errorf("packet.ipv4.srcIP: %w", err)
	}
	dstIP, err := parseOptionalIPv4(object.Get("dstIP"))
	if err != nil {
		return fmt.Errorf("packet.ipv4.dstIP: %w", err)
	}
	ttl, err := parseOptionalUint8(object.Get("ttl"))
	if err != nil {
		return fmt.Errorf("packet.ipv4.ttl: %w", err)
	}
	tos, err := parseOptionalUint8(object.Get("tos"))
	if err != nil {
		return fmt.Errorf("packet.ipv4.tos: %w", err)
	}
	id, err := parseOptionalUint16(object.Get("id"))
	if err != nil {
		return fmt.Errorf("packet.ipv4.id: %w", err)
	}

	packet.IPv4.SrcIP = srcIP
	packet.IPv4.DstIP = dstIP
	if ttl != nil {
		packet.IPv4.TTL = *ttl
	}
	if tos != nil {
		packet.IPv4.TOS = *tos
	}
	if id != nil {
		packet.IPv4.Id = *id
	}
	packet.IPv4.Version = 4
	packet.IPv4.Protocol = layers.IPProtocolICMPv4

	return nil
}

func applyARPValue(vm *goja.Runtime, value goja.Value, packet *packetpkg.OutboundPacket) error {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		packet.ARP = nil
		return nil
	}

	object := value.ToObject(vm)
	if packet.ARP == nil {
		packet.ARP = &layers.ARP{
			AddrType:        layers.LinkTypeEthernet,
			Protocol:        layers.EthernetTypeIPv4,
			HwAddressSize:   6,
			ProtAddressSize: 4,
		}
	}

	operation, err := parseOptionalUint16(object.Get("operation"))
	if err != nil {
		return fmt.Errorf("packet.arp.operation: %w", err)
	}
	sourceMAC, err := parseOptionalMAC(object.Get("sourceHwAddress"))
	if err != nil {
		return fmt.Errorf("packet.arp.sourceHwAddress: %w", err)
	}
	sourceIP, err := parseOptionalIPv4(object.Get("sourceProtAddress"))
	if err != nil {
		return fmt.Errorf("packet.arp.sourceProtAddress: %w", err)
	}
	dstMAC, err := parseOptionalMAC(object.Get("dstHwAddress"))
	if err != nil {
		return fmt.Errorf("packet.arp.dstHwAddress: %w", err)
	}
	dstIP, err := parseOptionalIPv4(object.Get("dstProtAddress"))
	if err != nil {
		return fmt.Errorf("packet.arp.dstProtAddress: %w", err)
	}

	if operation != nil {
		packet.ARP.Operation = *operation
	}
	packet.ARP.SourceHwAddress = sourceMAC
	packet.ARP.SourceProtAddress = sourceIP
	packet.ARP.DstHwAddress = dstMAC
	packet.ARP.DstProtAddress = dstIP
	packet.ARP.AddrType = layers.LinkTypeEthernet
	packet.ARP.Protocol = layers.EthernetTypeIPv4
	packet.ARP.HwAddressSize = 6
	packet.ARP.ProtAddressSize = 4

	return nil
}

func applyICMPValue(vm *goja.Runtime, value goja.Value, packet *packetpkg.OutboundPacket) error {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		packet.ICMPv4 = nil
		return nil
	}

	object := value.ToObject(vm)
	if packet.ICMPv4 == nil {
		packet.ICMPv4 = &layers.ICMPv4{}
	}

	typeCode, err := parseOptionalICMPTypeCode(object.Get("typeCode"))
	if err != nil {
		return fmt.Errorf("packet.icmpv4.typeCode: %w", err)
	}
	id, err := parseOptionalUint16(object.Get("id"))
	if err != nil {
		return fmt.Errorf("packet.icmpv4.id: %w", err)
	}
	seq, err := parseOptionalUint16(object.Get("seq"))
	if err != nil {
		return fmt.Errorf("packet.icmpv4.seq: %w", err)
	}

	if typeCode != nil {
		packet.ICMPv4.TypeCode = *typeCode
	}
	if id != nil {
		packet.ICMPv4.Id = *id
	}
	if seq != nil {
		packet.ICMPv4.Seq = *seq
	}

	return nil
}

func applyPayloadValue(vm *goja.Runtime, value goja.Value, packet *packetpkg.OutboundPacket) error {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		packet.Payload = nil
		return nil
	}

	var payload []byte
	if err := vm.ExportTo(value, &payload); err != nil {
		return fmt.Errorf("packet.payload: %w", err)
	}
	packet.Payload = payload
	return nil
}

func newContextValue(vm *goja.Runtime, ctx ExecutionContext) *goja.Object {
	value := vm.NewObject()
	_ = value.Set("scriptName", ctx.ScriptName)
	_ = value.Set("sendPath", ctx.SendPath)
	_ = value.Set("protocol", ctx.Protocol)

	adopted := vm.NewObject()
	_ = adopted.Set("label", ctx.Adopted.Label)
	_ = adopted.Set("ip", ctx.Adopted.IP)
	_ = adopted.Set("mac", ctx.Adopted.MAC)
	_ = adopted.Set("interfaceName", ctx.Adopted.InterfaceName)
	_ = adopted.Set("defaultGateway", ctx.Adopted.DefaultGateway)
	_ = value.Set("adopted", adopted)

	if len(ctx.Metadata) != 0 {
		_ = value.Set("metadata", ctx.Metadata)
	}

	return value
}

func parseOptionalMAC(value goja.Value) (net.HardwareAddr, error) {
	text := stringsFromValue(value)
	if text == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(text)
	if err != nil {
		return nil, err
	}
	return mac, nil
}

func parseOptionalIPv4(value goja.Value) (net.IP, error) {
	text := stringsFromValue(value)
	if text == "" {
		return nil, nil
	}
	return common.NormalizeAdoptionIP(text)
}

func parseOptionalUint8(value goja.Value) (*uint8, error) {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		return nil, nil
	}
	number := value.ToInteger()
	if number < 0 || number > 255 {
		return nil, fmt.Errorf("must be between 0 and 255")
	}
	converted := uint8(number)
	return &converted, nil
}

func parseOptionalUint16(value goja.Value) (*uint16, error) {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		return nil, nil
	}
	number := value.ToInteger()
	if number < 0 || number > 65535 {
		return nil, fmt.Errorf("must be between 0 and 65535")
	}
	converted := uint16(number)
	return &converted, nil
}

func parseOptionalICMPTypeCode(value goja.Value) (*layers.ICMPv4TypeCode, error) {
	text := stringsFromValue(value)
	if text == "" {
		return nil, nil
	}

	var typeCode layers.ICMPv4TypeCode
	switch text {
	case "EchoRequest":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	case "EchoReply":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)
	default:
		return nil, fmt.Errorf("unsupported type code %q", text)
	}

	return &typeCode, nil
}

func icmpTypeCodeText(typeCode layers.ICMPv4TypeCode) string {
	switch typeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		return "EchoRequest"
	case layers.ICMPv4TypeEchoReply:
		return "EchoReply"
	default:
		return typeCode.String()
	}
}

func stringsFromValue(value goja.Value) string {
	if goja.IsNull(value) || goja.IsUndefined(value) {
		return ""
	}

	return strings.TrimSpace(value.String())
}

func syncPacketTypes(packet *packetpkg.OutboundPacket) {
	if packet == nil {
		return
	}

	if packet.Ethernet != nil {
		if packet.ARP != nil {
			packet.Ethernet.EthernetType = layers.EthernetTypeARP
		} else {
			packet.Ethernet.EthernetType = layers.EthernetTypeIPv4
		}
	}
	if packet.IPv4 != nil {
		packet.IPv4.Version = 4
		packet.IPv4.Protocol = layers.IPProtocolICMPv4
	}
	if packet.ARP != nil {
		packet.ARP.AddrType = layers.LinkTypeEthernet
		packet.ARP.Protocol = layers.EthernetTypeIPv4
		packet.ARP.HwAddressSize = 6
		packet.ARP.ProtAddressSize = 4
	}
}
