package script

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func newPacketValue(packet *packetpkg.OutboundPacket) (*scriptObject, error) {
	if packet == nil {
		return newScriptObject("packet", true, starlark.StringDict{
			"ethernet":      starlark.None,
			"ipv4":          starlark.None,
			"arp":           starlark.None,
			"icmpv4":        starlark.None,
			"payload":       newBorrowedByteBuffer(nil),
			"serialization": newSerializationValue(packetpkg.PacketSerializationOptions{}),
		}), nil
	}

	return newScriptObject("packet", true, starlark.StringDict{
		"ethernet":      newEthernetValue(packet.Ethernet),
		"ipv4":          newIPv4Value(packet.IPv4),
		"arp":           newARPValue(packet.ARP),
		"icmpv4":        newICMPValue(packet.ICMPv4),
		"payload":       newBorrowedByteBuffer(packet.Payload),
		"serialization": newSerializationValue(packet.SerializationOptions()),
	}), nil
}

func newEthernetValue(layer *layers.Ethernet) starlark.Value {
	if layer == nil {
		return starlark.None
	}

	return newScriptObject("packet.ethernet", true, starlark.StringDict{
		"srcMAC":       starlark.String(layer.SrcMAC.String()),
		"dstMAC":       starlark.String(layer.DstMAC.String()),
		"ethernetType": starlark.MakeUint64(uint64(layer.EthernetType)),
		"length":       starlark.MakeUint64(uint64(layer.Length)),
	})
}

func newIPv4Value(layer *layers.IPv4) starlark.Value {
	if layer == nil {
		return starlark.None
	}

	options := make([]starlark.Value, 0, len(layer.Options))
	for _, option := range layer.Options {
		options = append(options, newScriptObject("packet.ipv4.option", true, starlark.StringDict{
			"optionType":   starlark.MakeUint64(uint64(option.OptionType)),
			"optionLength": starlark.MakeUint64(uint64(option.OptionLength)),
			"optionData":   newBorrowedByteBuffer(option.OptionData),
		}))
	}

	return newScriptObject("packet.ipv4", true, starlark.StringDict{
		"srcIP":      starlark.String(common.IPString(layer.SrcIP)),
		"dstIP":      starlark.String(common.IPString(layer.DstIP)),
		"version":    starlark.MakeUint64(uint64(layer.Version)),
		"ihl":        starlark.MakeUint64(uint64(layer.IHL)),
		"tos":        starlark.MakeUint64(uint64(layer.TOS)),
		"length":     starlark.MakeUint64(uint64(layer.Length)),
		"id":         starlark.MakeUint64(uint64(layer.Id)),
		"flags":      starlark.MakeUint64(uint64(layer.Flags)),
		"fragOffset": starlark.MakeUint64(uint64(layer.FragOffset)),
		"ttl":        starlark.MakeUint64(uint64(layer.TTL)),
		"protocol":   starlark.MakeUint64(uint64(layer.Protocol)),
		"checksum":   starlark.MakeUint64(uint64(layer.Checksum)),
		"options":    starlark.NewList(options),
		"padding":    newBorrowedByteBuffer(layer.Padding),
	})
}

func newARPValue(layer *layers.ARP) starlark.Value {
	if layer == nil {
		return starlark.None
	}

	return newScriptObject("packet.arp", true, starlark.StringDict{
		"addrType":          starlark.MakeUint64(uint64(layer.AddrType)),
		"protocol":          starlark.MakeUint64(uint64(layer.Protocol)),
		"hwAddressSize":     starlark.MakeUint64(uint64(layer.HwAddressSize)),
		"protAddressSize":   starlark.MakeUint64(uint64(layer.ProtAddressSize)),
		"operation":         starlark.MakeUint64(uint64(layer.Operation)),
		"sourceHwAddress":   starlark.String(formatScriptHardwareAddress(layer.SourceHwAddress)),
		"sourceProtAddress": starlark.String(formatScriptProtocolAddress(layer.SourceProtAddress)),
		"dstHwAddress":      starlark.String(formatScriptHardwareAddress(layer.DstHwAddress)),
		"dstProtAddress":    starlark.String(formatScriptProtocolAddress(layer.DstProtAddress)),
	})
}

func newICMPValue(layer *layers.ICMPv4) starlark.Value {
	if layer == nil {
		return starlark.None
	}

	return newScriptObject("packet.icmpv4", true, starlark.StringDict{
		"typeCode": starlark.String(icmpTypeCodeText(layer.TypeCode)),
		"type":     starlark.MakeUint64(uint64(layer.TypeCode.Type())),
		"code":     starlark.MakeUint64(uint64(layer.TypeCode.Code())),
		"checksum": starlark.MakeUint64(uint64(layer.Checksum)),
		"id":       starlark.MakeUint64(uint64(layer.Id)),
		"seq":      starlark.MakeUint64(uint64(layer.Seq)),
	})
}

func newSerializationValue(options packetpkg.PacketSerializationOptions) starlark.Value {
	return newScriptObject("packet.serialization", true, starlark.StringDict{
		"fixLengths":       starlark.Bool(options.FixLengths),
		"computeChecksums": starlark.Bool(options.ComputeChecksums),
	})
}

func applyPacketValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if packet == nil || isNone(value) {
		return nil
	}

	ethernetValue, err := attrValue(value, "ethernet")
	if err != nil {
		return fmt.Errorf("packet.ethernet: %w", err)
	}
	if err := applyEthernetValue(ethernetValue, packet); err != nil {
		return err
	}

	ipv4Value, err := attrValue(value, "ipv4")
	if err != nil {
		return fmt.Errorf("packet.ipv4: %w", err)
	}
	if err := applyIPv4Value(ipv4Value, packet); err != nil {
		return err
	}

	arpValue, err := attrValue(value, "arp")
	if err != nil {
		return fmt.Errorf("packet.arp: %w", err)
	}
	if err := applyARPValue(arpValue, packet); err != nil {
		return err
	}

	icmpValue, err := attrValue(value, "icmpv4")
	if err != nil {
		return fmt.Errorf("packet.icmpv4: %w", err)
	}
	if err := applyICMPValue(icmpValue, packet); err != nil {
		return err
	}

	payloadValue, err := attrValue(value, "payload")
	if err != nil {
		return fmt.Errorf("packet.payload: %w", err)
	}
	if err := applyPayloadValue(payloadValue, packet); err != nil {
		return err
	}

	serializationValue, err := attrValue(value, "serialization")
	if err != nil {
		return fmt.Errorf("packet.serialization: %w", err)
	}
	if err := applySerializationValue(serializationValue, packet); err != nil {
		return err
	}

	return nil
}

func applyEthernetValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		packet.Ethernet = nil
		return nil
	}

	if packet.Ethernet == nil {
		packet.Ethernet = &layers.Ethernet{}
	}

	srcMACValue, err := attrOrNone(value, "srcMAC")
	if err != nil {
		return fmt.Errorf("packet.ethernet.srcMAC: %w", err)
	}
	srcMAC, err := parseScriptHardwareAddr(srcMACValue, 6)
	if err != nil {
		return fmt.Errorf("packet.ethernet.srcMAC: %w", err)
	}
	dstMACValue, err := attrOrNone(value, "dstMAC")
	if err != nil {
		return fmt.Errorf("packet.ethernet.dstMAC: %w", err)
	}
	dstMAC, err := parseScriptHardwareAddr(dstMACValue, 6)
	if err != nil {
		return fmt.Errorf("packet.ethernet.dstMAC: %w", err)
	}
	ethernetTypeValue, err := attrOrNone(value, "ethernetType")
	if err != nil {
		return fmt.Errorf("packet.ethernet.ethernetType: %w", err)
	}
	ethernetType, err := parseOptionalUint16(ethernetTypeValue)
	if err != nil {
		return fmt.Errorf("packet.ethernet.ethernetType: %w", err)
	}
	lengthValue, err := attrOrNone(value, "length")
	if err != nil {
		return fmt.Errorf("packet.ethernet.length: %w", err)
	}
	length, err := parseOptionalUint16(lengthValue)
	if err != nil {
		return fmt.Errorf("packet.ethernet.length: %w", err)
	}

	packet.Ethernet.SrcMAC = srcMAC
	packet.Ethernet.DstMAC = dstMAC
	packet.Ethernet.EthernetType = layers.EthernetType(valueOrZeroUint16(ethernetType))
	packet.Ethernet.Length = valueOrZeroUint16(length)
	return nil
}

func applyIPv4Value(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		packet.IPv4 = nil
		return nil
	}

	if packet.IPv4 == nil {
		packet.IPv4 = &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
		}
	}

	srcIPValue, err := attrOrNone(value, "srcIP")
	if err != nil {
		return fmt.Errorf("packet.ipv4.srcIP: %w", err)
	}
	srcIP, err := parseScriptIPv4(srcIPValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.srcIP: %w", err)
	}
	dstIPValue, err := attrOrNone(value, "dstIP")
	if err != nil {
		return fmt.Errorf("packet.ipv4.dstIP: %w", err)
	}
	dstIP, err := parseScriptIPv4(dstIPValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.dstIP: %w", err)
	}
	versionValue, err := attrOrNone(value, "version")
	if err != nil {
		return fmt.Errorf("packet.ipv4.version: %w", err)
	}
	version, err := parseOptionalUint8Range(versionValue, 0, 15)
	if err != nil {
		return fmt.Errorf("packet.ipv4.version: %w", err)
	}
	ihlValue, err := attrOrNone(value, "ihl")
	if err != nil {
		return fmt.Errorf("packet.ipv4.ihl: %w", err)
	}
	ihl, err := parseOptionalUint8Range(ihlValue, 0, 15)
	if err != nil {
		return fmt.Errorf("packet.ipv4.ihl: %w", err)
	}
	tosValue, err := attrOrNone(value, "tos")
	if err != nil {
		return fmt.Errorf("packet.ipv4.tos: %w", err)
	}
	tos, err := parseOptionalUint8(tosValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.tos: %w", err)
	}
	lengthValue, err := attrOrNone(value, "length")
	if err != nil {
		return fmt.Errorf("packet.ipv4.length: %w", err)
	}
	length, err := parseOptionalUint16(lengthValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.length: %w", err)
	}
	idValue, err := attrOrNone(value, "id")
	if err != nil {
		return fmt.Errorf("packet.ipv4.id: %w", err)
	}
	id, err := parseOptionalUint16(idValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.id: %w", err)
	}
	flagsValue, err := attrOrNone(value, "flags")
	if err != nil {
		return fmt.Errorf("packet.ipv4.flags: %w", err)
	}
	flags, err := parseOptionalUint8Range(flagsValue, 0, 7)
	if err != nil {
		return fmt.Errorf("packet.ipv4.flags: %w", err)
	}
	fragOffsetValue, err := attrOrNone(value, "fragOffset")
	if err != nil {
		return fmt.Errorf("packet.ipv4.fragOffset: %w", err)
	}
	fragOffset, err := parseOptionalUint16Range(fragOffsetValue, 0, 8191)
	if err != nil {
		return fmt.Errorf("packet.ipv4.fragOffset: %w", err)
	}
	ttlValue, err := attrOrNone(value, "ttl")
	if err != nil {
		return fmt.Errorf("packet.ipv4.ttl: %w", err)
	}
	ttl, err := parseOptionalUint8(ttlValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.ttl: %w", err)
	}
	protocolValue, err := attrOrNone(value, "protocol")
	if err != nil {
		return fmt.Errorf("packet.ipv4.protocol: %w", err)
	}
	protocol, err := parseOptionalUint8(protocolValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.protocol: %w", err)
	}
	checksumValue, err := attrOrNone(value, "checksum")
	if err != nil {
		return fmt.Errorf("packet.ipv4.checksum: %w", err)
	}
	checksum, err := parseOptionalUint16(checksumValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.checksum: %w", err)
	}
	optionsValue, err := attrOrNone(value, "options")
	if err != nil {
		return fmt.Errorf("packet.ipv4.options: %w", err)
	}
	options, err := parseIPv4OptionsValue(optionsValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.options: %w", err)
	}
	paddingValue, err := attrOrNone(value, "padding")
	if err != nil {
		return fmt.Errorf("packet.ipv4.padding: %w", err)
	}
	padding, err := parseOptionalBytes(paddingValue)
	if err != nil {
		return fmt.Errorf("packet.ipv4.padding: %w", err)
	}

	packet.IPv4.SrcIP = srcIP
	packet.IPv4.DstIP = dstIP
	packet.IPv4.Version = valueOrZeroUint8(version)
	packet.IPv4.IHL = valueOrZeroUint8(ihl)
	packet.IPv4.TOS = valueOrZeroUint8(tos)
	packet.IPv4.Length = valueOrZeroUint16(length)
	packet.IPv4.Id = valueOrZeroUint16(id)
	packet.IPv4.Flags = layers.IPv4Flag(valueOrZeroUint8(flags))
	packet.IPv4.FragOffset = valueOrZeroUint16(fragOffset)
	packet.IPv4.TTL = valueOrZeroUint8(ttl)
	packet.IPv4.Protocol = layers.IPProtocol(valueOrZeroUint8(protocol))
	packet.IPv4.Checksum = valueOrZeroUint16(checksum)
	packet.IPv4.Options = options
	packet.IPv4.Padding = padding
	return nil
}

func applyARPValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		packet.ARP = nil
		return nil
	}

	if packet.ARP == nil {
		packet.ARP = &layers.ARP{}
	}

	addrTypeValue, err := attrOrNone(value, "addrType")
	if err != nil {
		return fmt.Errorf("packet.arp.addrType: %w", err)
	}
	addrType, err := parseOptionalUint16(addrTypeValue)
	if err != nil {
		return fmt.Errorf("packet.arp.addrType: %w", err)
	}
	protocolValue, err := attrOrNone(value, "protocol")
	if err != nil {
		return fmt.Errorf("packet.arp.protocol: %w", err)
	}
	protocol, err := parseOptionalUint16(protocolValue)
	if err != nil {
		return fmt.Errorf("packet.arp.protocol: %w", err)
	}
	hwAddressSizeValue, err := attrOrNone(value, "hwAddressSize")
	if err != nil {
		return fmt.Errorf("packet.arp.hwAddressSize: %w", err)
	}
	hwAddressSize, err := parseOptionalUint8(hwAddressSizeValue)
	if err != nil {
		return fmt.Errorf("packet.arp.hwAddressSize: %w", err)
	}
	protAddressSizeValue, err := attrOrNone(value, "protAddressSize")
	if err != nil {
		return fmt.Errorf("packet.arp.protAddressSize: %w", err)
	}
	protAddressSize, err := parseOptionalUint8(protAddressSizeValue)
	if err != nil {
		return fmt.Errorf("packet.arp.protAddressSize: %w", err)
	}
	operationValue, err := attrOrNone(value, "operation")
	if err != nil {
		return fmt.Errorf("packet.arp.operation: %w", err)
	}
	operation, err := parseOptionalUint16(operationValue)
	if err != nil {
		return fmt.Errorf("packet.arp.operation: %w", err)
	}
	sourceMACValue, err := attrOrNone(value, "sourceHwAddress")
	if err != nil {
		return fmt.Errorf("packet.arp.sourceHwAddress: %w", err)
	}
	sourceMAC, err := parseScriptHardwareAddr(sourceMACValue, 0)
	if err != nil {
		return fmt.Errorf("packet.arp.sourceHwAddress: %w", err)
	}
	sourceIPValue, err := attrOrNone(value, "sourceProtAddress")
	if err != nil {
		return fmt.Errorf("packet.arp.sourceProtAddress: %w", err)
	}
	sourceIP, err := parseScriptProtocolAddress(sourceIPValue)
	if err != nil {
		return fmt.Errorf("packet.arp.sourceProtAddress: %w", err)
	}
	dstMACValue, err := attrOrNone(value, "dstHwAddress")
	if err != nil {
		return fmt.Errorf("packet.arp.dstHwAddress: %w", err)
	}
	dstMAC, err := parseScriptHardwareAddr(dstMACValue, 0)
	if err != nil {
		return fmt.Errorf("packet.arp.dstHwAddress: %w", err)
	}
	dstIPValue, err := attrOrNone(value, "dstProtAddress")
	if err != nil {
		return fmt.Errorf("packet.arp.dstProtAddress: %w", err)
	}
	dstIP, err := parseScriptProtocolAddress(dstIPValue)
	if err != nil {
		return fmt.Errorf("packet.arp.dstProtAddress: %w", err)
	}

	packet.ARP.AddrType = layers.LinkType(valueOrZeroUint16(addrType))
	packet.ARP.Protocol = layers.EthernetType(valueOrZeroUint16(protocol))
	packet.ARP.HwAddressSize = valueOrZeroUint8(hwAddressSize)
	packet.ARP.ProtAddressSize = valueOrZeroUint8(protAddressSize)
	packet.ARP.Operation = valueOrZeroUint16(operation)
	packet.ARP.SourceHwAddress = sourceMAC
	packet.ARP.SourceProtAddress = sourceIP
	packet.ARP.DstHwAddress = dstMAC
	packet.ARP.DstProtAddress = dstIP
	return nil
}

func applyICMPValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		packet.ICMPv4 = nil
		return nil
	}

	if packet.ICMPv4 == nil {
		packet.ICMPv4 = &layers.ICMPv4{}
	}

	originalType := packet.ICMPv4.TypeCode.Type()
	originalCode := packet.ICMPv4.TypeCode.Code()

	typeCodeValue, err := attrOrNone(value, "typeCode")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.typeCode: %w", err)
	}
	typeCode, err := parseOptionalICMPTypeCode(typeCodeValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.typeCode: %w", err)
	}
	icmpTypeValue, err := attrOrNone(value, "type")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.type: %w", err)
	}
	icmpType, err := parseOptionalUint8(icmpTypeValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.type: %w", err)
	}
	icmpCodeValue, err := attrOrNone(value, "code")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.code: %w", err)
	}
	icmpCode, err := parseOptionalUint8(icmpCodeValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.code: %w", err)
	}
	checksumValue, err := attrOrNone(value, "checksum")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.checksum: %w", err)
	}
	checksum, err := parseOptionalUint16(checksumValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.checksum: %w", err)
	}
	idValue, err := attrOrNone(value, "id")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.id: %w", err)
	}
	id, err := parseOptionalUint16(idValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.id: %w", err)
	}
	seqValue, err := attrOrNone(value, "seq")
	if err != nil {
		return fmt.Errorf("packet.icmpv4.seq: %w", err)
	}
	seq, err := parseOptionalUint16(seqValue)
	if err != nil {
		return fmt.Errorf("packet.icmpv4.seq: %w", err)
	}

	if typeCode != nil {
		packet.ICMPv4.TypeCode = *typeCode
	}
	if typeCode != nil {
		if icmpType != nil && *icmpType == originalType {
			icmpType = nil
		}
		if icmpCode != nil && *icmpCode == originalCode {
			icmpCode = nil
		}
	}
	if icmpType != nil || icmpCode != nil {
		typeValue := packet.ICMPv4.TypeCode.Type()
		codeValue := packet.ICMPv4.TypeCode.Code()
		if icmpType != nil {
			typeValue = *icmpType
		}
		if icmpCode != nil {
			codeValue = *icmpCode
		}
		packet.ICMPv4.TypeCode = layers.CreateICMPv4TypeCode(typeValue, codeValue)
	}

	packet.ICMPv4.Checksum = valueOrZeroUint16(checksum)
	packet.ICMPv4.Id = valueOrZeroUint16(id)
	packet.ICMPv4.Seq = valueOrZeroUint16(seq)
	return nil
}

func applyPayloadValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		packet.Payload = nil
		return nil
	}

	payload, err := parseOptionalBytes(value)
	if err != nil {
		return fmt.Errorf("packet.payload: %w", err)
	}
	packet.Payload = payload
	return nil
}

func applySerializationValue(value starlark.Value, packet *packetpkg.OutboundPacket) error {
	if isNone(value) {
		return nil
	}

	fixLengthsValue, err := attrOrNone(value, "fixLengths")
	if err != nil {
		return fmt.Errorf("packet.serialization.fixLengths: %w", err)
	}
	fixLengths, err := parseOptionalBool(fixLengthsValue)
	if err != nil {
		return fmt.Errorf("packet.serialization.fixLengths: %w", err)
	}
	computeChecksumsValue, err := attrOrNone(value, "computeChecksums")
	if err != nil {
		return fmt.Errorf("packet.serialization.computeChecksums: %w", err)
	}
	computeChecksums, err := parseOptionalBool(computeChecksumsValue)
	if err != nil {
		return fmt.Errorf("packet.serialization.computeChecksums: %w", err)
	}

	packet.SetSerializationOptions(packetpkg.PacketSerializationOptions{
		FixLengths:       valueOrFalse(fixLengths),
		ComputeChecksums: valueOrFalse(computeChecksums),
	})
	return nil
}

func newContextValue(ctx ExecutionContext) (starlark.Value, error) {
	adopted := starlark.StringDict{
		"label":          starlark.String(ctx.Adopted.Label),
		"ip":             starlark.String(ctx.Adopted.IP),
		"mac":            starlark.String(ctx.Adopted.MAC),
		"interfaceName":  starlark.String(ctx.Adopted.InterfaceName),
		"defaultGateway": starlark.String(ctx.Adopted.DefaultGateway),
		"mtu":            starlark.MakeInt(ctx.Adopted.MTU),
	}

	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted":    starlarkstruct.FromStringDict(starlarkstruct.Default, adopted),
		"metadata":   starlark.None,
	}

	if len(ctx.Metadata) != 0 {
		metadata, err := toStarlarkValue(ctx.Metadata)
		if err != nil {
			return nil, fmt.Errorf("ctx.metadata: %w", err)
		}
		fields["metadata"] = metadata
	}

	return starlarkstruct.FromStringDict(starlarkstruct.Default, fields), nil
}

func attrOrNone(value starlark.Value, name string) (starlark.Value, error) {
	attr, err := attrValue(value, name)
	if err != nil {
		if isNone(value) || isNoSuchAttr(err) {
			return starlark.None, nil
		}
		return nil, err
	}
	return attr, nil
}

func isNoSuchAttr(err error) bool {
	var noSuchAttr starlark.NoSuchAttrError
	return errors.As(err, &noSuchAttr)
}

func parseScriptHardwareAddr(value starlark.Value, expectedLength int) ([]byte, error) {
	if text, ok := starlark.AsString(value); ok {
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		if mac, err := net.ParseMAC(strings.TrimSpace(text)); err == nil {
			if expectedLength != 0 && len(mac) != expectedLength {
				return nil, fmt.Errorf("must contain %d bytes", expectedLength)
			}
			return append([]byte(nil), mac...), nil
		}

		payload, err := packetpkg.ParsePayloadHex(text)
		if err != nil {
			return nil, err
		}
		if expectedLength != 0 && len(payload) != expectedLength {
			return nil, fmt.Errorf("must contain %d bytes", expectedLength)
		}
		return payload, nil
	}

	payload, err := parseOptionalBytes(value)
	if err != nil {
		return nil, err
	}
	if expectedLength != 0 && len(payload) != expectedLength {
		return nil, fmt.Errorf("must contain %d bytes", expectedLength)
	}
	return payload, nil
}

func parseScriptIPv4(value starlark.Value) (net.IP, error) {
	if text, ok := starlark.AsString(value); ok {
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		if ip, err := common.NormalizeAdoptionIP(text); err == nil {
			return ip, nil
		}
		payload, err := packetpkg.ParsePayloadHex(text)
		if err != nil {
			return nil, err
		}
		if len(payload) != 4 {
			return nil, fmt.Errorf("must contain exactly 4 bytes")
		}
		return net.IP(payload), nil
	}

	payload, err := parseOptionalBytes(value)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload) != 4 {
		return nil, fmt.Errorf("must contain exactly 4 bytes")
	}
	return net.IP(payload), nil
}

func parseScriptProtocolAddress(value starlark.Value) ([]byte, error) {
	if text, ok := starlark.AsString(value); ok {
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		if ip, err := common.NormalizeAdoptionIP(text); err == nil {
			return append([]byte(nil), ip...), nil
		}
		return packetpkg.ParsePayloadHex(text)
	}

	return parseOptionalBytes(value)
}

func parseIPv4OptionsValue(value starlark.Value) ([]layers.IPv4Option, error) {
	if isNone(value) {
		return nil, nil
	}

	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("packet.ipv4.options: must be a sequence")
	}

	iterator := iterable.Iterate()
	defer iterator.Done()

	options := make([]layers.IPv4Option, 0, max(0, starlark.Len(value)))
	var item starlark.Value
	for index := 0; iterator.Next(&item); index++ {
		if isNone(item) {
			return nil, fmt.Errorf("packet.ipv4.options[%d]: entry is required", index)
		}

		optionTypeValue, err := attrOrNone(item, "optionType")
		if err != nil {
			return nil, fmt.Errorf("[%d].optionType: %w", index, err)
		}
		optionType, err := parseOptionalUint8(optionTypeValue)
		if err != nil {
			return nil, fmt.Errorf("[%d].optionType: %w", index, err)
		}
		if optionType == nil {
			return nil, fmt.Errorf("[%d].optionType: value is required", index)
		}

		optionLengthValue, err := attrOrNone(item, "optionLength")
		if err != nil {
			return nil, fmt.Errorf("[%d].optionLength: %w", index, err)
		}
		optionLength, err := parseOptionalUint8(optionLengthValue)
		if err != nil {
			return nil, fmt.Errorf("[%d].optionLength: %w", index, err)
		}
		optionDataValue, err := attrOrNone(item, "optionData")
		if err != nil {
			return nil, fmt.Errorf("[%d].optionData: %w", index, err)
		}
		optionData, err := parseOptionalBytes(optionDataValue)
		if err != nil {
			return nil, fmt.Errorf("[%d].optionData: %w", index, err)
		}

		option := layers.IPv4Option{
			OptionType: *optionType,
			OptionData: optionData,
		}
		if optionLength != nil {
			option.OptionLength = *optionLength
		} else if option.OptionType > 1 {
			option.OptionLength = uint8(len(option.OptionData) + 2)
		}
		options = append(options, option)
	}

	return options, nil
}

func parseOptionalBytes(value starlark.Value) ([]byte, error) {
	if isNone(value) {
		return nil, nil
	}

	payload, err := byteSliceFromValue(value)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func parseOptionalUint8(value starlark.Value) (*uint8, error) {
	return parseOptionalUint8Range(value, 0, 255)
}

func parseOptionalUint8Range(value starlark.Value, min, max int64) (*uint8, error) {
	if isNone(value) {
		return nil, nil
	}
	number, err := integerValue(value)
	if err != nil {
		return nil, err
	}
	if number < min || number > max {
		return nil, fmt.Errorf("must be between %d and %d", min, max)
	}
	converted := uint8(number)
	return &converted, nil
}

func parseOptionalUint16(value starlark.Value) (*uint16, error) {
	return parseOptionalUint16Range(value, 0, 65535)
}

func parseOptionalUint16Range(value starlark.Value, min, max int64) (*uint16, error) {
	if isNone(value) {
		return nil, nil
	}
	number, err := integerValue(value)
	if err != nil {
		return nil, err
	}
	if number < min || number > max {
		return nil, fmt.Errorf("must be between %d and %d", min, max)
	}
	converted := uint16(number)
	return &converted, nil
}

func parseOptionalBool(value starlark.Value) (*bool, error) {
	if isNone(value) {
		return nil, nil
	}
	boolean, ok := value.(starlark.Bool)
	if !ok {
		return nil, fmt.Errorf("must be a boolean")
	}
	converted := bool(boolean)
	return &converted, nil
}

func parseOptionalICMPTypeCode(value starlark.Value) (*layers.ICMPv4TypeCode, error) {
	text := stringValue(value)
	if text == "" {
		return nil, nil
	}

	var typeCode layers.ICMPv4TypeCode
	switch text {
	case "EchoRequest":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	case "EchoReply":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)
	case "TimestampRequest":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampRequest, 0)
	case "TimestampReply":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampReply, 0)
	case "AddressMaskRequest":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeAddressMaskRequest, 0)
	case "AddressMaskReply":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeAddressMaskReply, 0)
	case "RouterSolicitation":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRouterSolicitation, 0)
	case "RouterAdvertisement":
		typeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRouterAdvertisement, 0)
	default:
		parts := strings.Fields(strings.NewReplacer("/", " ", ":", " ", ",", " ").Replace(text))
		if len(parts) != 2 {
			return nil, fmt.Errorf("unsupported type code %q", text)
		}

		icmpType, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("unsupported type code %q", text)
		}
		icmpCode, err := strconv.ParseUint(parts[1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("unsupported type code %q", text)
		}

		typeCode = layers.CreateICMPv4TypeCode(uint8(icmpType), uint8(icmpCode))
	}

	return &typeCode, nil
}

func icmpTypeCodeText(typeCode layers.ICMPv4TypeCode) string {
	switch typeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		if typeCode.Code() == 0 {
			return "EchoRequest"
		}
	case layers.ICMPv4TypeEchoReply:
		if typeCode.Code() == 0 {
			return "EchoReply"
		}
	case layers.ICMPv4TypeTimestampRequest:
		if typeCode.Code() == 0 {
			return "TimestampRequest"
		}
	case layers.ICMPv4TypeTimestampReply:
		if typeCode.Code() == 0 {
			return "TimestampReply"
		}
	case layers.ICMPv4TypeAddressMaskRequest:
		if typeCode.Code() == 0 {
			return "AddressMaskRequest"
		}
	case layers.ICMPv4TypeAddressMaskReply:
		if typeCode.Code() == 0 {
			return "AddressMaskReply"
		}
	case layers.ICMPv4TypeRouterSolicitation:
		if typeCode.Code() == 0 {
			return "RouterSolicitation"
		}
	case layers.ICMPv4TypeRouterAdvertisement:
		if typeCode.Code() == 0 {
			return "RouterAdvertisement"
		}
	}

	return typeCode.String()
}

func formatScriptHardwareAddress(value []byte) string {
	if len(value) == 6 {
		return net.HardwareAddr(value).String()
	}
	return packetpkg.FormatPayloadHex(value)
}

func formatScriptProtocolAddress(value []byte) string {
	if len(value) == 4 {
		return net.IP(value).String()
	}
	return packetpkg.FormatPayloadHex(value)
}

func valueOrZeroUint8(value *uint8) uint8 {
	if value == nil {
		return 0
	}
	return *value
}

func valueOrZeroUint16(value *uint16) uint16 {
	if value == nil {
		return 0
	}
	return *value
}

func valueOrFalse(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}
