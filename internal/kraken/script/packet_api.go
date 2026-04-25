package script

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

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

		payload, err := common.ParsePayloadHex(text)
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
		payload, err := common.ParsePayloadHex(text)
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
		return common.ParsePayloadHex(text)
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
