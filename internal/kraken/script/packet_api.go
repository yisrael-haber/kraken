package script

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"go.starlark.net/starlark"
)

var icmpTypeCodes = map[string]layers.ICMPv4TypeCode{
	"EchoRequest":         layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	"EchoReply":           layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
	"TimestampRequest":    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampRequest, 0),
	"TimestampReply":      layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimestampReply, 0),
	"AddressMaskRequest":  layers.CreateICMPv4TypeCode(layers.ICMPv4TypeAddressMaskRequest, 0),
	"AddressMaskReply":    layers.CreateICMPv4TypeCode(layers.ICMPv4TypeAddressMaskReply, 0),
	"RouterSolicitation":  layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRouterSolicitation, 0),
	"RouterAdvertisement": layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRouterAdvertisement, 0),
}

func newContextValue(ctx ExecutionContext) (starlark.Value, error) {
	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted": newScriptObject("ctx.adopted", starlark.StringDict{
			"label":          starlark.String(ctx.Adopted.Label),
			"ip":             starlark.String(ctx.Adopted.IP),
			"mac":            starlark.String(ctx.Adopted.MAC),
			"interfaceName":  starlark.String(ctx.Adopted.InterfaceName),
			"defaultGateway": starlark.String(ctx.Adopted.DefaultGateway),
			"mtu":            starlark.MakeInt(ctx.Adopted.MTU),
		}),
		"metadata": starlark.None,
	}

	if len(ctx.Metadata) != 0 {
		metadata := starlark.NewDict(len(ctx.Metadata))
		for key, value := range ctx.Metadata {
			if err := metadata.SetKey(starlark.String(key), starlark.String(value)); err != nil {
				return nil, fmt.Errorf("ctx.metadata.%s: %w", key, err)
			}
		}
		fields["metadata"] = metadata
	}

	return newScriptObject("ctx", fields), nil
}

func parseScriptHardwareAddr(value starlark.Value, expectedLength int) ([]byte, error) {
	var payload []byte
	if text, ok := starlark.AsString(value); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, nil
		}
		if mac, err := net.ParseMAC(text); err == nil {
			payload = mac
		} else {
			var err error
			payload, err = common.ParsePayloadHex(text)
			if err != nil {
				return nil, err
			}
		}
	} else {
		var err error
		payload, err = byteSliceFromValue(value)
		if err != nil {
			return nil, err
		}
	}
	if expectedLength != 0 && len(payload) != expectedLength {
		return nil, fmt.Errorf("must contain %d bytes", expectedLength)
	}
	return payload, nil
}

func parseScriptProtocolAddress(value starlark.Value) ([]byte, error) {
	if text, ok := starlark.AsString(value); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, nil
		}
		if ip, err := common.NormalizeAdoptionIP(text); err == nil {
			return ip, nil
		}
		return common.ParsePayloadHex(text)
	}

	return byteSliceFromValue(value)
}

func parseIPv4OptionsValue(value starlark.Value) ([]layers.IPv4Option, error) {
	return parsePacketOptionsValue(value, "packet.ipv4.options", func(optionType, optionLength uint8, optionData []byte) layers.IPv4Option {
		return layers.IPv4Option{OptionType: optionType, OptionLength: optionLength, OptionData: optionData}
	})
}

func parseTCPOptionsValue(value starlark.Value) ([]layers.TCPOption, error) {
	return parsePacketOptionsValue(value, "packet.tcp.options", func(optionType, optionLength uint8, optionData []byte) layers.TCPOption {
		return layers.TCPOption{OptionType: layers.TCPOptionKind(optionType), OptionLength: optionLength, OptionData: optionData}
	})
}

func parsePacketOptionsValue[T any](value starlark.Value, label string, newOption func(uint8, uint8, []byte) T) ([]T, error) {
	if isNone(value) {
		return nil, nil
	}

	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("%s: must be a sequence", label)
	}

	iterator := iterable.Iterate()
	defer iterator.Done()

	var options []T
	var item starlark.Value
	for index := 0; iterator.Next(&item); index++ {
		dict, ok := item.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: must be a dict, not %s", label, index, item.Type())
		}

		optionTypeValue, _, err := dict.Get(starlark.String("optionType"))
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionType: %w", label, index, err)
		}
		optionTypeNumber, err := integerInRange(optionTypeValue, 0, 255)
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionType: %w", label, index, err)
		}

		optionLengthValue, _, err := dict.Get(starlark.String("optionLength"))
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionLength: %w", label, index, err)
		}
		optionDataValue, _, err := dict.Get(starlark.String("optionData"))
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionData: %w", label, index, err)
		}
		optionData, err := byteSliceFromValue(optionDataValue)
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionData: %w", label, index, err)
		}

		optionType := uint8(optionTypeNumber)
		optionLength := uint8(1)
		if optionType > 1 {
			optionLength = uint8(len(optionData) + 2)
		}
		if !isNone(optionLengthValue) {
			optionLengthNumber, err := integerInRange(optionLengthValue, 0, 255)
			if err != nil {
				return nil, fmt.Errorf("%s[%d].optionLength: %w", label, index, err)
			}
			optionLength = uint8(optionLengthNumber)
		}
		options = append(options, newOption(optionType, optionLength, optionData))
	}

	return options, nil
}

func requiredUint8(label string, value starlark.Value) (uint8, error) {
	return requiredUint8Range(label, value, 0, 255)
}

func requiredUint8Range(label string, value starlark.Value, min, max int64) (uint8, error) {
	if isNone(value) {
		return 0, fmt.Errorf("%s: value is required", label)
	}
	number, err := integerInRange(value, min, max)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", label, err)
	}
	return uint8(number), nil
}

func requiredUint16(label string, value starlark.Value) (uint16, error) {
	return requiredUint16Range(label, value, 0, 65535)
}

func requiredUint16Range(label string, value starlark.Value, min, max int64) (uint16, error) {
	if isNone(value) {
		return 0, fmt.Errorf("%s: value is required", label)
	}
	number, err := integerInRange(value, min, max)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", label, err)
	}
	return uint16(number), nil
}

func requiredUint32(label string, value starlark.Value) (uint32, error) {
	if isNone(value) {
		return 0, fmt.Errorf("%s: value is required", label)
	}
	number, err := integerInRange(value, 0, 0xffffffff)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", label, err)
	}
	return uint32(number), nil
}

func integerInRange(value starlark.Value, min, max int64) (int64, error) {
	number, err := integerValue(value)
	if err != nil {
		return 0, err
	}
	if number < min || number > max {
		return 0, fmt.Errorf("must be between %d and %d", min, max)
	}
	return number, nil
}

func requiredIPv4(label string, value starlark.Value) (net.IP, error) {
	payload, err := parseScriptProtocolAddress(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%s: value is required", label)
	}
	if len(payload) != 4 {
		return nil, fmt.Errorf("%s: must contain exactly 4 bytes", label)
	}
	return net.IP(payload), nil
}

func requiredICMPTypeCode(label string, value starlark.Value) (layers.ICMPv4TypeCode, error) {
	if isNone(value) {
		return 0, fmt.Errorf("%s: value is required", label)
	}
	text, ok := starlark.AsString(value)
	if !ok {
		return 0, fmt.Errorf("%s: must be a string", label)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("%s: value is required", label)
	}

	if typeCode, ok := icmpTypeCodes[text]; ok {
		return typeCode, nil
	}

	parts := strings.Fields(strings.NewReplacer("/", " ", ":", " ", ",", " ").Replace(text))
	if len(parts) != 2 {
		return 0, fmt.Errorf("%s: unsupported type code %q", label, text)
	}

	icmpType, typeErr := strconv.ParseUint(parts[0], 10, 8)
	icmpCode, codeErr := strconv.ParseUint(parts[1], 10, 8)
	if typeErr != nil || codeErr != nil {
		return 0, fmt.Errorf("%s: unsupported type code %q", label, text)
	}

	return layers.CreateICMPv4TypeCode(uint8(icmpType), uint8(icmpCode)), nil
}

func icmpTypeCodeText(typeCode layers.ICMPv4TypeCode) string {
	for name, namedTypeCode := range icmpTypeCodes {
		if typeCode == namedTypeCode {
			return name
		}
	}

	return typeCode.String()
}
