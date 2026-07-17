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

var icmpTypeCodeSeparator = strings.NewReplacer("/", " ", ":", " ", ",", " ")

type contextValues struct {
	adopted    *identityValue
	identities []contextIdentityValue
	metadata   map[string]starlark.String
}

type contextIdentityValue struct {
	ip    string
	value *identityValue
}

func PrepareTransportContext(ctx ExecutionContext) ExecutionContext {
	ctx.context = newContextValues(ctx)
	return ctx
}

func newContextValue(ctx ExecutionContext) starlark.Value {
	values := ctx.context
	if values == nil {
		values = newContextValues(ctx)
	}

	identities := starlark.NewDict(len(values.identities))
	for _, identity := range values.identities {
		_ = identities.SetKey(starlark.String(identity.ip), identity.value)
	}
	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted":    values.adopted,
		"identities": identities,
		"metadata":   starlark.None,
	}
	if len(values.metadata) != 0 {
		metadata := starlark.NewDict(len(values.metadata))
		for key, value := range values.metadata {
			_ = metadata.SetKey(starlark.String(key), value)
		}
		fields["metadata"] = metadata
	}
	return &scriptObject{typeName: "ctx", fields: fields}
}

func newContextValues(ctx ExecutionContext) *contextValues {
	values := &contextValues{identities: make([]contextIdentityValue, 0, len(ctx.Identities))}
	for _, identity := range ctx.Identities {
		value := newIdentityValue("ctx.identity", identity)
		if ctx.Adopted.IP != "" && identity.IP == ctx.Adopted.IP {
			values.adopted = value
		}
		values.identities = append(values.identities, contextIdentityValue{ip: identity.IP, value: value})
	}
	if values.adopted == nil {
		values.adopted = newIdentityValue("ctx.adopted", ctx.Adopted)
	}
	if len(ctx.Identities) == 0 && ctx.Adopted.IP != "" {
		values.identities = append(values.identities, contextIdentityValue{ip: ctx.Adopted.IP, value: values.adopted})
	}
	if len(ctx.Metadata) != 0 {
		values.metadata = make(map[string]starlark.String, len(ctx.Metadata))
		for key, value := range ctx.Metadata {
			values.metadata[key] = starlark.String(value)
		}
	}
	return values
}

func parseScriptHardwareAddr(value starlark.Value, expectedLength int) ([]byte, error) {
	var payload []byte
	if text, ok := starlark.AsString(value); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, nil
		}
		mac, err := net.ParseMAC(text)
		if err != nil {
			return nil, err
		}
		payload = mac
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
		ip, err := common.NormalizeAdoptionIP(text)
		if err != nil {
			return nil, err
		}
		return ip, nil
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

		optionTypeValue, _, _ := dict.Get(starlark.String("optionType"))
		optionType, err := requiredUint8(fmt.Sprintf("%s[%d].optionType", label, index), optionTypeValue)
		if err != nil {
			return nil, err
		}

		optionLengthValue, _, _ := dict.Get(starlark.String("optionLength"))
		optionDataValue, _, _ := dict.Get(starlark.String("optionData"))
		optionData, err := byteSliceFromValue(optionDataValue)
		if err != nil {
			return nil, fmt.Errorf("%s[%d].optionData: %w", label, index, err)
		}

		optionLength := uint8(1)
		if optionType > 1 {
			optionLength = uint8(len(optionData) + 2)
		}
		if !isNone(optionLengthValue) {
			optionLength, err = requiredUint8(fmt.Sprintf("%s[%d].optionLength", label, index), optionLengthValue)
			if err != nil {
				return nil, err
			}
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
	valueNumber, ok := value.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("must be an integer")
	}
	var number int64
	if err := starlark.AsInt(valueNumber, &number); err != nil {
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

	parts := strings.Fields(icmpTypeCodeSeparator.Replace(text))
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
