package script

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
)

func ExecuteApplicationBuffer(compiled *CompiledScript, data *ApplicationData, ctx ApplicationContext, logf LogFunc) error {
	if err := validateExecutableScript(compiled, SurfaceApplication); err != nil {
		return err
	}

	dataValue, err := newApplicationBufferValue(data, ctx)
	if err != nil {
		return err
	}
	ctxValue, err := newApplicationContextValue(ctx)
	if err != nil {
		return err
	}

	thread, globals, err := initScriptGlobals(compiled, logf, nil)
	if err != nil {
		return err
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{dataValue, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	return applyApplicationBufferValue(dataValue, data)
}

func newApplicationContextValue(ctx ApplicationContext) (starlark.Value, error) {
	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted": newScriptObject("ctx.adopted", false, starlark.StringDict{
			"label":          starlark.String(ctx.Adopted.Label),
			"ip":             starlark.String(ctx.Adopted.IP),
			"mac":            starlark.String(ctx.Adopted.MAC),
			"interfaceName":  starlark.String(ctx.Adopted.InterfaceName),
			"defaultGateway": starlark.String(ctx.Adopted.DefaultGateway),
			"mtu":            starlark.MakeInt(ctx.Adopted.MTU),
		}),
		"service": newScriptObject("ctx.service", false, starlark.StringDict{
			"name":     starlark.String(ctx.Service.Name),
			"port":     starlark.MakeInt(ctx.Service.Port),
			"protocol": starlark.String(ctx.Service.Protocol),
		}),
		"connection": newScriptObject("ctx.connection", false, starlark.StringDict{
			"localAddress":  starlark.String(ctx.Connection.LocalAddress),
			"remoteAddress": starlark.String(ctx.Connection.RemoteAddress),
			"transport":     starlark.String(applicationTransport(ctx.Connection.Transport)),
		}),
		"metadata": starlark.None,
	}

	if len(ctx.Metadata) != 0 {
		metadata, err := toStarlarkValue(ctx.Metadata)
		if err != nil {
			return nil, fmt.Errorf("ctx.metadata: %w", err)
		}
		fields["metadata"] = metadata
	}

	return newScriptObject("ctx", false, fields), nil
}

type applicationBufferValue struct {
	direction       string
	payloadValue    *byteBuffer
	originalPayload []byte
	layerNames      []string
	dnsTCPPrefix    bool
	dnsTCPLength    uint16
	dnsValue        starlark.Value
	tlsValue        starlark.Value
	modbusValue     starlark.Value
}

func newApplicationBufferValue(data *ApplicationData, ctx ApplicationContext) (*applicationBufferValue, error) {
	if data == nil {
		data = &ApplicationData{}
	}

	value := &applicationBufferValue{
		direction:       data.Direction,
		payloadValue:    newOwnedByteBuffer(append([]byte(nil), data.Payload...)),
		originalPayload: append([]byte(nil), data.Payload...),
	}

	transport := applicationTransport(ctx.Connection.Transport)
	switch applicationLayerTypeForContext(ctx, transport) {
	case layers.LayerTypeDNS:
		dnsPayload := data.Payload
		prefixed := false
		if transport == "tcp" {
			dnsPayload, prefixed = maybeTrimTCPDNSPrefix(data.Payload)
		}
		dns := &layers.DNS{}
		if err := dns.DecodeFromBytes(dnsPayload, gopacket.NilDecodeFeedback); err == nil {
			layerValue, err := newApplicationDNSValue(dns)
			if err != nil {
				return nil, err
			}
			value.dnsValue = layerValue
			value.dnsTCPPrefix = prefixed
			if prefixed && len(data.Payload) >= 2 {
				value.dnsTCPLength = binary.BigEndian.Uint16(data.Payload[:2])
			}
			value.layerNames = []string{"dns"}
		}
	case layers.LayerTypeTLS:
		layerValue, err := newApplicationTLSValue(data.Payload)
		if err != nil {
			return nil, err
		}
		if layerValue != nil {
			value.tlsValue = layerValue
			value.layerNames = []string{"tls"}
		}
	case layers.LayerTypeModbusTCP:
		modbus := &layers.ModbusTCP{}
		if err := modbus.DecodeFromBytes(data.Payload, gopacket.NilDecodeFeedback); err == nil {
			layerValue, err := newApplicationModbusValue(modbus)
			if err != nil {
				return nil, err
			}
			value.modbusValue = layerValue
			value.layerNames = []string{"modbusTCP"}
		}
	}

	return value, nil
}

func (value *applicationBufferValue) String() string       { return "<buffer>" }
func (value *applicationBufferValue) Type() string         { return "buffer" }
func (value *applicationBufferValue) Freeze()              {}
func (value *applicationBufferValue) Truth() starlark.Bool { return true }
func (value *applicationBufferValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", value.Type())
}

func (value *applicationBufferValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "direction":
		return starlark.String(value.direction), nil
	case "payload":
		return value.payloadValue, nil
	case "layers":
		items := make([]starlark.Value, 0, len(value.layerNames))
		for _, item := range value.layerNames {
			items = append(items, starlark.String(item))
		}
		return starlark.NewList(items), nil
	case "layer":
		return starlark.NewBuiltin("buffer.layer", value.layerByName), nil
	case "dns":
		if value.dnsValue == nil {
			return starlark.None, nil
		}
		return value.dnsValue, nil
	case "tls":
		if value.tlsValue == nil {
			return starlark.None, nil
		}
		return value.tlsValue, nil
	case "modbusTCP":
		if value.modbusValue == nil {
			return starlark.None, nil
		}
		return value.modbusValue, nil
	default:
		return nil, starlark.NoSuchAttrError(fmt.Sprintf("buffer has no .%s attribute", name))
	}
}

func (value *applicationBufferValue) AttrNames() []string {
	return []string{"direction", "payload", "layers", "layer", "dns", "tls", "modbusTCP"}
}

func (value *applicationBufferValue) SetField(name string, fieldValue starlark.Value) error {
	switch name {
	case "payload":
		payload, err := parseOptionalBytes(fieldValue)
		if err != nil {
			return fmt.Errorf("buffer.payload: %w", err)
		}
		value.payloadValue = newOwnedByteBuffer(payload)
		return nil
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("buffer has no writable .%s attribute", name))
	}
}

func (value *applicationBufferValue) layerByName(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	layerValue, err := value.Attr(strings.TrimSpace(name))
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

func (value *applicationBufferValue) payloadChanged() bool {
	if value == nil {
		return false
	}
	return !bytes.Equal(value.originalPayload, value.payloadValue.Bytes())
}

func applyApplicationBufferValue(value *applicationBufferValue, data *ApplicationData) error {
	if data == nil || value == nil {
		return nil
	}

	if value.payloadChanged() || (value.dnsValue == nil && value.tlsValue == nil && value.modbusValue == nil) {
		data.Payload = append([]byte(nil), value.payloadValue.Bytes()...)
		return nil
	}

	switch {
	case value.dnsValue != nil:
		payload, err := encodeApplicationDNSValue(value.dnsValue)
		if err != nil {
			return err
		}
		if value.dnsTCPPrefix {
			prefixed := make([]byte, 2+len(payload))
			// Preserve the original TCP length prefix instead of rewriting it to match the rebuilt DNS payload.
			binary.BigEndian.PutUint16(prefixed[:2], value.dnsTCPLength)
			copy(prefixed[2:], payload)
			payload = prefixed
		}
		data.Payload = payload
	case value.tlsValue != nil:
		payload, err := encodeApplicationTLSValue(value.tlsValue)
		if err != nil {
			return err
		}
		data.Payload = payload
	case value.modbusValue != nil:
		payload, err := encodeApplicationModbusValue(value.modbusValue)
		if err != nil {
			return err
		}
		data.Payload = payload
	}
	return nil
}

func applicationLayerTypeForContext(ctx ApplicationContext, transport string) gopacket.LayerType {
	ports := make([]int, 0, 3)
	if port := applicationPortFromAddress(ctx.Connection.LocalAddress); port > 0 {
		ports = append(ports, port)
	}
	if ctx.Service.Port > 0 && !containsInt(ports, ctx.Service.Port) {
		ports = append(ports, ctx.Service.Port)
	}
	if port := applicationPortFromAddress(ctx.Connection.RemoteAddress); port > 0 && !containsInt(ports, port) {
		ports = append(ports, port)
	}

	for _, port := range ports {
		layerType := gopacket.LayerTypePayload
		switch transport {
		case "udp":
			layerType = layers.UDPPort(port).LayerType()
		default:
			layerType = layers.TCPPort(port).LayerType()
		}
		if layerType != gopacket.LayerTypePayload {
			return layerType
		}
	}
	return gopacket.LayerTypePayload
}

func applicationPortFromAddress(address string) int {
	if strings.TrimSpace(address) == "" {
		return 0
	}
	_, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 0
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return 0
	}
	return port
}

func applicationTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "", "tcp", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6":
		return "udp"
	default:
		return strings.ToLower(strings.TrimSpace(transport))
	}
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func maybeTrimTCPDNSPrefix(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return payload, false
	}
	length := int(binary.BigEndian.Uint16(payload[:2]))
	if length == len(payload)-2 {
		return payload[2:], true
	}
	return payload, false
}
