package script

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.starlark.net/starlark"
)

func ExecuteApplicationBuffer(script StoredScript, data *StreamData, ctx StreamExecutionContext, logf LogFunc) error {
	if err := validateExecutableScript(script, SurfaceApplication); err != nil {
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

	thread, globals, err := initScriptGlobals(script, logf, nil)
	if err != nil {
		return err
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", script.Name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{dataValue, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	return applyApplicationBufferValue(dataValue, data)
}

func newApplicationContextValue(ctx StreamExecutionContext) (starlark.Value, error) {
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
			"name":          starlark.String(ctx.Service.Name),
			"port":          starlark.MakeInt(ctx.Service.Port),
			"protocol":      starlark.String(ctx.Service.Protocol),
			"rootDirectory": starlark.String(ctx.Service.RootDirectory),
			"useTLS":        starlark.Bool(ctx.Service.UseTLS),
		}),
		"connection": newScriptObject("ctx.connection", false, starlark.StringDict{
			"localAddress":  starlark.String(ctx.Connection.LocalAddress),
			"remoteAddress": starlark.String(ctx.Connection.RemoteAddress),
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
	dnsValue        starlark.Value
	tlsValue        starlark.Value
	modbusValue     starlark.Value
}

func newApplicationBufferValue(data *StreamData, ctx StreamExecutionContext) (*applicationBufferValue, error) {
	if data == nil {
		data = &StreamData{}
	}

	value := &applicationBufferValue{
		direction:       data.Direction,
		payloadValue:    newOwnedByteBuffer(append([]byte(nil), data.Payload...)),
		originalPayload: append([]byte(nil), data.Payload...),
	}

	switch applicationLayerTypeForStream(ctx) {
	case layers.LayerTypeDNS:
		dnsPayload, prefixed := maybeTrimTCPDNSPrefix(data.Payload)
		dns := &layers.DNS{}
		if err := dns.DecodeFromBytes(dnsPayload, gopacket.NilDecodeFeedback); err == nil {
			layerValue, err := newApplicationDNSValue(dns)
			if err != nil {
				return nil, err
			}
			value.dnsValue = layerValue
			value.dnsTCPPrefix = prefixed
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

func applyApplicationBufferValue(value *applicationBufferValue, data *StreamData) error {
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
			binary.BigEndian.PutUint16(prefixed[:2], uint16(len(payload)))
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

func applicationLayerTypeForStream(ctx StreamExecutionContext) gopacket.LayerType {
	ports := make([]int, 0, 3)
	if port := applicationPortFromAddress(ctx.Connection.LocalAddress); port > 0 {
		ports = append(ports, port)
	}
	if ctx.Service.Port > 0 && !slices.Contains(ports, ctx.Service.Port) {
		ports = append(ports, ctx.Service.Port)
	}
	if port := applicationPortFromAddress(ctx.Connection.RemoteAddress); port > 0 && !slices.Contains(ports, port) {
		ports = append(ports, port)
	}

	for _, port := range ports {
		if layerType := layers.TCPPort(port).LayerType(); layerType != gopacket.LayerTypePayload {
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
