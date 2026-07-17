package script

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/epmapper"
	"github.com/mandiant/gopacket/pkg/session"
	"go.starlark.net/starlark"
)

type dcerpcClientValue struct {
	unhashableValue
	client      *dcerpc.Client
	epmEndpoint []*dcerpcEndpointValue
}

type dcerpcEndpointValue struct {
	unhashableValue
	uuid        string
	version     string
	major       int
	minor       int
	annotation  string
	protocol    string
	provider    string
	bindings    []string
	tcpBindings []*dcerpcTCPBindingValue
}

type dcerpcTCPBindingValue struct {
	unhashableValue
	raw     string
	host    string
	port    int
	address string
}

var (
	dcerpcClientValueBase     = unhashableValue{typeName: "dcerpc.client", attrNames: []string{"bind", "bind_auth", "call", "call_auth", "epm_lookup", "epm_find", "close"}}
	dcerpcEndpointValueBase   = unhashableValue{typeName: "dcerpc.endpoint", attrNames: []string{"uuid", "version", "major", "minor", "annotation", "protocol", "provider", "bindings", "tcp_bindings", "tcp_binding"}}
	dcerpcTCPBindingValueBase = unhashableValue{typeName: "dcerpc.tcp_binding", attrNames: []string{"raw", "protocol", "host", "port", "address"}}
)

func buildDCERPCModule() starlark.Value {
	return &scriptObject{typeName: "dcerpc", fields: starlark.StringDict{
		"tcp":  starlark.NewBuiltin("dcerpc.tcp", newDCERPCTCPClient),
		"uuid": starlark.NewBuiltin("dcerpc.uuid", dcerpcUUID),
	}}
}

func dcerpcUUID(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &text); err != nil {
		return nil, err
	}
	uuid, err := dcerpc.ParseUUID(text)
	if err != nil {
		return nil, err
	}
	return &byteBuffer{data: uuid[:]}, nil
}

func newDCERPCTCPClient(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var conn *scriptConn
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "connection", &conn); err != nil {
		return nil, err
	}
	rawConn, err := takeTCPScriptConn(builtin.Name(), conn, "dcerpc.client")
	if err != nil {
		return nil, err
	}
	return &dcerpcClientValue{unhashableValue: dcerpcClientValueBase, client: dcerpc.NewClientTCP(dcerpc.NewTCPTransport(rawConn))}, nil
}

func (value *dcerpcClientValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "bind":
		return starlark.NewBuiltin("dcerpc.client.bind", value.bind), nil
	case "bind_auth":
		return starlark.NewBuiltin("dcerpc.client.bind_auth", value.bindAuth), nil
	case "call":
		return starlark.NewBuiltin("dcerpc.client.call", value.call), nil
	case "call_auth":
		return starlark.NewBuiltin("dcerpc.client.call_auth", value.callAuth), nil
	case "epm_lookup":
		return starlark.NewBuiltin("dcerpc.client.epm_lookup", value.epmLookup), nil
	case "epm_find":
		return starlark.NewBuiltin("dcerpc.client.epm_find", value.epmFind), nil
	case "close":
		return starlark.NewBuiltin("dcerpc.client.close", value.close), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (value *dcerpcClientValue) bind(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var uuidText string
	var major, minor int
	major = 1
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "uuid", &uuidText, "major?", &major, "minor?", &minor); err != nil {
		return nil, err
	}
	uuid, majorVersion, minorVersion, err := dcerpcBindingTarget(uuidText, major, minor)
	if err != nil {
		return nil, err
	}
	if err := value.client.Bind(uuid, majorVersion, minorVersion); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (value *dcerpcClientValue) bindAuth(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var uuidText string
	var major, minor int
	var auth *windowsNTLMClientValue
	major = 1
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "uuid", &uuidText, "auth", &auth, "major?", &major, "minor?", &minor); err != nil {
		return nil, err
	}
	if auth == nil || auth.client == nil {
		return nil, fmt.Errorf("%s requires auth from windows.ntlm.client(...)", builtin.Name())
	}
	uuid, majorVersion, minorVersion, err := dcerpcBindingTarget(uuidText, major, minor)
	if err != nil {
		return nil, err
	}
	creds := session.Credentials{
		Domain:   auth.client.Domain,
		Username: auth.client.User,
		Password: auth.client.Password,
	}
	if len(auth.client.Hash) > 0 {
		creds.Hash = hex.EncodeToString(auth.client.Hash)
	}
	if err := value.client.BindAuth(uuid, majorVersion, minorVersion, &creds); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func dcerpcBindingTarget(uuidText string, major, minor int) ([16]byte, uint16, uint16, error) {
	if major < 0 || major > 65535 {
		return [16]byte{}, 0, 0, fmt.Errorf("major version must be between 0 and 65535")
	}
	if minor < 0 || minor > 65535 {
		return [16]byte{}, 0, 0, fmt.Errorf("minor version must be between 0 and 65535")
	}
	uuid, err := dcerpc.ParseUUID(uuidText)
	if err != nil {
		return [16]byte{}, 0, 0, err
	}
	return uuid, uint16(major), uint16(minor), nil
}

func (value *dcerpcClientValue) call(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return value.invoke(builtin, args, kwargs, false)
}

func (value *dcerpcClientValue) callAuth(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return value.invoke(builtin, args, kwargs, true)
}

func (value *dcerpcClientValue) invoke(builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, authenticated bool) (starlark.Value, error) {
	var opnumValue starlark.Value
	var payloadValue starlark.Value = starlark.None
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "opnum", &opnumValue, "payload?", &payloadValue); err != nil {
		return nil, err
	}
	opnum, err := integerInRange(opnumValue, 0, 65535)
	if err != nil {
		return nil, fmt.Errorf("opnum: %w", err)
	}
	payload, err := byteSliceFromValue(payloadValue)
	if err != nil {
		return nil, err
	}
	var response []byte
	if authenticated {
		response, err = value.client.CallAuthAuto(uint16(opnum), payload)
	} else {
		response, err = value.client.Call(uint16(opnum), payload)
	}
	if err != nil {
		return nil, err
	}
	return &byteBuffer{data: response}, nil
}

func (value *dcerpcClientValue) epmLookup(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	endpoints, err := value.lookupEndpoints()
	if err != nil {
		return nil, err
	}
	items := make([]starlark.Value, 0, len(endpoints))
	for _, endpoint := range endpoints {
		items = append(items, endpoint)
	}
	return starlark.NewList(items), nil
}

func (value *dcerpcClientValue) epmFind(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var uuidText string
	var majorValue starlark.Value = starlark.None
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "uuid", &uuidText, "major?", &majorValue); err != nil {
		return nil, err
	}
	major := -1
	if !isNone(majorValue) {
		parsed, err := integerInRange(majorValue, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("major: %w", err)
		}
		major = int(parsed)
	}
	uuidText = strings.ToUpper(uuidText)
	endpoints, err := value.lookupEndpoints()
	if err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		if strings.ToUpper(endpoint.uuid) == uuidText && (major < 0 || endpoint.major == major) {
			return endpoint, nil
		}
	}
	return starlark.None, nil
}

func (value *dcerpcClientValue) lookupEndpoints() ([]*dcerpcEndpointValue, error) {
	if value.epmEndpoint != nil {
		return value.epmEndpoint, nil
	}
	if err := value.client.Bind(epmapper.UUID, epmapper.MajorVersion, epmapper.MinorVersion); err != nil {
		return nil, err
	}
	endpoints, err := epmapper.NewEpmClient(value.client).Lookup()
	if err != nil {
		return nil, err
	}
	items := make([]*dcerpcEndpointValue, 0, len(endpoints))
	for _, endpoint := range endpoints {
		items = append(items, newDCERPCEndpointValue(endpoint))
	}
	value.epmEndpoint = items
	return items, nil
}

func (value *dcerpcClientValue) close(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	if value.client == nil || value.client.Transport == nil {
		return starlark.None, nil
	}
	return starlark.None, value.client.Transport.Close()
}

func newDCERPCEndpointValue(endpoint epmapper.Endpoint) *dcerpcEndpointValue {
	major, minor := parseDCERPCVersion(endpoint.Version)
	tcpBindings := make([]*dcerpcTCPBindingValue, 0, len(endpoint.Bindings))
	for _, binding := range endpoint.Bindings {
		if tcpBinding, ok := parseDCERPCTCPBinding(binding); ok {
			tcpBindings = append(tcpBindings, tcpBinding)
		}
	}
	return &dcerpcEndpointValue{
		unhashableValue: dcerpcEndpointValueBase,
		uuid:            endpoint.UUID,
		version:         endpoint.Version,
		major:           major,
		minor:           minor,
		annotation:      endpoint.Annotation,
		protocol:        endpoint.Protocol,
		provider:        endpoint.Provider,
		bindings:        endpoint.Bindings,
		tcpBindings:     tcpBindings,
	}
}

func (value *dcerpcEndpointValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "uuid":
		return starlark.String(value.uuid), nil
	case "version":
		return starlark.String(value.version), nil
	case "major":
		return starlark.MakeInt(value.major), nil
	case "minor":
		return starlark.MakeInt(value.minor), nil
	case "annotation":
		return starlark.String(value.annotation), nil
	case "protocol":
		return starlark.String(value.protocol), nil
	case "provider":
		return starlark.String(value.provider), nil
	case "bindings":
		items := make([]starlark.Value, 0, len(value.bindings))
		for _, binding := range value.bindings {
			items = append(items, starlark.String(binding))
		}
		return starlark.NewList(items), nil
	case "tcp_bindings":
		items := make([]starlark.Value, 0, len(value.tcpBindings))
		for _, binding := range value.tcpBindings {
			items = append(items, binding)
		}
		return starlark.NewList(items), nil
	case "tcp_binding":
		return starlark.NewBuiltin("dcerpc.endpoint.tcp_binding", value.tcpBinding), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func (value *dcerpcEndpointValue) tcpBinding(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	if len(value.tcpBindings) == 0 {
		return starlark.None, nil
	}
	return value.tcpBindings[0], nil
}

func (value *dcerpcTCPBindingValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "raw":
		return starlark.String(value.raw), nil
	case "protocol":
		return starlark.String("ncacn_ip_tcp"), nil
	case "host":
		return starlark.String(value.host), nil
	case "port":
		return starlark.MakeInt(value.port), nil
	case "address":
		return starlark.String(value.address), nil
	}
	return nil, starlark.NoSuchAttrError(fmt.Sprintf("%s has no .%s attribute", value.Type(), name))
}

func parseDCERPCVersion(version string) (int, int) {
	version = strings.TrimPrefix(version, "v")
	majorText, minorText, found := strings.Cut(version, ".")
	if !found {
		return 0, 0
	}
	major, err := strconv.Atoi(majorText)
	if err != nil {
		return 0, 0
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return 0, 0
	}
	return major, minor
}

func parseDCERPCTCPBinding(raw string) (*dcerpcTCPBindingValue, bool) {
	const prefix = "ncacn_ip_tcp:"
	if !strings.HasPrefix(raw, prefix) {
		return nil, false
	}
	target := strings.TrimPrefix(raw, prefix)
	host := ""
	portText := target
	if before, after, found := strings.Cut(target, "["); found {
		host = before
		portText = strings.TrimSuffix(after, "]")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, false
	}
	address := ""
	if host != "" {
		address = fmt.Sprintf("%s:%d", host, port)
	}
	return &dcerpcTCPBindingValue{
		unhashableValue: dcerpcTCPBindingValueBase,
		raw:             raw,
		host:            host,
		port:            port,
		address:         address,
	}, true
}
