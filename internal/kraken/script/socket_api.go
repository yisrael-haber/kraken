package script

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

type identityValue struct {
	typeName string
	identity ExecutionIdentity
}

var (
	identityAttrNames   = []string{"defaultGateway", "interfaceName", "ip", "label", "mac", "mtu"}
	scriptConnAttrNames = []string{"send", "recv", "close", "set_option", "local_addr", "remote_addr"}
)

func newIdentityValue(typeName string, identity ExecutionIdentity) *identityValue {
	return &identityValue{typeName: typeName, identity: identity}
}

func (identity *identityValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "label":
		return starlark.String(identity.identity.Label), nil
	case "ip":
		return starlark.String(identity.identity.IP), nil
	case "mac":
		return starlark.String(identity.identity.MAC), nil
	case "interfaceName":
		return starlark.String(identity.identity.InterfaceName), nil
	case "defaultGateway":
		return starlark.String(identity.identity.DefaultGateway), nil
	case "mtu":
		return starlark.MakeInt(identity.identity.MTU), nil
	}
	return nil, nil
}

func (*identityValue) AttrNames() []string           { return identityAttrNames }
func (identity *identityValue) String() string       { return identity.identity.IP }
func (identity *identityValue) Type() string         { return identity.typeName }
func (identity *identityValue) Freeze()              {}
func (identity *identityValue) Truth() starlark.Bool { return true }
func (identity *identityValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("%s is not hashable", identity.typeName)
}

type scriptConn struct {
	protocol    string
	conn        net.Conn
	owner       string
	connections *scriptConnections
}

func buildSocketModule(ctx ExecutionContext, allowRuntime bool) starlark.Value {
	return &scriptObject{typeName: "socket", fields: starlark.StringDict{
		"tcp": starlark.NewBuiltin("socket.tcp", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if !allowRuntime {
				return nil, fmt.Errorf("kraken/socket.tcp is unavailable during validation")
			}
			return dialScriptSocket(ctx, builtin, args, kwargs, "tcp")
		}),
		"udp": starlark.NewBuiltin("socket.udp", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if !allowRuntime {
				return nil, fmt.Errorf("kraken/socket.udp is unavailable during validation")
			}
			return dialScriptSocket(ctx, builtin, args, kwargs, "udp")
		}),
	}}
}

func dialScriptSocket(ctx ExecutionContext, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, protocol string) (starlark.Value, error) {
	var identity *identityValue
	var address string
	var optionsValue starlark.Value = starlark.None
	if err := starlark.UnpackArgs(builtin.Name(), args, kwargs, "identity", &identity, "address", &address, "options?", &optionsValue); err != nil {
		return nil, err
	}
	if identity == nil || identity.identity.SocketIdentity == nil {
		return nil, fmt.Errorf("%s requires an adopted identity from ctx.identities", builtin.Name())
	}
	remoteIP, remotePort, err := parseSocketAddress(address)
	if err != nil {
		return nil, err
	}
	options, err := parseSocketOptions(optionsValue)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	switch protocol {
	case "tcp":
		conn, err = identity.identity.SocketIdentity.DialScriptTCP(ctx.RunContext, remoteIP, remotePort, options)
	case "udp":
		conn, err = identity.identity.SocketIdentity.DialScriptUDP(remoteIP, remotePort, options)
	default:
		err = fmt.Errorf("unsupported socket protocol %q", protocol)
	}
	if err != nil {
		return nil, err
	}
	ctx.connections.Add(conn)
	return &scriptConn{protocol: protocol, conn: conn, connections: ctx.connections}, nil
}

func parseSocketAddress(address string) (net.IP, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, 0, fmt.Errorf("address must be host:port: %w", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("address host must be an IPv4 address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("address port must be between 1 and 65535")
	}
	return ip, port, nil
}

func parseSocketOptions(value starlark.Value) (SocketOptions, error) {
	var options SocketOptions
	if isNone(value) {
		return options, nil
	}
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return options, fmt.Errorf("options must be a dict")
	}
	for _, item := range dict.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok {
			return options, fmt.Errorf("socket option key must be a string")
		}
		if err := setSocketOption(&options, key, item[1]); err != nil {
			return options, err
		}
	}
	return options, nil
}

func setSocketOption(options *SocketOptions, name string, value starlark.Value) error {
	switch name {
	case "ttl":
		parsed, err := intSocketOption(name, value, 0, 255)
		options.TTL = &parsed
		return err
	case "nodelay", "keepalive", "reuseaddr":
		parsed, err := boolSocketOption(name, value)
		if err != nil {
			return err
		}
		switch name {
		case "nodelay":
			options.NoDelay = &parsed
		case "keepalive":
			options.KeepAlive = &parsed
		default:
			options.ReuseAddr = &parsed
		}
		return nil
	case "recv_buffer", "send_buffer":
		parsed, err := intSocketOption(name, value, 0, 1<<31-1)
		if err != nil {
			return err
		}
		if name == "recv_buffer" {
			options.RecvBuffer = &parsed
		} else {
			options.SendBuffer = &parsed
		}
		return nil
	default:
		return fmt.Errorf("unsupported socket option %q", name)
	}
}

func intSocketOption(name string, value starlark.Value, min, max int64) (int, error) {
	number, err := integerInRange(value, min, max)
	if err != nil {
		return 0, fmt.Errorf("socket option %q: %w", name, err)
	}
	return int(number), nil
}

func boolSocketOption(name string, value starlark.Value) (bool, error) {
	boolean, ok := value.(starlark.Bool)
	if !ok {
		return false, fmt.Errorf("socket option %q must be a bool", name)
	}
	return bool(boolean), nil
}

func (conn *scriptConn) Attr(name string) (starlark.Value, error) {
	switch name {
	case "send":
		return starlark.NewBuiltin("connection.send", conn.send), nil
	case "recv":
		return starlark.NewBuiltin("connection.recv", conn.recv), nil
	case "close":
		return starlark.NewBuiltin("connection.close", conn.close), nil
	case "set_option":
		return starlark.NewBuiltin("connection.set_option", conn.setOption), nil
	case "local_addr":
		if conn.conn == nil {
			return nil, conn.unavailableError()
		}
		return starlark.String(conn.conn.LocalAddr().String()), nil
	case "remote_addr":
		if conn.conn == nil {
			return nil, conn.unavailableError()
		}
		return starlark.String(conn.conn.RemoteAddr().String()), nil
	}
	return nil, nil
}

func (*scriptConn) AttrNames() []string { return scriptConnAttrNames }

func (conn *scriptConn) String() string       { return fmt.Sprintf("<%s connection>", conn.protocol) }
func (conn *scriptConn) Type() string         { return "socket.connection" }
func (conn *scriptConn) Freeze()              {}
func (conn *scriptConn) Truth() starlark.Bool { return true }
func (conn *scriptConn) Hash() (uint32, error) {
	return 0, fmt.Errorf("socket.connection is not hashable")
}

func (conn *scriptConn) netConn() (net.Conn, error) {
	if conn == nil || conn.conn == nil {
		return nil, conn.unavailableError()
	}
	return conn.conn, nil
}

func (conn *scriptConn) takeNetConn(owner string) (net.Conn, error) {
	rawConn, err := conn.netConn()
	if err != nil {
		return nil, err
	}
	conn.conn = nil
	conn.owner = owner
	return rawConn, nil
}

func (conn *scriptConn) unavailableError() error {
	if conn != nil && conn.owner != "" {
		return fmt.Errorf("socket.connection is owned by %s", conn.owner)
	}
	return fmt.Errorf("socket.connection is closed")
}

func (conn *scriptConn) send(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var payload starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &payload); err != nil {
		return nil, err
	}
	rawConn, err := conn.netConn()
	if err != nil {
		return nil, err
	}
	data, err := byteSliceFromValue(payload)
	if err != nil {
		return nil, err
	}
	written, err := rawConn.Write(data)
	if err != nil {
		return nil, err
	}
	return starlark.MakeInt(written), nil
}

func (conn *scriptConn) recv(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &size); err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("recv size must be positive")
	}
	rawConn, err := conn.netConn()
	if err != nil {
		return nil, err
	}
	payload := make([]byte, size)
	read, err := rawConn.Read(payload)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return starlark.Bytes(payload[:read]), nil
}

func (conn *scriptConn) close(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	rawConn, err := conn.netConn()
	if err != nil {
		return nil, err
	}
	conn.conn = nil
	conn.connections.Remove(rawConn)
	return starlark.None, rawConn.Close()
}

func (conn *scriptConn) setOption(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 2, &name, &value); err != nil {
		return nil, err
	}
	rawConn, err := conn.netConn()
	if err != nil {
		return starlark.None, err
	}
	setter, ok := rawConn.(SocketOptionSetter)
	if !ok {
		return starlark.None, fmt.Errorf("socket option %q cannot be changed after creation on this connection", name)
	}
	options, err := parseSocketOption(name, value)
	if err != nil {
		return starlark.None, err
	}
	return starlark.None, setter.SetScriptSocketOptions(options)
}

func parseSocketOption(name string, value starlark.Value) (SocketOptions, error) {
	var options SocketOptions
	return options, setSocketOption(&options, name, value)
}
