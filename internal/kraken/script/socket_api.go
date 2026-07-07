package script

import (
	"context"
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
	fields   starlark.StringDict
}

func newIdentityValue(typeName string, identity ExecutionIdentity) *identityValue {
	return &identityValue{
		typeName: typeName,
		identity: identity,
		fields: starlark.StringDict{
			"label":          starlark.String(identity.Label),
			"ip":             starlark.String(identity.IP),
			"mac":            starlark.String(identity.MAC),
			"interfaceName":  starlark.String(identity.InterfaceName),
			"defaultGateway": starlark.String(identity.DefaultGateway),
			"mtu":            starlark.MakeInt(identity.MTU),
		},
	}
}

func (identity *identityValue) Attr(name string) (starlark.Value, error) {
	if value, ok := identity.fields[name]; ok {
		return value, nil
	}
	return nil, nil
}

func (identity *identityValue) AttrNames() []string  { return identity.fields.Keys() }
func (identity *identityValue) String() string       { return identity.identity.IP }
func (identity *identityValue) Type() string         { return identity.typeName }
func (identity *identityValue) Freeze()              {}
func (identity *identityValue) Truth() starlark.Bool { return true }
func (identity *identityValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("%s is not hashable", identity.typeName)
}

type scriptConn struct {
	protocol string
	conn     net.Conn
	options  SocketOptions
}

func buildSocketModule(ctx ExecutionContext, allowRuntime bool) starlark.Value {
	return &scriptObject{typeName: "socket", fields: starlark.StringDict{
		"tcp": starlark.NewBuiltin("socket.tcp", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if !allowRuntime {
				return nil, fmt.Errorf("kraken/socket.tcp is unavailable during validation")
			}
			return dialScriptSocket(ctx, thread, builtin, args, kwargs, "tcp")
		}),
		"udp": starlark.NewBuiltin("socket.udp", func(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if !allowRuntime {
				return nil, fmt.Errorf("kraken/socket.udp is unavailable during validation")
			}
			return dialScriptSocket(ctx, thread, builtin, args, kwargs, "udp")
		}),
	}}
}

func dialScriptSocket(ctx ExecutionContext, thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, protocol string) (starlark.Value, error) {
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
		runContext := ctx.RunContext
		if runContext == nil {
			runContext = context.Background()
		}
		conn, err = identity.identity.SocketIdentity.DialScriptTCP(runContext, remoteIP, remotePort, options)
	case "udp":
		conn, err = identity.identity.SocketIdentity.DialScriptUDP(remoteIP, remotePort, options)
	default:
		err = fmt.Errorf("unsupported socket protocol %q", protocol)
	}
	if err != nil {
		return nil, err
	}
	return &scriptConn{protocol: protocol, conn: conn, options: options}, nil
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
		switch key {
		case "ttl":
			parsed, err := intSocketOption(key, item[1], 0, 255)
			if err != nil {
				return options, err
			}
			options.TTL = &parsed
		case "nodelay":
			parsed, err := boolSocketOption(key, item[1])
			if err != nil {
				return options, err
			}
			options.NoDelay = &parsed
		case "keepalive":
			parsed, err := boolSocketOption(key, item[1])
			if err != nil {
				return options, err
			}
			options.KeepAlive = &parsed
		case "reuseaddr":
			parsed, err := boolSocketOption(key, item[1])
			if err != nil {
				return options, err
			}
			options.ReuseAddr = &parsed
		case "recv_buffer":
			parsed, err := intSocketOption(key, item[1], 0, 1<<31-1)
			if err != nil {
				return options, err
			}
			options.RecvBuffer = &parsed
		case "send_buffer":
			parsed, err := intSocketOption(key, item[1], 0, 1<<31-1)
			if err != nil {
				return options, err
			}
			options.SendBuffer = &parsed
		default:
			return options, fmt.Errorf("unsupported socket option %q", key)
		}
	}
	return options, nil
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
		return starlark.String(conn.conn.LocalAddr().String()), nil
	case "remote_addr":
		return starlark.String(conn.conn.RemoteAddr().String()), nil
	}
	return nil, nil
}

func (conn *scriptConn) AttrNames() []string {
	return []string{"send", "recv", "close", "set_option", "local_addr", "remote_addr"}
}

func (conn *scriptConn) String() string       { return fmt.Sprintf("<%s connection>", conn.protocol) }
func (conn *scriptConn) Type() string         { return "socket.connection" }
func (conn *scriptConn) Freeze()              {}
func (conn *scriptConn) Truth() starlark.Bool { return true }
func (conn *scriptConn) Hash() (uint32, error) {
	return 0, fmt.Errorf("socket.connection is not hashable")
}

func (conn *scriptConn) send(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var payload starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &payload); err != nil {
		return nil, err
	}
	data, err := byteSliceFromValue(payload)
	if err != nil {
		return nil, err
	}
	written, err := conn.conn.Write(data)
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
	payload := make([]byte, size)
	read, err := conn.conn.Read(payload)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return starlark.Bytes(payload[:read]), nil
}

func (conn *scriptConn) close(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	return starlark.None, conn.conn.Close()
}

func (conn *scriptConn) setOption(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 2, &name, &value); err != nil {
		return nil, err
	}
	setter, ok := conn.conn.(SocketOptionSetter)
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
	dict := starlark.NewDict(1)
	if err := dict.SetKey(starlark.String(name), value); err != nil {
		return SocketOptions{}, err
	}
	return parseSocketOptions(dict)
}
