package operations

import (
	"io"
	"net"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type applicationScriptBinding struct {
	script   *scriptpkg.CompiledScript
	service  scriptpkg.ApplicationServiceInfo
	adopted  scriptpkg.ExecutionIdentity
	metadata map[string]any
}

func resolveApplicationScriptBinding(
	identity adoption.Identity,
	service scriptpkg.ApplicationServiceInfo,
	metadata map[string]any,
) (*applicationScriptBinding, error) {
	if identity.IP.To4() == nil {
		return nil, nil
	}

	compiled := identity.ApplicationScript()
	if compiled == nil {
		return nil, nil
	}

	return &applicationScriptBinding{
		script:   compiled,
		service:  service,
		adopted:  buildExecutionIdentity(identity),
		metadata: metadata,
	}, nil
}

func (binding *applicationScriptBinding) apply(direction string, payload []byte, connection scriptpkg.ApplicationConnection) ([]byte, error) {
	if binding == nil || len(payload) == 0 {
		return payload, nil
	}

	data := scriptpkg.ApplicationData{
		Direction: direction,
		Payload:   payload,
	}
	ctx := scriptpkg.ExecutionContext{
		ScriptName: binding.script.Name(),
		Adopted:    binding.adopted,
		Service:    binding.service,
		Connection: connection,
		Metadata:   binding.metadata,
	}

	if err := scriptpkg.ExecuteApplicationBuffer(binding.script, &data, ctx, nil); err != nil {
		return nil, err
	}
	return data.Payload, nil
}

type scriptedListener struct {
	net.Listener
	binding *applicationScriptBinding
}

func wrapListenerWithApplicationScript(listener net.Listener, binding *applicationScriptBinding) net.Listener {
	if listener == nil || binding == nil {
		return listener
	}

	return &scriptedListener{
		Listener: listener,
		binding:  binding,
	}
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &scriptedConn{
		Conn:    conn,
		binding: listener.binding,
	}, nil
}

type scriptedConn struct {
	net.Conn
	binding *applicationScriptBinding
	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
}

func (conn *scriptedConn) Read(p []byte) (int, error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()

	if len(conn.readBuf) != 0 {
		return conn.drainReadBuffer(p), nil
	}

	buffer := make([]byte, max(len(p), 4096))
	n, err := conn.Conn.Read(buffer)
	if n <= 0 {
		return 0, err
	}

	payload, applyErr := conn.applyApplicationScript("inbound", buffer[:n])
	if applyErr != nil {
		_ = conn.Conn.Close()
		return 0, applyErr
	}

	conn.readBuf = append(conn.readBuf[:0], payload...)
	read := conn.drainReadBuffer(p)
	if read != 0 {
		return read, err
	}
	return 0, err
}

func (conn *scriptedConn) Write(p []byte) (int, error) {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()

	payload, err := conn.applyApplicationScript("outbound", p)
	if err != nil {
		_ = conn.Conn.Close()
		return 0, err
	}
	if err := writeAll(conn.Conn, payload); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (conn *scriptedConn) drainReadBuffer(target []byte) int {
	if len(conn.readBuf) == 0 || len(target) == 0 {
		return 0
	}

	n := copy(target, conn.readBuf)
	conn.readBuf = append(conn.readBuf[:0], conn.readBuf[n:]...)
	return n
}

func (conn *scriptedConn) applyApplicationScript(direction string, payload []byte) ([]byte, error) {
	if conn == nil {
		return payload, nil
	}

	return conn.binding.apply(direction, payload, scriptpkg.ApplicationConnection{
		LocalAddress:  conn.LocalAddr().String(),
		RemoteAddress: conn.RemoteAddr().String(),
		Transport:     "tcp",
	})
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func buildExecutionIdentity(identity adoption.Identity) scriptpkg.ExecutionIdentity {
	if identity.IP.To4() == nil {
		return scriptpkg.ExecutionIdentity{}
	}

	return scriptpkg.ExecutionIdentity{
		Label:          identity.Label,
		IP:             identity.IP.String(),
		MAC:            identity.MAC.String(),
		InterfaceName:  identity.InterfaceName,
		DefaultGateway: ipString(identity.DefaultGateway),
		MTU:            int(identity.MTU),
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
