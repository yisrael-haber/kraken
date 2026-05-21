package netruntime

import (
	"io"
	"net"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/script"
)

type applicationScriptListener struct {
	net.Listener
	binding applicationScriptBinding
}

func (listener *applicationScriptListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return wrapApplicationConn(conn, "tcp", listener.binding), nil
}

type applicationScriptBinding struct {
	compiled *script.CompiledScript
	adopted  script.ExecutionIdentity
}

type applicationScriptConn struct {
	net.Conn
	binding   applicationScriptBinding
	transport string
	readMu    sync.Mutex
	writeMu   sync.Mutex
	readBuf   []byte
}

func (conn *applicationScriptConn) Read(p []byte) (int, error) {
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

func (conn *applicationScriptConn) Write(p []byte) (int, error) {
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

func (conn *applicationScriptConn) drainReadBuffer(target []byte) int {
	if len(conn.readBuf) == 0 || len(target) == 0 {
		return 0
	}

	n := copy(target, conn.readBuf)
	conn.readBuf = append(conn.readBuf[:0], conn.readBuf[n:]...)
	return n
}

func wrapApplicationConn(conn net.Conn, transport string, binding applicationScriptBinding) net.Conn {
	if binding.compiled == nil {
		return conn
	}
	return &applicationScriptConn{Conn: conn, binding: binding, transport: transport}
}

func (conn *applicationScriptConn) applyApplicationScript(direction string, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return payload, nil
	}

	data := script.ApplicationData{
		Direction: direction,
		Payload:   payload,
	}
	ctx := script.ExecutionContext{
		ScriptName: conn.binding.compiled.Name(),
		Adopted:    conn.binding.adopted,
		Connection: script.ApplicationConnection{
			LocalAddress:  conn.LocalAddr().String(),
			RemoteAddress: conn.RemoteAddr().String(),
			Transport:     conn.transport,
		},
	}

	if err := script.ExecuteApplicationBuffer(conn.binding.compiled, &data, ctx, nil); err != nil {
		return nil, err
	}
	return data.Payload, nil
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
