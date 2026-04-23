package capture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type applicationScriptBinding struct {
	script      scriptpkg.StoredScript
	service     scriptpkg.ApplicationServiceInfo
	adopted     scriptpkg.ExecutionIdentity
	metadata    map[string]interface{}
	recordError func(error)
	clearError  func()
}

func resolveApplicationScriptBinding(
	identity adoption.Identity,
	lookup adoption.ScriptLookupFunc,
	service scriptpkg.ApplicationServiceInfo,
	metadata map[string]interface{},
	recordError func(error),
	clearError func(),
) (*applicationScriptBinding, error) {
	if identity == nil {
		return nil, nil
	}

	scriptName := strings.TrimSpace(identity.ApplicationScriptName())
	if scriptName == "" {
		return nil, nil
	}
	if lookup == nil {
		return nil, fmt.Errorf("stored scripts are unavailable")
	}

	storedScript, err := lookup(scriptpkg.StoredScriptRef{
		Name:    scriptName,
		Surface: scriptpkg.SurfaceApplication,
	})
	if err != nil {
		if errors.Is(err, scriptpkg.ErrStoredScriptNotFound) {
			return nil, fmt.Errorf("stored script %q was not found", scriptName)
		}
		return nil, err
	}
	if storedScript.Name == "" {
		return nil, fmt.Errorf("stored script %q was not found", scriptName)
	}

	return &applicationScriptBinding{
		script:      storedScript,
		service:     service,
		adopted:     buildExecutionIdentity(identity),
		metadata:    metadata,
		recordError: recordError,
		clearError:  clearError,
	}, nil
}

func (binding *applicationScriptBinding) apply(direction string, payload []byte, connection scriptpkg.ApplicationConnection) ([]byte, error) {
	if binding == nil || len(payload) == 0 {
		return append([]byte(nil), payload...), nil
	}

	data := scriptpkg.ApplicationData{
		Direction: direction,
		Payload:   append([]byte(nil), payload...),
	}
	ctx := scriptpkg.ApplicationContext{
		ScriptName: binding.script.Name,
		Adopted:    binding.adopted,
		Service:    binding.service,
		Connection: connection,
		Metadata:   binding.metadata,
	}

	if err := scriptpkg.ExecuteApplicationBuffer(binding.script, &data, ctx, nil); err != nil {
		if binding.recordError != nil {
			binding.recordError(err)
		}
		return nil, err
	}
	if binding.clearError != nil {
		binding.clearError()
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
		return append([]byte(nil), payload...), nil
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
