package operations

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type echoListenerService struct {
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	waitErr error
}

func echoListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceEchoID,
		Label:       "Echo",
		DefaultPort: 7007,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "7007",
			},
		},
		Start: startEchoListenerService,
	}
}

func startEchoListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	port, _ := strconv.Atoi(config["port"])
	binding, err := newApplicationScriptBinding(ctx, scriptpkg.ApplicationServiceInfo{
		Name:     listenerServiceEchoID,
		Port:     port,
		Protocol: "echo",
	}, nil)
	if err != nil {
		return nil, err
	}

	server := &echoListenerService{
		listener: wrapListenerWithApplicationScript(listener, binding),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}

	go server.run()
	return server, nil
}

func (server *echoListenerService) run() {
	defer close(server.done)

	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if !isClosedNetworkError(err) {
				server.setWaitError(fmt.Errorf("accept echo connection: %w", err))
			}
			return
		}

		server.trackConn(conn)
		go server.runConn(conn)
	}
}

func (server *echoListenerService) setWaitError(err error) {
	if server == nil || err == nil {
		return
	}

	server.mu.Lock()
	if server.waitErr == nil {
		server.waitErr = err
	}
	server.mu.Unlock()
}

func (server *echoListenerService) Wait() error {
	if server == nil {
		return nil
	}

	<-server.done
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.waitErr
}

func (server *echoListenerService) trackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	server.conns[conn] = struct{}{}
	server.mu.Unlock()
}

func (server *echoListenerService) untrackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	delete(server.conns, conn)
	server.mu.Unlock()
}

func (server *echoListenerService) Close() error {
	if server == nil {
		return nil
	}

	server.mu.Lock()
	conns := make([]net.Conn, 0, len(server.conns))
	for conn := range server.conns {
		conns = append(conns, conn)
	}
	server.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}

	if server.listener == nil {
		return nil
	}

	return server.listener.Close()
}

func (server *echoListenerService) runConn(conn net.Conn) {
	if conn == nil {
		return
	}

	defer server.untrackConn(conn)
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}
