package operations

import (
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type echoService struct {
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	waitErr error
}

func echoServiceDefinition() serviceDefinition {
	return serviceDefinition{
		ID:          serviceEchoID,
		Label:       "Echo",
		DefaultPort: 7007,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         "port",
				Required:     true,
				DefaultValue: "7007",
			},
		},
	}
}

func startEchoService(ctx serviceContext, listener net.Listener, config map[string]string) (adoption.ServiceProcess, error) {
	port, _ := strconv.Atoi(config["port"])
	binding, err := newApplicationScriptBinding(ctx, scriptpkg.ApplicationServiceInfo{
		Name:     serviceEchoID,
		Port:     port,
		Protocol: "echo",
	}, nil)
	if err != nil {
		return nil, err
	}

	server := &echoService{
		listener: wrapListenerWithApplicationScript(listener, binding),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}

	go server.run()
	return server, nil
}

func (server *echoService) run() {
	defer close(server.done)

	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if !isClosedNetworkError(err) {
				server.waitErr = err
			}
			return
		}

		server.mu.Lock()
		server.conns[conn] = struct{}{}
		server.mu.Unlock()
		go server.runConn(conn)
	}
}

func (server *echoService) Wait() error {
	<-server.done
	return server.waitErr
}

func (server *echoService) Close() error {
	server.mu.Lock()
	for conn := range server.conns {
		_ = conn.Close()
	}
	server.mu.Unlock()

	return server.listener.Close()
}

func (server *echoService) runConn(conn net.Conn) {
	defer func() {
		server.mu.Lock()
		delete(server.conns, conn)
		server.mu.Unlock()
	}()
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}
