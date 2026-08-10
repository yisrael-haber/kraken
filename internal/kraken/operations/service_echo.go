package operations

import (
	"io"
	"net"
	"sync"
	"time"
)

type echoService struct {
	metadata ServiceMetadata
	listener net.Listener

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newEchoService(config map[string]string) (Service, error) {
	port, err := servicePort(config)
	if err != nil {
		return nil, err
	}
	return &echoService{
		metadata: ServiceMetadata{Service: "echo", Port: port, Config: config},
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

func (server *echoService) Metadata() ServiceMetadata {
	return server.metadata
}

func (server *echoService) Start(listener net.Listener) error {
	server.listener = listener
	server.metadata.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	go server.run(listener)
	return nil
}

func (server *echoService) run(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		server.mu.Lock()
		if server.listener == nil {
			server.mu.Unlock()
			_ = conn.Close()
			return
		}
		server.conns[conn] = struct{}{}
		server.mu.Unlock()
		go server.runConn(conn)
	}
}

func (server *echoService) Close() error {
	_ = server.listener.Close()

	server.mu.Lock()
	defer server.mu.Unlock()
	server.listener = nil
	for conn := range server.conns {
		_ = conn.Close()
	}
	return nil
}

func (server *echoService) runConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		server.mu.Lock()
		delete(server.conns, conn)
		server.mu.Unlock()
	}()
	_, _ = io.Copy(conn, conn)
}
