package operations

import (
	"errors"
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

func NewEcho(config map[string]string) (Service, error) {
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
	server.metadata.Active = true
	server.metadata.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	go server.run()
	return nil
}

func (server *echoService) run() {
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				server.metadata.LastError = err.Error()
			}
			server.metadata.Active = false
			return
		}

		server.mu.Lock()
		server.conns[conn] = struct{}{}
		server.mu.Unlock()
		go server.runConn(conn)
	}
}

func (server *echoService) Close() error {
	server.mu.Lock()
	for conn := range server.conns {
		_ = conn.Close()
	}
	server.mu.Unlock()

	_ = server.listener.Close()
	if server.metadata.LastError != "" {
		return errors.New(server.metadata.LastError)
	}
	return nil
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
