package operations

import (
	"errors"
	"io"
	"net"
	"sync"
)

type echoService struct {
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	waitErr error
}

func StartEcho(listener net.Listener) (*echoService, error) {
	server := &echoService{
		listener: listener,
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
			if !errors.Is(err, net.ErrClosed) {
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
