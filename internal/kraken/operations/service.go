package operations

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type Service interface {
	Metadata() ServiceMetadata
	Start(net.Listener) error
	Close() error
}

type ServiceMetadata struct {
	Service   string               `json:"service"`
	Port      int                  `json:"port"`
	Config    map[string]string    `json:"config,omitempty"`
	Summary   []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt string               `json:"startedAt,omitempty"`
	LastError string               `json:"lastError,omitempty"`
}

type ServiceSummaryItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
}

type tcpService struct {
	handler func(net.Conn) error

	mu       sync.Mutex
	metadata ServiceMetadata
	listener net.Listener
	conns    map[net.Conn]struct{}
}

func newTCPService(metadata ServiceMetadata, handler func(net.Conn) error) *tcpService {
	return &tcpService{
		handler:  handler,
		metadata: metadata,
		conns:    make(map[net.Conn]struct{}),
	}
}

func (service *tcpService) Metadata() ServiceMetadata {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.metadata
}

func (service *tcpService) Start(listener net.Listener) error {
	service.listener = listener
	service.metadata.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	go service.accept(listener)
	return nil
}

func (service *tcpService) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			service.mu.Lock()
			if service.listener != nil {
				service.metadata.LastError = err.Error()
			}
			service.mu.Unlock()
			return
		}

		service.mu.Lock()
		if service.listener == nil {
			service.mu.Unlock()
			_ = conn.Close()
			return
		}
		service.conns[conn] = struct{}{}
		service.mu.Unlock()
		go service.serveConn(conn)
	}
}

func (service *tcpService) serveConn(conn net.Conn) {
	defer func() {
		service.mu.Lock()
		if _, exists := service.conns[conn]; exists {
			delete(service.conns, conn)
			if err := conn.Close(); err != nil {
				service.metadata.LastError = err.Error()
			}
		}
		service.mu.Unlock()
	}()

	if err := service.handler(conn); err != nil {
		service.mu.Lock()
		if service.listener != nil {
			service.metadata.LastError = err.Error()
		}
		service.mu.Unlock()
	}
}

func (service *tcpService) Close() error {
	service.mu.Lock()
	defer service.mu.Unlock()

	closeErr := service.listener.Close()
	service.listener = nil
	for conn := range service.conns {
		delete(service.conns, conn)
		closeErr = errors.Join(closeErr, conn.Close())
	}
	return closeErr
}

func NewService(name string, config map[string]string) (Service, error) {
	switch name {
	case "echo":
		return newEchoService(config)
	case "http":
		return newHTTPService(config)
	case "ssh":
		return newSSHService(config)
	default:
		return nil, fmt.Errorf("unsupported service %q", name)
	}
}

func servicePort(config map[string]string) (int, error) {
	port, err := strconv.Atoi(config["port"])
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("Port must be between 1 and 65535")
	}
	return port, nil
}
