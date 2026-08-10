package operations

import (
	"fmt"
	"net"
	"strconv"
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
	Active    bool                 `json:"active"`
	StartedAt string               `json:"startedAt,omitempty"`
	LastError string               `json:"lastError,omitempty"`
}

type ServiceSummaryItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
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
