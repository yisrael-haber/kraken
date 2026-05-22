package operations

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
	switch strings.TrimSpace(name) {
	case "echo":
		return NewEcho(config)
	case "http":
		return NewHTTP(config)
	case "ssh":
		return NewSSH(config)
	default:
		return nil, fmt.Errorf("unsupported service %q", name)
	}
}

func servicePort(config map[string]string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(config["port"]))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("Port must be between 1 and 65535")
	}
	return port, nil
}
