package adoption

import (
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/operations"
)

func ListServiceDefinitions() []ServiceDefinition {
	return []ServiceDefinition{
		{Service: "echo", Label: "Echo", DefaultPort: 7007, Fields: []ServiceFieldDefinition{
			{Name: "port", Label: "Port", Type: "port", Required: true, DefaultValue: "7007"},
		}},
		{Service: "http", Label: "HTTP", DefaultPort: 8080, Fields: []ServiceFieldDefinition{
			{Name: "port", Label: "Port", Type: "port", Required: true, DefaultValue: "8080"},
			{Name: "protocol", Label: "Protocol", Type: "select", Required: true, DefaultValue: "http", Options: []ServiceFieldOption{
				{Value: "http", Label: "HTTP"},
				{Value: "https", Label: "HTTPS"},
			}},
			{Name: "rootDirectory", Label: "Root", Type: "directory", Required: true},
		}},
		{Service: "ssh", Label: "SSH", DefaultPort: 2222, Fields: []ServiceFieldDefinition{
			{Name: "port", Label: "Port", Type: "port", Required: true, DefaultValue: "2222"},
			{Name: "username", Label: "User", Type: "text", Placeholder: "researcher"},
			{Name: "password", Label: "Password", Type: "secret", Placeholder: "secret"},
			{Name: "authorizedKey", Label: "Key", Type: "text", Placeholder: "ssh-ed25519 AAAA..."},
			{Name: "allowPty", Label: "Terminal", Type: "select", DefaultValue: "true", Options: []ServiceFieldOption{
				{Value: "true", Label: "On"},
				{Value: "false", Label: "Off"},
			}},
		}},
	}
}

func (s *Manager) StartConfiguredService(ip net.IP, service string, config map[string]string) (Identity, error) {
	service = strings.TrimSpace(service)
	switch service {
	case "echo":
		port, err := servicePort(config, 7007)
		if err != nil {
			return Identity{}, err
		}
		return s.StartService(ip, ManagedService{Service: service, Port: port, Config: serviceConfig(config, map[string]string{"port": "7007"})}, func(listener net.Listener) (ServiceProcess, error) {
			return operations.StartEcho(listener)
		})
	case "http":
		port, err := servicePort(config, 8080)
		if err != nil {
			return Identity{}, err
		}
		status := ManagedService{Service: service, Port: port, Config: serviceConfig(config, map[string]string{"port": "8080", "protocol": "http"})}
		protocol := "HTTP"
		if config["protocol"] == "https" {
			protocol = "HTTPS"
		}
		status.Summary = []ServiceSummaryItem{{Label: "Proto", Value: protocol}}
		if root := config["rootDirectory"]; root != "" {
			status.Summary = append(status.Summary, ServiceSummaryItem{Label: "Root", Value: root, Code: true})
		}
		return s.StartService(ip, status, func(listener net.Listener) (ServiceProcess, error) {
			return operations.StartHTTP(listener, config)
		})
	case "ssh":
		port, err := servicePort(config, 2222)
		if err != nil {
			return Identity{}, err
		}
		out := serviceConfig(config, map[string]string{"port": "2222", "allowPty": "true"})
		if out["password"] != "" {
			out["password"] = "configured"
		}
		status := ManagedService{
			Service: service,
			Port:    port,
			Config:  out,
			Summary: []ServiceSummaryItem{{Label: "Auth", Value: sshAuthLabel(config)}},
		}
		if username := config["username"]; username != "" {
			status.Summary = append(status.Summary, ServiceSummaryItem{Label: "User", Value: username})
		}
		if config["allowPty"] != "false" {
			status.Summary = append(status.Summary, ServiceSummaryItem{Label: "PTY", Value: "On"})
		}
		return s.StartService(ip, status, func(listener net.Listener) (ServiceProcess, error) {
			return operations.StartSSH(listener, config)
		})
	default:
		return Identity{}, fmt.Errorf("unsupported service %q", service)
	}
}

func servicePort(config map[string]string, fallback int) (int, error) {
	value := strings.TrimSpace(config["port"])
	if value == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("Port must be between 1 and 65535")
	}
	return port, nil
}

func serviceConfig(config map[string]string, defaults map[string]string) map[string]string {
	out := maps.Clone(defaults)
	for key, value := range config {
		if strings.TrimSpace(value) != "" {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func sshAuthLabel(config map[string]string) string {
	hasPassword := strings.TrimSpace(config["password"]) != ""
	hasKey := strings.TrimSpace(config["authorizedKey"]) != ""

	switch {
	case hasPassword && hasKey:
		return "Pass+Key"
	case hasPassword:
		return "Pass"
	case hasKey:
		return "Key"
	default:
		return "None"
	}
}
