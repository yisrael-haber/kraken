package operations

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

const (
	serviceEchoID = "echo"
	serviceHTTPID = "http"
	serviceSSHID  = "ssh"
)

type serviceContext struct {
	Identity adoption.Identity
	Service  *adoption.ManagedService
}

type serviceDefinition struct {
	ID          string
	Label       string
	DefaultPort int
	Fields      []adoption.ServiceFieldDefinition
}

var serviceDefinitions = []serviceDefinition{
	echoServiceDefinition(),
	httpServiceDefinition(),
	sshServiceDefinition(),
}

func ListServiceDefinitions() []adoption.ServiceDefinition {
	definitions := make([]adoption.ServiceDefinition, 0, len(serviceDefinitions))
	for _, definition := range serviceDefinitions {
		definitions = append(definitions, adoption.ServiceDefinition{
			Service:     definition.ID,
			Label:       definition.Label,
			DefaultPort: definition.DefaultPort,
			Fields:      definition.Fields,
		})
	}

	return definitions
}

func serviceByID(service string) (serviceDefinition, bool) {
	service = strings.TrimSpace(service)
	for _, definition := range serviceDefinitions {
		if strings.EqualFold(definition.ID, service) {
			return definition, true
		}
	}
	return serviceDefinition{}, false
}

func StartService(manager *adoption.Manager, ip net.IP, service string, config map[string]string) (adoption.Identity, error) {
	definition, ok := serviceByID(service)
	if !ok {
		return adoption.Identity{}, fmt.Errorf("unsupported service %q", service)
	}

	config, err := normalizeServiceConfig(definition, config)
	if err != nil {
		return adoption.Identity{}, err
	}
	port, err := servicePort(definition, config)
	if err != nil {
		return adoption.Identity{}, err
	}
	managed := adoption.ManagedService{
		Service: definition.ID,
		Port:    port,
		Config:  redactedServiceConfig(definition, config),
		Summary: serviceSummary(definition.ID, config),
	}

	return manager.StartService(ip, managed, func(identity *adoption.Identity, managed *adoption.ManagedService) (adoption.ServiceProcess, error) {
		return startServiceProcess(identity, managed, definition.ID, config)
	})
}

func startServiceProcess(identity *adoption.Identity, managed *adoption.ManagedService, service string, config map[string]string) (adoption.ServiceProcess, error) {
	if identity == nil || identity.IP.To4() == nil {
		return nil, fmt.Errorf("service requires an adopted identity")
	}

	tcpListener, err := identity.ListenTCP(managed.Port)
	if err != nil {
		return nil, err
	}

	ctx := serviceContext{
		Identity: *identity,
		Service:  managed,
	}
	var process adoption.ServiceProcess
	switch service {
	case serviceEchoID:
		process, err = startEchoService(ctx, tcpListener, config)
	case serviceHTTPID:
		process, err = startHTTPService(ctx, tcpListener, config)
	case serviceSSHID:
		process, err = startSSHService(ctx, tcpListener, config)
	}
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}
	return process, nil
}

func normalizeServiceConfig(definition serviceDefinition, raw map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(definition.Fields))
	for key := range raw {
		found := false
		for _, field := range definition.Fields {
			if field.Name == key {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%s is not supported for %s", key, definition.Label)
		}
	}

	for _, field := range definition.Fields {
		value := strings.TrimSpace(raw[field.Name])
		if value == "" {
			value = field.DefaultValue
		}
		if value == "" && field.Name == "port" && definition.DefaultPort > 0 {
			value = strconv.Itoa(definition.DefaultPort)
		}
		if value == "" && field.Required {
			return nil, fmt.Errorf("%s is required", field.Label)
		}
		if value != "" && field.Type == "select" && !serviceOptionAllowed(field.Options, value) {
			return nil, fmt.Errorf("%s has an invalid value", field.Label)
		}
		config[field.Name] = value
	}

	return config, nil
}

func serviceOptionAllowed(options []adoption.ServiceFieldOption, value string) bool {
	for _, option := range options {
		if option.Value == value {
			return true
		}
	}

	return false
}

func servicePort(definition serviceDefinition, config map[string]string) (int, error) {
	value := strings.TrimSpace(config["port"])
	if value == "" && definition.DefaultPort > 0 {
		return definition.DefaultPort, nil
	}
	if value == "" {
		return 0, fmt.Errorf("Port is required")
	}

	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("Port must be numeric")
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("Port must be between 1 and 65535")
	}

	return port, nil
}

func newApplicationScriptBinding(ctx serviceContext, service scriptpkg.ApplicationServiceInfo, metadata map[string]any) (*applicationScriptBinding, error) {
	return resolveApplicationScriptBinding(
		ctx.Identity,
		service,
		metadata,
	)
}

func serviceSummary(service string, config map[string]string) []adoption.ServiceSummaryItem {
	switch service {
	case serviceHTTPID:
		return httpServiceSummary(config)
	case serviceSSHID:
		return sshServiceSummary(config)
	default:
		return nil
	}
}

func redactedServiceConfig(definition serviceDefinition, config map[string]string) map[string]string {
	if len(config) == 0 {
		return nil
	}

	cloned := maps.Clone(config)
	for _, field := range definition.Fields {
		if field.Type == "secret" && cloned[field.Name] != "" {
			cloned[field.Name] = "configured"
		}
	}
	return cloned
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return true
	}

	return strings.Contains(err.Error(), "use of closed network connection")
}
