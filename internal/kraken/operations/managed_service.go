package operations

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

const (
	serviceEchoID = "echo"
	serviceHTTPID = "http"
	serviceSSHID  = "ssh"
)

type serviceContext struct {
	Identity           adoption.Identity
	LookupStoredScript adoption.ScriptLookupFunc
	RecordError        func(adoption.ScriptRuntimeError)
	ClearError         func()
}

type runningService interface {
	Close() error
	Wait() error
}

type serviceDefinition struct {
	ID          string
	Label       string
	DefaultPort int
	Fields      []adoption.ServiceFieldDefinition
	Start       func(ctx serviceContext, listener net.Listener, config map[string]string) (runningService, error)
	Summary     func(config map[string]string) []adoption.ServiceSummaryItem
}

type managedService struct {
	mu        sync.RWMutex
	service   string
	config    map[string]string
	port      int
	started   time.Time
	active    bool
	stopping  bool
	lastErr   string
	scriptErr *adoption.ScriptRuntimeError
	running   runningService
	done      chan struct{}
	stopOnce  sync.Once
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
	service = strings.ToLower(strings.TrimSpace(service))
	for _, definition := range serviceDefinitions {
		if definition.ID == service {
			return definition, true
		}
	}
	return serviceDefinition{}, false
}

func (listener *pcapAdoptionListener) StartService(source *adoption.Identity, service string, config map[string]string) (adoption.ServiceStatus, error) {
	if source == nil {
		return adoption.ServiceStatus{}, fmt.Errorf("service requires a valid IPv4 identity")
	}
	key := engineKey(source.IP)
	if key == "" {
		return adoption.ServiceStatus{}, fmt.Errorf("service requires a valid IPv4 identity")
	}

	if err := listener.ensureEngine(source); err != nil {
		return adoption.ServiceStatus{}, err
	}

	service = strings.ToLower(strings.TrimSpace(service))

	previous := listener.takeService(source.IP, service)
	if previous != nil {
		previous.stop()
	}

	managed, err := startManagedService(source, service, config, listener.resolveScript)
	if err != nil {
		return adoption.ServiceStatus{}, err
	}

	listener.storeService(source.IP, managed)
	return managed.snapshot(), nil
}

func (listener *pcapAdoptionListener) StopService(ip net.IP, service string) error {
	managed := listener.takeService(ip, service)
	if managed != nil {
		managed.stop()
		if err := listener.forceReleaseServicePort(ip, managed.port); err != nil {
			return err
		}
	}

	return nil
}

func (listener *pcapAdoptionListener) ServiceSnapshot(ip net.IP) []adoption.ServiceStatus {
	key := engineKey(ip)
	if key == "" {
		return nil
	}

	listener.servicesMu.RLock()
	services := listener.services[key]
	listener.servicesMu.RUnlock()
	if len(services) == 0 {
		return nil
	}

	items := make([]adoption.ServiceStatus, 0, len(services))
	for _, managed := range services {
		if managed != nil {
			items = append(items, managed.snapshot())
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Service < items[j].Service
	})

	return items
}

func (listener *pcapAdoptionListener) takeService(ip net.IP, service string) *managedService {
	key := engineKey(ip)
	if key == "" {
		return nil
	}

	service = strings.ToLower(strings.TrimSpace(service))

	listener.servicesMu.Lock()
	defer listener.servicesMu.Unlock()

	byService := listener.services[key]
	if len(byService) == 0 {
		return nil
	}

	managed := byService[service]
	delete(byService, service)
	if len(byService) == 0 {
		delete(listener.services, key)
	}

	return managed
}

func (listener *pcapAdoptionListener) takeServices(ip net.IP) []*managedService {
	listener.servicesMu.Lock()
	defer listener.servicesMu.Unlock()

	if len(listener.services) == 0 {
		return nil
	}

	if ip == nil {
		items := make([]*managedService, 0, len(listener.services)*2)
		for key, byService := range listener.services {
			items = append(items, drainManagedServices(byService)...)
			delete(listener.services, key)
		}
		return items
	}

	key := engineKey(ip)
	if key == "" {
		return nil
	}

	byService := listener.services[key]
	if len(byService) == 0 {
		return nil
	}

	items := drainManagedServices(byService)
	delete(listener.services, key)

	return items
}

func (listener *pcapAdoptionListener) storeService(ip net.IP, managed *managedService) {
	key := engineKey(ip)
	if key == "" || managed == nil {
		return
	}

	listener.servicesMu.Lock()
	if listener.services == nil {
		listener.services = make(map[string]map[string]*managedService)
	}
	byService := listener.services[key]
	if byService == nil {
		byService = make(map[string]*managedService)
		listener.services[key] = byService
	}
	byService[managed.service] = managed
	listener.servicesMu.Unlock()
}

func (listener *pcapAdoptionListener) forceReleaseServicePort(ip net.IP, port int) error {
	ip = ip.To4()
	if listener == nil || ip == nil || port <= 0 {
		return nil
	}
	if listener.servicePortReleased(ip, port) {
		return nil
	}
	if err := listener.recycleEngineForIP(ip); err != nil {
		return err
	}
	if listener.servicePortReleased(ip, port) {
		return nil
	}
	return fmt.Errorf("port %d is still busy", port)
}

func (listener *pcapAdoptionListener) servicePortReleased(ip net.IP, port int) bool {
	for attempt := 0; attempt < 6; attempt++ {
		identity := listener.identityForIP(ip)
		if identity == nil {
			return true
		}

		probe, err := identity.ListenTCP(port)
		if err == nil {
			_ = probe.Close()
			return true
		}

		time.Sleep(25 * time.Millisecond)
	}

	return false
}

func (listener *pcapAdoptionListener) identityForIP(ip net.IP) *adoption.Identity {
	key := engineKey(ip)
	if key == "" {
		return nil
	}

	return listener.currentEngines()[key]
}

func (listener *pcapAdoptionListener) recycleEngineForIP(ip net.IP) error {
	identity := listener.identityForIP(ip)
	if identity == nil {
		return nil
	}

	suspended := listener.takeServices(identity.IP)
	for _, service := range suspended {
		service.stop()
	}

	identity.CloseEngine()
	if err := identity.EnsureEngine(listener.routes, listener.handleEngineOutbound); err != nil {
		listener.restoreServices(identity, suspended)
		return err
	}

	listener.stackMu.Lock()
	listener.engines[engineKey(identity.IP)] = identity
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	listener.restoreServices(identity, suspended)

	return nil
}

func drainManagedServices(byService map[string]*managedService) []*managedService {
	if len(byService) == 0 {
		return nil
	}

	items := make([]*managedService, 0, len(byService))
	for service, managed := range byService {
		if managed != nil {
			items = append(items, managed)
		}
		delete(byService, service)
	}

	return items
}

func (listener *pcapAdoptionListener) restoreServices(identity *adoption.Identity, suspended []*managedService) {
	if identity == nil || identity.IP.To4() == nil || len(suspended) == 0 {
		return
	}

	for _, previous := range suspended {
		if previous == nil {
			continue
		}

		service, config := previous.snapshotStartConfig()
		managed, err := startManagedService(identity, service, config, listener.resolveScript)
		if err != nil {
			definition, ok := serviceByID(service)
			port := 0
			if ok {
				port, _ = servicePort(definition, config)
			}
			managed = newFailedManagedService(service, config, port, err)
		}
		listener.storeService(identity.IP, managed)
	}
}

func startManagedService(identity *adoption.Identity, service string, rawConfig map[string]string, resolveScript adoption.ScriptLookupFunc) (*managedService, error) {
	if identity == nil || identity.IP.To4() == nil {
		return nil, fmt.Errorf("service requires an adopted identity")
	}

	definition, ok := serviceByID(service)
	if !ok {
		return nil, fmt.Errorf("unsupported service %q", service)
	}

	config, err := normalizeServiceConfig(definition, rawConfig)
	if err != nil {
		return nil, err
	}

	port, err := servicePort(definition, config)
	if err != nil {
		return nil, err
	}

	tcpListener, err := identity.ListenTCP(port)
	if err != nil {
		return nil, err
	}

	managed := newManagedService(service, config, port)
	running, err := definition.Start(serviceContext{
		Identity:           *identity,
		LookupStoredScript: resolveScript,
		RecordError:        managed.recordScriptError,
		ClearError:         managed.clearLastError,
	}, tcpListener, config)
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	managed.start(running)
	return managed, nil
}

func normalizeServiceConfig(definition serviceDefinition, raw map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(definition.Fields))
	if len(raw) != 0 {
		for key := range raw {
			if !serviceHasField(definition.Fields, key) {
				return nil, fmt.Errorf("%s is not supported for %s", key, definition.Label)
			}
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
		if value != "" && field.Type == adoption.ServiceFieldTypeSelect && !serviceOptionAllowed(field.Options, value) {
			return nil, fmt.Errorf("%s has an invalid value", field.Label)
		}
		config[field.Name] = value
	}

	return config, nil
}

func serviceHasField(fields []adoption.ServiceFieldDefinition, name string) bool {
	for _, field := range fields {
		if field.Name == name {
			return true
		}
	}

	return false
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

func serviceSummary(service string, config map[string]string) []adoption.ServiceSummaryItem {
	definition, ok := serviceByID(service)
	if !ok || definition.Summary == nil {
		return nil
	}

	return definition.Summary(config)
}

func newManagedService(service string, config map[string]string, port int) *managedService {
	return &managedService{
		service: service,
		config:  config,
		port:    port,
		started: time.Now().UTC(),
		active:  true,
		done:    make(chan struct{}),
	}
}

func newFailedManagedService(serviceName string, config map[string]string, port int, err error) *managedService {
	service := &managedService{
		service: serviceName,
		config:  config,
		port:    port,
		done:    make(chan struct{}),
		active:  false,
	}
	service.fail(err)
	close(service.done)
	return service
}

func newApplicationScriptBinding(ctx serviceContext, service scriptpkg.ApplicationServiceInfo, metadata map[string]interface{}) (*applicationScriptBinding, error) {
	return resolveApplicationScriptBinding(
		ctx.Identity,
		ctx.LookupStoredScript,
		service,
		metadata,
		ctx.RecordError,
		ctx.ClearError,
	)
}

func (service *managedService) start(running runningService) {
	service.mu.Lock()
	service.running = running
	service.mu.Unlock()

	go service.monitor()
}

func (service *managedService) monitor() {
	var waitErr error

	service.mu.RLock()
	running := service.running
	done := service.done
	service.mu.RUnlock()

	if running != nil {
		waitErr = running.Wait()
	}

	service.mu.Lock()
	stopping := service.stopping
	service.active = false
	if !stopping && waitErr != nil {
		service.lastErr = waitErr.Error()
	}
	service.mu.Unlock()
	close(done)
}

func (service *managedService) snapshot() adoption.ServiceStatus {
	service.mu.RLock()
	status := adoption.ServiceStatus{
		Service:   service.service,
		Active:    service.active,
		Port:      service.port,
		Config:    redactedServiceConfig(service.service, service.config),
		Summary:   serviceSummary(service.service, service.config),
		LastError: service.lastErr,
	}
	if service.scriptErr != nil {
		cloned := *service.scriptErr
		status.ScriptError = &cloned
	}
	if !service.started.IsZero() {
		status.StartedAt = service.started.Format(time.RFC3339Nano)
	}
	service.mu.RUnlock()

	return status
}

func (service *managedService) snapshotStartConfig() (string, map[string]string) {
	service.mu.RLock()
	defer service.mu.RUnlock()

	return service.service, maps.Clone(service.config)
}

func (service *managedService) fail(err error) {
	if err == nil {
		return
	}

	service.mu.Lock()
	service.active = false
	service.lastErr = err.Error()
	service.mu.Unlock()
}

func (service *managedService) recordScriptError(err adoption.ScriptRuntimeError) {
	if err.LastError == "" {
		return
	}

	service.mu.Lock()
	if service.active {
		service.lastErr = err.LastError
		service.scriptErr = &err
	}
	service.mu.Unlock()
}

func (service *managedService) clearLastError() {
	service.mu.Lock()
	if service.active {
		service.lastErr = ""
		service.scriptErr = nil
	}
	service.mu.Unlock()
}

func (service *managedService) stop() {
	service.stopOnce.Do(func() {
		service.mu.Lock()
		service.stopping = true
		service.active = false
		service.lastErr = ""
		service.scriptErr = nil
		running := service.running
		done := service.done
		service.mu.Unlock()

		if running != nil {
			_ = running.Close()
		}
		if done != nil {
			<-done
		}
	})
}

func redactedServiceConfig(service string, config map[string]string) map[string]string {
	if len(config) == 0 {
		return nil
	}

	cloned := maps.Clone(config)
	definition, ok := serviceByID(service)
	if !ok {
		return cloned
	}
	for _, field := range definition.Fields {
		if field.Type == adoption.ServiceFieldTypeSecret && cloned[field.Name] != "" {
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
