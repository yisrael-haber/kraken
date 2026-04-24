package capture

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

const (
	listenerServiceEchoID = "echo"
	listenerServiceHTTPID = "http"
	listenerServiceSSHID  = "ssh"
)

type ServiceContext struct {
	Identity           adoption.Identity
	LookupStoredScript adoption.ScriptLookupFunc
	RecordError        func(adoption.ScriptRuntimeError)
	ClearError         func()
}

type RunningService interface {
	Close() error
	Wait() error
}

type ListenerServiceFactory func(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error)

type ListenerServiceDefinition struct {
	ID          string
	Label       string
	DefaultPort int
	Fields      []adoption.ServiceFieldDefinition
	Start       ListenerServiceFactory
	Summary     func(config map[string]string) []adoption.ServiceSummaryItem
}

type serviceSpec struct {
	service string
	config  map[string]string
}

type managedService struct {
	mu        sync.RWMutex
	spec      serviceSpec
	port      int
	started   time.Time
	active    bool
	stopping  bool
	lastErr   string
	scriptErr *adoption.ScriptRuntimeError
	running   RunningService
	onDone    func()
	done      chan struct{}
	stopOnce  sync.Once
}

var (
	listenerServicesMu    sync.RWMutex
	listenerServicesOrder []string
	listenerServices      = make(map[string]ListenerServiceDefinition)
	registerServicesOnce  sync.Once
)

func RegisterListenerService(definition ListenerServiceDefinition) error {
	normalized, err := normalizeListenerServiceDefinition(definition)
	if err != nil {
		return err
	}

	listenerServicesMu.Lock()
	defer listenerServicesMu.Unlock()

	if _, exists := listenerServices[normalized.ID]; exists {
		return fmt.Errorf("listener service %q is already registered", normalized.ID)
	}

	listenerServices[normalized.ID] = normalized
	listenerServicesOrder = append(listenerServicesOrder, normalized.ID)
	return nil
}

func ListServiceDefinitions() []adoption.ServiceDefinition {
	ensureListenerServicesRegistered()

	listenerServicesMu.RLock()
	defer listenerServicesMu.RUnlock()

	definitions := make([]adoption.ServiceDefinition, 0, len(listenerServicesOrder))
	for _, serviceID := range listenerServicesOrder {
		definition := listenerServices[serviceID]
		definitions = append(definitions, adoption.ServiceDefinition{
			Service:     definition.ID,
			Label:       definition.Label,
			DefaultPort: definition.DefaultPort,
			Fields:      cloneServiceFieldDefinitions(definition.Fields),
		})
	}

	return definitions
}

func ensureListenerServicesRegistered() {
	registerServicesOnce.Do(func() {
		for _, definition := range []ListenerServiceDefinition{
			echoListenerServiceDefinition(),
			httpListenerServiceDefinition(),
			sshListenerServiceDefinition(),
		} {
			if err := RegisterListenerService(definition); err != nil {
				panic(err)
			}
		}
	})
}

func normalizeListenerServiceDefinition(definition ListenerServiceDefinition) (ListenerServiceDefinition, error) {
	definition.ID = strings.ToLower(strings.TrimSpace(definition.ID))
	definition.Label = strings.TrimSpace(definition.Label)
	if definition.ID == "" {
		return ListenerServiceDefinition{}, fmt.Errorf("listener service id is required")
	}
	if definition.Label == "" {
		return ListenerServiceDefinition{}, fmt.Errorf("listener service %q label is required", definition.ID)
	}
	if definition.Start == nil {
		return ListenerServiceDefinition{}, fmt.Errorf("listener service %q start function is required", definition.ID)
	}
	if definition.DefaultPort < 0 || definition.DefaultPort > 65535 {
		return ListenerServiceDefinition{}, fmt.Errorf("listener service %q default port must be between 0 and 65535", definition.ID)
	}

	fields := make([]adoption.ServiceFieldDefinition, 0, len(definition.Fields))
	seenFields := make(map[string]struct{}, len(definition.Fields))
	for _, field := range definition.Fields {
		field.Name = strings.TrimSpace(field.Name)
		field.Label = strings.TrimSpace(field.Label)
		field.Type = strings.TrimSpace(field.Type)
		field.DefaultValue = strings.TrimSpace(field.DefaultValue)
		field.Placeholder = strings.TrimSpace(field.Placeholder)
		field.ScriptSurface = strings.TrimSpace(field.ScriptSurface)
		if field.Name == "" || field.Label == "" || field.Type == "" {
			return ListenerServiceDefinition{}, fmt.Errorf("listener service %q field definitions must include name, label, and type", definition.ID)
		}
		if _, exists := seenFields[field.Name]; exists {
			return ListenerServiceDefinition{}, fmt.Errorf("listener service %q field %q is duplicated", definition.ID, field.Name)
		}
		seenFields[field.Name] = struct{}{}
		field.Options = cloneServiceFieldOptions(field.Options)
		fields = append(fields, field)
	}
	definition.Fields = fields

	return definition, nil
}

func listenerServiceDefinitionByID(service string) (ListenerServiceDefinition, bool) {
	ensureListenerServicesRegistered()

	listenerServicesMu.RLock()
	defer listenerServicesMu.RUnlock()

	definition, ok := listenerServices[strings.ToLower(strings.TrimSpace(service))]
	return definition, ok
}

func (listener *pcapAdoptionListener) StartService(source adoption.Identity, service string, config map[string]string) (adoption.ServiceStatus, error) {
	key := recordingKey(source.IP())
	if key == "" {
		return adoption.ServiceStatus{}, fmt.Errorf("service requires a valid IPv4 identity")
	}

	group, err := listener.engineForIdentity(source)
	if err != nil {
		return adoption.ServiceStatus{}, err
	}

	spec := serviceSpec{
		service: strings.ToLower(strings.TrimSpace(service)),
		config:  cloneServiceConfig(config),
	}

	previous := listener.takeService(source.IP(), spec.service)
	if previous != nil {
		previous.stop()
	}

	managed, err := startManagedService(group, source, spec, listener.resolveScript)
	if err != nil {
		return adoption.ServiceStatus{}, err
	}

	listener.storeService(source.IP(), managed)
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
	key := recordingKey(ip)
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
	key := recordingKey(ip)
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

	key := recordingKey(ip)
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
	key := recordingKey(ip)
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
	byService[managed.specSnapshot().service] = managed
	listener.servicesMu.Unlock()
}

func (listener *pcapAdoptionListener) forceReleaseServicePort(ip net.IP, port int) error {
	ip = common.NormalizeIPv4(ip)
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
		engine := listener.engineForIP(ip)
		if engine == nil {
			return true
		}

		probe, err := listenEngineTCP(engine, ip, port)
		if err == nil {
			_ = probe.Close()
			return true
		}

		time.Sleep(25 * time.Millisecond)
	}

	return false
}

func (listener *pcapAdoptionListener) engineForIP(ip net.IP) *adoptedEngine {
	key := compactIPv4FromIP(ip)
	if !key.valid {
		return nil
	}

	return listener.currentEngines()[key]
}

func (listener *pcapAdoptionListener) recycleEngineForIP(ip net.IP) error {
	engine := listener.engineForIP(ip)
	if engine == nil {
		return nil
	}

	identity := engine.identitySnapshot()
	if identity == nil {
		return nil
	}

	suspended := listener.takeServices(identity.IP())
	for _, service := range suspended {
		service.stop()
	}

	replacement, err := newAdoptedEngine(adoptedEngineConfigForIdentity(identity, listener.routes), listener.handleEngineOutbound)
	if err != nil {
		listener.restoreServices(identity, engine, suspended)
		return err
	}
	if err := replacement.addIdentity(identity); err != nil {
		replacement.close()
		listener.restoreServices(identity, engine, suspended)
		return err
	}

	listener.stackMu.Lock()
	listener.engines[compactIPv4FromIP(identity.IP())] = replacement
	listener.publishEngineSnapshotLocked()
	listener.stackMu.Unlock()

	engine.close()
	listener.restoreServices(identity, replacement, suspended)

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

func (listener *pcapAdoptionListener) restoreServices(identity adoption.Identity, engine *adoptedEngine, suspended []*managedService) {
	if identity == nil || engine == nil || len(suspended) == 0 {
		return
	}

	for _, previous := range suspended {
		if previous == nil {
			continue
		}

		spec := previous.specSnapshot()
		managed, err := startManagedService(engine, identity, spec, listener.resolveScript)
		if err != nil {
			definition, ok := listenerServiceDefinitionByID(spec.service)
			port := 0
			if ok {
				port, _ = listenerServicePort(definition, spec.config)
			}
			managed = newFailedManagedService(spec, port, err)
		}
		listener.storeService(identity.IP(), managed)
	}
}

func startManagedService(engine *adoptedEngine, identity adoption.Identity, spec serviceSpec, resolveScript adoption.ScriptLookupFunc) (*managedService, error) {
	if identity == nil {
		return nil, fmt.Errorf("service requires an adopted identity")
	}

	definition, ok := listenerServiceDefinitionByID(spec.service)
	if !ok {
		return nil, fmt.Errorf("unsupported service %q", spec.service)
	}

	config, err := normalizeListenerServiceConfig(definition, spec.config)
	if err != nil {
		return nil, err
	}
	spec.config = config

	port, err := listenerServicePort(definition, config)
	if err != nil {
		return nil, err
	}

	tcpListener, err := listenEngineTCP(engine, identity.IP(), port)
	if err != nil {
		return nil, err
	}

	managed := newManagedService(spec, port)
	running, err := definition.Start(ServiceContext{
		Identity:           identity,
		LookupStoredScript: resolveScript,
		RecordError:        managed.recordScriptError,
		ClearError:         managed.clearLastError,
	}, net.Listener(tcpListener), config)
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	managed.start(running)
	return managed, nil
}

func normalizeListenerServiceConfig(definition ListenerServiceDefinition, raw map[string]string) (map[string]string, error) {
	config := make(map[string]string, len(definition.Fields))
	if len(raw) != 0 {
		for key := range raw {
			if !listenerServiceHasField(definition.Fields, key) {
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
		if value != "" && field.Type == adoption.ServiceFieldTypeSelect && !listenerServiceOptionAllowed(field.Options, value) {
			return nil, fmt.Errorf("%s has an invalid value", field.Label)
		}
		config[field.Name] = value
	}

	return config, nil
}

func listenerServiceHasField(fields []adoption.ServiceFieldDefinition, name string) bool {
	for _, field := range fields {
		if field.Name == name {
			return true
		}
	}

	return false
}

func listenerServiceOptionAllowed(options []adoption.ServiceFieldOption, value string) bool {
	for _, option := range options {
		if option.Value == value {
			return true
		}
	}

	return false
}

func listenerServicePort(definition ListenerServiceDefinition, config map[string]string) (int, error) {
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
	definition, ok := listenerServiceDefinitionByID(service)
	if !ok || definition.Summary == nil {
		return nil
	}

	return slices.Clone(definition.Summary(config))
}

func newManagedService(spec serviceSpec, port int) *managedService {
	return &managedService{
		spec:    serviceSpec{service: spec.service, config: cloneServiceConfig(spec.config)},
		port:    port,
		started: time.Now().UTC(),
		active:  true,
		done:    make(chan struct{}),
	}
}

func newFailedManagedService(spec serviceSpec, port int, err error) *managedService {
	service := &managedService{
		spec:   serviceSpec{service: spec.service, config: cloneServiceConfig(spec.config)},
		port:   port,
		done:   make(chan struct{}),
		active: false,
	}
	service.fail(err)
	close(service.done)
	return service
}

func newApplicationScriptBinding(ctx ServiceContext, service scriptpkg.ApplicationServiceInfo, metadata map[string]interface{}) (*applicationScriptBinding, error) {
	return resolveApplicationScriptBinding(
		ctx.Identity,
		ctx.LookupStoredScript,
		service,
		metadata,
		ctx.RecordError,
		ctx.ClearError,
	)
}

func (service *managedService) start(running RunningService) {
	if service == nil {
		return
	}

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
	onDone := service.onDone
	service.mu.Unlock()

	if onDone != nil {
		onDone()
	}
	close(done)
}

func (service *managedService) snapshot() adoption.ServiceStatus {
	if service == nil {
		return adoption.ServiceStatus{}
	}

	service.mu.RLock()
	spec := service.spec
	status := adoption.ServiceStatus{
		Service:   spec.service,
		Active:    service.active,
		Port:      service.port,
		Config:    service.snapshotConfigLocked(),
		Summary:   serviceSummary(spec.service, spec.config),
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

func (service *managedService) specSnapshot() serviceSpec {
	if service == nil {
		return serviceSpec{}
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	return serviceSpec{
		service: service.spec.service,
		config:  cloneServiceConfig(service.spec.config),
	}
}

func (service *managedService) fail(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	service.active = false
	service.lastErr = err.Error()
	service.mu.Unlock()
}

func (service *managedService) recordScriptError(err adoption.ScriptRuntimeError) {
	if service == nil || err.LastError == "" {
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
	if service == nil {
		return
	}

	service.mu.Lock()
	if service.active {
		service.lastErr = ""
		service.scriptErr = nil
	}
	service.mu.Unlock()
}

func (service *managedService) stop() {
	if service == nil {
		return
	}

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

func (service *managedService) snapshotConfigLocked() map[string]string {
	if service == nil {
		return nil
	}

	return redactedServiceConfig(service.spec.service, service.spec.config)
}

func cloneServiceConfig(config map[string]string) map[string]string {
	return maps.Clone(config)
}

func redactedServiceConfig(service string, config map[string]string) map[string]string {
	if len(config) == 0 {
		return nil
	}

	cloned := maps.Clone(config)
	definition, ok := listenerServiceDefinitionByID(service)
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

func cloneServiceFieldDefinitions(fields []adoption.ServiceFieldDefinition) []adoption.ServiceFieldDefinition {
	if len(fields) == 0 {
		return nil
	}

	cloned := make([]adoption.ServiceFieldDefinition, 0, len(fields))
	for _, field := range fields {
		field.Options = cloneServiceFieldOptions(field.Options)
		cloned = append(cloned, field)
	}
	return cloned
}

func cloneServiceFieldOptions(options []adoption.ServiceFieldOption) []adoption.ServiceFieldOption {
	return slices.Clone(options)
}

func listenEngineTCP(engine *adoptedEngine, ip net.IP, port int) (*gonet.TCPListener, error) {
	ip = common.NormalizeIPv4(ip)
	if engine == nil || ip == nil {
		return nil, fmt.Errorf("service requires a valid IPv4 identity")
	}

	return gonet.ListenTCP(engine.stack, tcpip.FullAddress{
		NIC:  adoptedNetstackNICID,
		Addr: tcpip.AddrFrom4Slice(ip.To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
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
