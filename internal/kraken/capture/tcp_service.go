package capture

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
	gossh "golang.org/x/crypto/ssh"
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
	RecordError        func(error)
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

	tracksHTTP bool
}

type serviceSpec struct {
	service string
	config  map[string]string
}

type managedService struct {
	mu       sync.RWMutex
	spec     serviceSpec
	port     int
	started  time.Time
	active   bool
	stopping bool
	lastErr  string
	running  RunningService
	onDone   func()
	done     chan struct{}
	stopOnce sync.Once
}

type echoListenerService struct {
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	waitErr error
}

type httpListenerService struct {
	server   *http.Server
	listener net.Listener
	done     chan struct{}

	mu      sync.Mutex
	waitErr error
}

type sshListenerService struct {
	server *gliderssh.Server
	done   chan struct{}

	mu      sync.Mutex
	waitErr error
}

type applicationScriptBinding struct {
	script      scriptpkg.StoredScript
	service     scriptpkg.StreamServiceInfo
	adopted     scriptpkg.ExecutionIdentity
	metadata    map[string]interface{}
	recordError func(error)
	clearError  func()
}

type scriptedListener struct {
	net.Listener
	binding *applicationScriptBinding
}

type scriptedConn struct {
	net.Conn
	binding *applicationScriptBinding
	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
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
		RecordError:        managed.recordError,
		ClearError:         managed.clearLastError,
	}, net.Listener(tcpListener), config)
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	managed.start(running)
	if definition.tracksHTTP {
		engine.registerManagedHTTPPort(uint16(port))
		managed.mu.Lock()
		managed.onDone = func() {
			engine.unregisterManagedHTTPPort(uint16(port))
		}
		managed.mu.Unlock()
	}

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

func newApplicationScriptBinding(ctx ServiceContext, service scriptpkg.StreamServiceInfo, metadata map[string]interface{}) (*applicationScriptBinding, error) {
	if ctx.Identity == nil {
		return nil, nil
	}

	scriptName := strings.TrimSpace(ctx.Identity.ApplicationScriptName())
	if scriptName == "" {
		return nil, nil
	}
	if ctx.LookupStoredScript == nil {
		return nil, fmt.Errorf("stored scripts are unavailable")
	}

	storedScript, err := ctx.LookupStoredScript(scriptpkg.StoredScriptRef{
		Name:    scriptName,
		Surface: scriptpkg.SurfaceApplication,
	})
	if err != nil {
		if errors.Is(err, scriptpkg.ErrStoredScriptNotFound) {
			return nil, fmt.Errorf("stored script %q was not found", scriptName)
		}
		return nil, err
	}
	if storedScript.Name == "" {
		return nil, fmt.Errorf("stored script %q was not found", scriptName)
	}

	return &applicationScriptBinding{
		script:      storedScript,
		service:     service,
		adopted:     buildExecutionIdentity(ctx.Identity),
		metadata:    metadata,
		recordError: ctx.RecordError,
		clearError:  ctx.ClearError,
	}, nil
}

func wrapListenerWithApplicationScript(listener net.Listener, binding *applicationScriptBinding) net.Listener {
	if listener == nil || binding == nil {
		return listener
	}

	return &scriptedListener{
		Listener: listener,
		binding:  binding,
	}
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &scriptedConn{
		Conn:    conn,
		binding: listener.binding,
	}, nil
}

func (conn *scriptedConn) Read(p []byte) (int, error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()

	if len(conn.readBuf) != 0 {
		return conn.drainReadBuffer(p), nil
	}

	buffer := make([]byte, max(len(p), 4096))
	n, err := conn.Conn.Read(buffer)
	if n <= 0 {
		return 0, err
	}

	payload, applyErr := conn.applyApplicationScript("inbound", buffer[:n])
	if applyErr != nil {
		_ = conn.Conn.Close()
		return 0, applyErr
	}

	conn.readBuf = append(conn.readBuf[:0], payload...)
	read := conn.drainReadBuffer(p)
	if read != 0 {
		return read, err
	}
	return 0, err
}

func (conn *scriptedConn) Write(p []byte) (int, error) {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()

	payload, err := conn.applyApplicationScript("outbound", p)
	if err != nil {
		_ = conn.Conn.Close()
		return 0, err
	}
	if err := writeAll(conn.Conn, payload); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (conn *scriptedConn) drainReadBuffer(target []byte) int {
	if len(conn.readBuf) == 0 || len(target) == 0 {
		return 0
	}

	n := copy(target, conn.readBuf)
	conn.readBuf = append(conn.readBuf[:0], conn.readBuf[n:]...)
	return n
}

func (conn *scriptedConn) applyApplicationScript(direction string, payload []byte) ([]byte, error) {
	if conn == nil || conn.binding == nil || len(payload) == 0 {
		return append([]byte(nil), payload...), nil
	}

	data := scriptpkg.StreamData{
		Direction: direction,
		Payload:   append([]byte(nil), payload...),
	}
	ctx := scriptpkg.StreamExecutionContext{
		ScriptName: conn.binding.script.Name,
		Adopted:    conn.binding.adopted,
		Service:    conn.binding.service,
		Connection: scriptpkg.StreamConnection{
			LocalAddress:  conn.LocalAddr().String(),
			RemoteAddress: conn.RemoteAddr().String(),
		},
		Metadata: conn.binding.metadata,
	}

	if err := scriptpkg.ExecuteApplicationBuffer(conn.binding.script, &data, ctx, nil); err != nil {
		if conn.binding.recordError != nil {
			conn.binding.recordError(err)
		}
		return nil, err
	}
	if conn.binding.clearError != nil {
		conn.binding.clearError()
	}
	return data.Payload, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
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
		Config:    cloneServiceConfig(spec.config),
		Summary:   serviceSummary(spec.service, spec.config),
		LastError: service.lastErr,
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

func (service *managedService) recordError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.active {
		service.lastErr = err.Error()
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

func echoListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceEchoID,
		Label:       "Echo",
		DefaultPort: 7007,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "7007",
			},
		},
		Start: startEchoListenerService,
	}
}

func startEchoListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	port, _ := strconv.Atoi(config["port"])
	binding, err := newApplicationScriptBinding(ctx, scriptpkg.StreamServiceInfo{
		Name:     listenerServiceEchoID,
		Port:     port,
		Protocol: "echo",
	}, nil)
	if err != nil {
		return nil, err
	}

	server := &echoListenerService{
		listener: wrapListenerWithApplicationScript(listener, binding),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}

	go server.run()
	return server, nil
}

func (server *echoListenerService) run() {
	defer close(server.done)

	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if !isClosedNetworkError(err) {
				server.setWaitError(fmt.Errorf("accept echo connection: %w", err))
			}
			return
		}

		server.trackConn(conn)
		go server.runConn(conn)
	}
}

func (server *echoListenerService) setWaitError(err error) {
	if server == nil || err == nil {
		return
	}

	server.mu.Lock()
	if server.waitErr == nil {
		server.waitErr = err
	}
	server.mu.Unlock()
}

func (server *echoListenerService) Wait() error {
	if server == nil {
		return nil
	}

	<-server.done
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.waitErr
}

func (server *echoListenerService) trackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	server.conns[conn] = struct{}{}
	server.mu.Unlock()
}

func (server *echoListenerService) untrackConn(conn net.Conn) {
	if server == nil || conn == nil {
		return
	}

	server.mu.Lock()
	delete(server.conns, conn)
	server.mu.Unlock()
}

func (server *echoListenerService) Close() error {
	if server == nil {
		return nil
	}

	server.mu.Lock()
	conns := make([]net.Conn, 0, len(server.conns))
	for conn := range server.conns {
		conns = append(conns, conn)
	}
	server.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}

	if server.listener == nil {
		return nil
	}

	return server.listener.Close()
}

func (server *echoListenerService) runConn(conn net.Conn) {
	if conn == nil {
		return
	}

	defer server.untrackConn(conn)
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func httpListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceHTTPID,
		Label:       "HTTP",
		DefaultPort: 8080,
		tracksHTTP:  true,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "8080",
			},
			{
				Name:         "protocol",
				Label:        "Protocol",
				Type:         adoption.ServiceFieldTypeSelect,
				Required:     true,
				DefaultValue: "http",
				Options: []adoption.ServiceFieldOption{
					{Value: "http", Label: "HTTP"},
					{Value: "https", Label: "HTTPS"},
				},
			},
			{
				Name:     "rootDirectory",
				Label:    "Root",
				Type:     adoption.ServiceFieldTypeDirectory,
				Required: true,
			},
		},
		Start: startHTTPListenerService,
		Summary: func(config map[string]string) []adoption.ServiceSummaryItem {
			items := []adoption.ServiceSummaryItem{
				{Label: "Proto", Value: strings.ToUpper(httpServiceProtocol(config))},
			}
			if rootDirectory := strings.TrimSpace(config["rootDirectory"]); rootDirectory != "" {
				items = append(items, adoption.ServiceSummaryItem{Label: "Root", Value: rootDirectory, Code: true})
			}
			return items
		},
	}
}

func startHTTPListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	rootDirectory, err := validateHTTPRootDirectory(config["rootDirectory"])
	if err != nil {
		return nil, err
	}

	protocol := httpServiceProtocol(config)
	port, err := strconv.Atoi(config["port"])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Port must be between 1 and 65535")
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveListener := listener
	binding, err := newApplicationScriptBinding(ctx, scriptpkg.StreamServiceInfo{
		Name:          listenerServiceHTTPID,
		Port:          port,
		Protocol:      protocol,
		RootDirectory: rootDirectory,
		UseTLS:        protocol == "https",
	}, nil)
	if err != nil {
		return nil, err
	}
	serveListener = wrapListenerWithApplicationScript(serveListener, binding)
	if protocol == "https" {
		if ctx.Identity == nil || common.NormalizeIPv4(ctx.Identity.IP()) == nil {
			return nil, fmt.Errorf("service requires a valid IPv4 identity")
		}
		tlsConfig, err := newSelfSignedTLSBundle(ctx.Identity.IP())
		if err != nil {
			return nil, err
		}
		serveListener = tls.NewListener(serveListener, tlsConfig)
	}

	running := &httpListenerService{
		server:   server,
		listener: serveListener,
		done:     make(chan struct{}),
	}
	server.Handler = http.FileServer(http.Dir(rootDirectory))

	go running.run()
	return running, nil
}

func (service *httpListenerService) run() {
	defer close(service.done)

	if err := service.server.Serve(service.listener); err != nil && !isClosedNetworkError(err) {
		service.setWaitError(fmt.Errorf("serve HTTP: %w", err))
	}
}

func (service *httpListenerService) setWaitError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.waitErr == nil {
		service.waitErr = err
	}
	service.mu.Unlock()
}

func (service *httpListenerService) Close() error {
	if service == nil {
		return nil
	}

	return errors.Join(service.server.Close(), service.listener.Close())
}

func (service *httpListenerService) Wait() error {
	if service == nil {
		return nil
	}

	<-service.done
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.waitErr
}

func sshListenerServiceDefinition() ListenerServiceDefinition {
	return ListenerServiceDefinition{
		ID:          listenerServiceSSHID,
		Label:       "SSH",
		DefaultPort: 2222,
		Fields: []adoption.ServiceFieldDefinition{
			{
				Name:         "port",
				Label:        "Port",
				Type:         adoption.ServiceFieldTypePort,
				Required:     true,
				DefaultValue: "2222",
			},
			{
				Name:        "username",
				Label:       "User",
				Type:        adoption.ServiceFieldTypeText,
				Placeholder: "researcher",
			},
			{
				Name:        "password",
				Label:       "Password",
				Type:        adoption.ServiceFieldTypeSecret,
				Placeholder: "secret",
			},
			{
				Name:        "authorizedKey",
				Label:       "Key",
				Type:        adoption.ServiceFieldTypeText,
				Placeholder: "ssh-ed25519 AAAA...",
			},
			{
				Name:         "allowPty",
				Label:        "Terminal",
				Type:         adoption.ServiceFieldTypeSelect,
				DefaultValue: "true",
				Options: []adoption.ServiceFieldOption{
					{Value: "true", Label: "On"},
					{Value: "false", Label: "Off"},
				},
			},
		},
		Start: startSSHListenerService,
		Summary: func(config map[string]string) []adoption.ServiceSummaryItem {
			items := []adoption.ServiceSummaryItem{
				{Label: "Auth", Value: sshAuthLabel(config)},
			}
			if username := strings.TrimSpace(config["username"]); username != "" {
				items = append(items, adoption.ServiceSummaryItem{Label: "User", Value: username})
			}
			if strings.EqualFold(strings.TrimSpace(config["allowPty"]), "true") {
				items = append(items, adoption.ServiceSummaryItem{Label: "PTY", Value: "On"})
			}
			return items
		},
	}
}

func startSSHListenerService(ctx ServiceContext, listener net.Listener, config map[string]string) (RunningService, error) {
	password := config["password"]
	authorizedKeyText := config["authorizedKey"]
	if strings.TrimSpace(password) == "" && strings.TrimSpace(authorizedKeyText) == "" {
		return nil, fmt.Errorf("SSH requires a password or authorized key")
	}
	port, err := strconv.Atoi(config["port"])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("Port must be between 1 and 65535")
	}

	signers, err := krakenSSHHostSigners()
	if err != nil {
		return nil, err
	}

	var authorizedKey gliderssh.PublicKey
	if strings.TrimSpace(authorizedKeyText) != "" {
		var parseErr error
		authorizedKey, _, _, _, parseErr = gliderssh.ParseAuthorizedKey([]byte(authorizedKeyText))
		if parseErr != nil {
			return nil, fmt.Errorf("Key: %w", parseErr)
		}
	}

	username := strings.TrimSpace(config["username"])
	server := &gliderssh.Server{
		Handler: func(session gliderssh.Session) {
			handleKrakenSSHSession(session)
		},
		PasswordHandler: func(ctx gliderssh.Context, supplied string) bool {
			if username != "" && ctx.User() != username {
				return false
			}
			return password != "" && supplied == password
		},
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			if username != "" && ctx.User() != username {
				return false
			}
			return authorizedKey != nil && gliderssh.KeysEqual(key, authorizedKey)
		},
		PtyCallback: func(_ gliderssh.Context, _ gliderssh.Pty) bool {
			return strings.EqualFold(strings.TrimSpace(config["allowPty"]), "true")
		},
		IdleTimeout: 5 * time.Minute,
	}
	for _, signer := range signers {
		server.AddHostKey(signer)
	}

	binding, err := newApplicationScriptBinding(ctx, scriptpkg.StreamServiceInfo{
		Name:     listenerServiceSSHID,
		Port:     port,
		Protocol: "ssh",
	}, nil)
	if err != nil {
		return nil, err
	}
	listener = wrapListenerWithApplicationScript(listener, binding)

	running := &sshListenerService{
		server: server,
		done:   make(chan struct{}),
	}
	go running.run(listener)
	return running, nil
}

func (service *sshListenerService) run(listener net.Listener) {
	defer close(service.done)

	if err := service.server.Serve(listener); err != nil && !isClosedNetworkError(err) {
		service.setWaitError(fmt.Errorf("serve SSH: %w", err))
	}
}

func (service *sshListenerService) setWaitError(err error) {
	if service == nil || err == nil {
		return
	}

	service.mu.Lock()
	if service.waitErr == nil {
		service.waitErr = err
	}
	service.mu.Unlock()
}

func (service *sshListenerService) Close() error {
	if service == nil {
		return nil
	}

	return service.server.Close()
}

func (service *sshListenerService) Wait() error {
	if service == nil {
		return nil
	}

	<-service.done
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.waitErr
}

func handleKrakenSSHSession(session gliderssh.Session) {
	if session == nil {
		return
	}

	ptyInfo, winCh, hasPty := session.Pty()
	command, err := resolveSSHCommand(session.Command(), hasPty)
	if err != nil {
		_, _ = io.WriteString(session, err.Error()+"\r\n")
		_ = session.Exit(1)
		return
	}

	if hasPty {
		_ = session.Exit(runSSHPtyCommand(session, command, ptyInfo, winCh))
		return
	}

	_ = session.Exit(runSSHCommand(session, command))
}

func resolveSSHCommand(command []string, hasPty bool) ([]string, error) {
	if len(command) != 0 {
		return append([]string(nil), command...), nil
	}
	if hasPty {
		return defaultSSHLoginCommand(), nil
	}

	return nil, fmt.Errorf("SSH requires a command or terminal. Connect with ssh -t for an interactive shell")
}

func defaultSSHLoginCommand() []string {
	if runtime.GOOS == "windows" {
		if shell := strings.TrimSpace(os.Getenv("COMSPEC")); shell != "" {
			return []string{shell}
		}
		return []string{"cmd.exe"}
	}

	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		return []string{shell}
	}
	return []string{"/bin/sh"}
}

func runSSHCommand(session gliderssh.Session, command []string) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, nil)
	cmd.Stdin = session
	cmd.Stdout = session
	cmd.Stderr = session.Stderr()

	return sshCommandExitCode(cmd.Run())
}

func runSSHPtyCommand(session gliderssh.Session, command []string, ptyInfo gliderssh.Pty, winCh <-chan gliderssh.Window) int {
	cmd := exec.CommandContext(session.Context(), command[0], command[1:]...)
	cmd.Env = sshCommandEnv(session, &ptyInfo)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(ptyInfo.Window.Height),
		Cols: uint16(ptyInfo.Window.Width),
	})
	if err != nil {
		_, _ = io.WriteString(session, err.Error()+"\r\n")
		return 1
	}
	defer ptmx.Close()

	go func() {
		for win := range winCh {
			_ = pty.Setsize(ptmx, &pty.Winsize{
				Rows: uint16(win.Height),
				Cols: uint16(win.Width),
			})
		}
	}()

	go func() {
		_, _ = io.Copy(ptmx, session)
	}()

	_, _ = io.Copy(session, ptmx)
	return sshCommandExitCode(cmd.Wait())
}

func sshCommandEnv(session gliderssh.Session, ptyInfo *gliderssh.Pty) []string {
	env := append([]string(nil), os.Environ()...)
	env = append(env, session.Environ()...)
	if ptyInfo != nil && strings.TrimSpace(ptyInfo.Term) != "" {
		env = append(env, "TERM="+strings.TrimSpace(ptyInfo.Term))
	}
	return env
}

func sshCommandExitCode(err error) int {
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
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

func krakenSSHHostSigners() ([]gossh.Signer, error) {
	hostKeyDir, err := storeutil.DefaultKrakenConfigDir(filepath.Join("services", "ssh", "hostkeys"))
	if err != nil {
		return nil, err
	}

	return loadOrCreateSSHHostSigners(hostKeyDir)
}

func loadOrCreateSSHHostSigners(hostKeyDir string) ([]gossh.Signer, error) {
	if strings.TrimSpace(hostKeyDir) == "" {
		return nil, fmt.Errorf("SSH host key directory is unavailable")
	}
	if err := os.MkdirAll(hostKeyDir, 0o755); err != nil {
		return nil, fmt.Errorf("create SSH host key directory: %w", err)
	}

	entries, err := os.ReadDir(hostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("list SSH host keys: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	signers := make([]gossh.Signer, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if ext := strings.ToLower(filepath.Ext(name)); ext != "" && ext != ".pem" {
			continue
		}

		signer, err := loadSSHHostSigner(filepath.Join(hostKeyDir, name))
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	if len(signers) != 0 {
		return signers, nil
	}

	defaultKeyPath := filepath.Join(hostKeyDir, "host_ed25519.pem")
	signer, err := createSSHHostSigner(defaultKeyPath)
	if err != nil {
		return nil, err
	}

	return []gossh.Signer{signer}, nil
}

func loadSSHHostSigner(path string) (gossh.Signer, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.ParsePrivateKey(payload)
	if err != nil {
		return nil, fmt.Errorf("parse SSH host key %q: %w", filepath.Base(path), err)
	}

	return signer, nil
}

func createSSHHostSigner(path string) (gossh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate SSH host key: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode SSH host key: %w", err)
	}

	payload := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return nil, fmt.Errorf("write SSH host key %q: %w", filepath.Base(path), err)
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("load SSH host key %q: %w", filepath.Base(path), err)
	}

	return signer, nil
}

func cloneServiceConfig(config map[string]string) map[string]string {
	return maps.Clone(config)
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

func httpServiceProtocol(config map[string]string) string {
	if strings.EqualFold(strings.TrimSpace(config["protocol"]), "https") {
		return "https"
	}

	return "http"
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

func validateHTTPRootDirectory(rootDirectory string) (string, error) {
	rootDirectory = strings.TrimSpace(rootDirectory)
	if rootDirectory == "" {
		return "", fmt.Errorf("Root is required")
	}

	rootDirectory = filepath.Clean(rootDirectory)
	info, err := os.Stat(rootDirectory)
	if err != nil {
		return "", fmt.Errorf("Root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("Root must be a directory")
	}

	return rootDirectory, nil
}

func newSelfSignedTLSBundle(ip net.IP) (*tls.Config, error) {
	certificate, err := newSelfSignedCertificate(ip)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func newSelfSignedCertificate(ip net.IP) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate HTTPS private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate HTTPS serial number: %w", err)
	}

	now := time.Now().UTC()
	normalizedIP := common.NormalizeIPv4(ip)
	certificateTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kraken-self-signed",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"kraken-self-signed"},
	}
	if normalizedIP != nil {
		certificateTemplate.IPAddresses = []net.IP{append(net.IP(nil), normalizedIP...)}
		certificateTemplate.Subject.CommonName = normalizedIP.String()
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create HTTPS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse HTTPS certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
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
