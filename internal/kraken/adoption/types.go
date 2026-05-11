package adoption

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

const (
	ServiceFieldTypePort      = "port"
	ServiceFieldTypeText      = "text"
	ServiceFieldTypeSecret    = "secret"
	ServiceFieldTypeSelect    = "select"
	ServiceFieldTypeDirectory = "directory"
)

type Identity struct {
	Label                 string                 `json:"label"`
	IP                    net.IP                 `json:"ip"`
	InterfaceName         string                 `json:"interfaceName"`
	Interface             net.Interface          `json:"-"`
	MAC                   HardwareAddr           `json:"mac,omitempty"`
	DefaultGateway        net.IP                 `json:"defaultGateway,omitempty"`
	MTU                   uint32                 `json:"mtu,omitempty"`
	TransportScriptName   string                 `json:"transportScriptName,omitempty"`
	ApplicationScriptName string                 `json:"applicationScriptName,omitempty"`
	Recording             *PacketRecordingStatus `json:"recording,omitempty"`
	Services              []ServiceStatus        `json:"services,omitempty"`

	engine     *netruntime.Engine
	listener   Listener
	recorderMu sync.Mutex
	recorder   RecorderRuntime
	servicesMu sync.RWMutex
	services   map[string]*ManagedService
}

type RecorderRuntime interface {
	Stop()
}

func (identity *Identity) Init(listener Listener) error {
	identity.listener = listener
	if listener == nil {
		return ErrListenerStopped
	}
	transportScript, err := resolveTransportScript(identity.TransportScriptName, listener.LookupScript())
	if err != nil {
		return err
	}

	engine, err := netruntime.NewEngine(netruntime.EngineConfig{
		IP:              identity.IP,
		Label:           identity.Label,
		InterfaceName:   identity.InterfaceName,
		MAC:             net.HardwareAddr(identity.MAC),
		DefaultGateway:  identity.DefaultGateway,
		Routes:          listener.InterfaceRoutes(),
		MTU:             identity.MTU,
		TransportScript: transportScript,
		PacketIO:        listener.PacketIO(),
	})
	if err != nil {
		return err
	}
	identity.engine = engine
	return nil
}

func (identity *Identity) InjectFrame(frame buffer.Buffer) {
	if identity != nil && identity.engine != nil {
		identity.engine.InjectFrame(frame)
		return
	}
	frame.Release()
}

func (identity *Identity) CloseEngine() {
	if identity != nil && identity.engine != nil {
		identity.engine.Close()
		identity.engine = nil
	}
}

func (identity *Identity) Close() error {
	if recorder := identity.TakeRecorder(); recorder != nil {
		recorder.Stop()
	}
	for _, service := range identity.takeServices() {
		service.Stop()
	}
	identity.CloseEngine()
	err := identity.listener.Close()
	identity.listener = nil
	return err
}

func (identity *Identity) ListenTCP(port int) (net.Listener, error) {
	if identity == nil || identity.engine == nil {
		return nil, ErrListenerStopped
	}
	return identity.engine.ListenTCP(port)
}

func (identity *Identity) DialTCP(ctx context.Context, remoteIP net.IP, remotePort int) (net.Conn, error) {
	if identity == nil || identity.engine == nil {
		return nil, ErrListenerStopped
	}
	return identity.engine.DialTCP(ctx, remoteIP, remotePort)
}

func (identity *Identity) DialUDP(remoteIP net.IP, remotePort int) (net.Conn, error) {
	if identity == nil || identity.engine == nil {
		return nil, ErrListenerStopped
	}
	return identity.engine.DialUDP(remoteIP, remotePort)
}

func resolveTransportScript(scriptName string, lookup ScriptLookupFunc) (*script.CompiledScript, error) {
	scriptName = strings.TrimSpace(scriptName)
	if scriptName == "" {
		return nil, nil
	}
	if lookup == nil {
		return nil, script.MissingStoredScriptError(scriptName)
	}
	storedScript, err := lookup(storage.StoredScriptRef{
		Name:    scriptName,
		Surface: storage.SurfaceTransport,
	})
	if err != nil {
		if errors.Is(err, storage.ErrStoredScriptNotFound) {
			return nil, script.MissingStoredScriptError(scriptName)
		}
		return nil, err
	}
	if storedScript.Compiled == nil {
		return nil, script.MissingStoredScriptError(scriptName)
	}
	return storedScript.Compiled, nil
}

func (identity *Identity) StoreRecorder(recorder RecorderRuntime) RecorderRuntime {
	identity.recorderMu.Lock()
	previous := identity.recorder
	identity.recorder = recorder
	identity.recorderMu.Unlock()
	return previous
}

func (identity *Identity) TakeRecorder() RecorderRuntime {
	identity.recorderMu.Lock()
	recorder := identity.recorder
	identity.recorder = nil
	identity.recorderMu.Unlock()
	return recorder
}

func (identity *Identity) storeService(service *ManagedService) {
	identity.servicesMu.Lock()
	if identity.services == nil {
		identity.services = make(map[string]*ManagedService)
	}
	identity.services[service.status.Service] = service
	identity.servicesMu.Unlock()
}

func (identity *Identity) takeService(service string) *ManagedService {
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return nil
	}

	identity.servicesMu.Lock()
	running := identity.services[service]
	delete(identity.services, service)
	identity.servicesMu.Unlock()
	return running
}

func (identity *Identity) takeServices() []*ManagedService {
	identity.servicesMu.Lock()
	defer identity.servicesMu.Unlock()
	if len(identity.services) == 0 {
		return nil
	}

	items := make([]*ManagedService, 0, len(identity.services))
	for service, running := range identity.services {
		if running != nil {
			items = append(items, running)
		}
		delete(identity.services, service)
	}
	return items
}

func (identity *Identity) Snapshot() Identity {
	snapshot := *identity
	identity.servicesMu.RLock()
	defer identity.servicesMu.RUnlock()
	if len(identity.services) == 0 {
		snapshot.Services = nil
		return snapshot
	}

	snapshot.Services = make([]ServiceStatus, 0, len(identity.services))
	for _, service := range identity.services {
		snapshot.Services = append(snapshot.Services, service.Snapshot())
	}
	sort.Slice(snapshot.Services, func(i, j int) bool {
		return snapshot.Services[i].Service < snapshot.Services[j].Service
	})
	return snapshot
}

type HardwareAddr net.HardwareAddr

func (addr HardwareAddr) String() string {
	return net.HardwareAddr(addr).String()
}

func (addr HardwareAddr) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *HardwareAddr) UnmarshalText(text []byte) error {
	mac, err := net.ParseMAC(string(text))
	*addr = HardwareAddr(mac)
	return err
}

type UpdateAdoptedIPAddressRequest struct {
	Identity
	CurrentIP string `json:"currentIP"`
}

type UpdateAdoptedIPAddressScriptsRequest struct {
	IP                    string `json:"ip"`
	TransportScriptName   string `json:"transportScriptName"`
	ApplicationScriptName string `json:"applicationScriptName"`
}

type StartAdoptedIPAddressServiceRequest struct {
	IP      string            `json:"ip"`
	Service string            `json:"service"`
	Config  map[string]string `json:"config,omitempty"`
}

type StopAdoptedIPAddressServiceRequest struct {
	IP      string `json:"ip"`
	Service string `json:"service"`
}

type ServiceFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type ServiceFieldDefinition struct {
	Name          string               `json:"name"`
	Label         string               `json:"label"`
	Type          string               `json:"type"`
	Required      bool                 `json:"required,omitempty"`
	DefaultValue  string               `json:"defaultValue,omitempty"`
	Placeholder   string               `json:"placeholder,omitempty"`
	ScriptSurface string               `json:"scriptSurface,omitempty"`
	Options       []ServiceFieldOption `json:"options,omitempty"`
}

type ServiceDefinition struct {
	Service     string                   `json:"service"`
	Label       string                   `json:"label"`
	DefaultPort int                      `json:"defaultPort,omitempty"`
	Fields      []ServiceFieldDefinition `json:"fields,omitempty"`
}

type ServiceSummaryItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Code  bool   `json:"code,omitempty"`
}

type ServiceStatus struct {
	Service     string               `json:"service"`
	Active      bool                 `json:"active"`
	Port        int                  `json:"port"`
	Config      map[string]string    `json:"config,omitempty"`
	Summary     []ServiceSummaryItem `json:"summary,omitempty"`
	StartedAt   string               `json:"startedAt,omitempty"`
	LastError   string               `json:"lastError,omitempty"`
	ScriptError *ScriptRuntimeError  `json:"scriptError,omitempty"`
}

var ErrListenerStopped = errors.New("adoption listener is not running")

type ScriptLookupFunc func(ref storage.StoredScriptRef) (storage.StoredScript, error)

type Listener interface {
	Close() error
	Healthy() error
	InterfaceRoutes() []net.IPNet
	PacketIO() *netruntime.InterfacePacketIO
	LookupScript() ScriptLookupFunc
	CaptureIPv4Target(ip net.IP) error
	StartRecording(source *Identity, outputPath string) (PacketRecordingStatus, error)
}

type StartAdoptedIPAddressRecordingRequest struct {
	IP         string `json:"ip"`
	OutputPath string `json:"outputPath,omitempty"`
}

type PacketRecordingStatus struct {
	Active     bool   `json:"active"`
	OutputPath string `json:"outputPath,omitempty"`
	StartedAt  string `json:"startedAt,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

type ScriptRuntimeError struct {
	ScriptName string `json:"scriptName,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Stage      string `json:"stage,omitempty"`
	Direction  string `json:"direction,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}
