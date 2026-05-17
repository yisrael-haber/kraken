package adoption

import (
	"errors"
	"net"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
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
	services   map[string]*ManagedService
}

type RecorderRuntime interface {
	Stop()
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
