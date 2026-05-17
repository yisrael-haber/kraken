package adoption

import (
	"errors"
	"net"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
)

type Identity struct {
	Label          string                 `json:"label"`
	IP             net.IP                 `json:"ip"`
	InterfaceName  string                 `json:"interfaceName"`
	Interface      net.Interface          `json:"-"`
	MAC            HardwareAddr           `json:"mac,omitempty"`
	DefaultGateway net.IP                 `json:"defaultGateway,omitempty"`
	MTU            uint32                 `json:"mtu,omitempty"`
	Recording      *PacketRecordingStatus `json:"recording,omitempty"`

	engine            *netruntime.Engine
	listener          Listener
	transportScript   *script.CompiledScript
	applicationScript *script.CompiledScript
	recorderMu        sync.Mutex
	recorder          RecorderRuntime
	services          map[string]*ManagedService
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
	if len(text) == 0 {
		*addr = nil
		return nil
	}
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

var ErrListenerStopped = errors.New("adoption listener is not running")

type Listener interface {
	Close() error
	Healthy() error
	InterfaceRoutes() []net.IPNet
	PacketIO() *netruntime.InterfacePacketIO
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
