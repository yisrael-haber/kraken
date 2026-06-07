package adoption

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
)

const defaultIdentityMTU = 1500
const defaultSubnetPrefix = 24

type Identity struct {
	Label          string        `json:"label"`
	IP             net.IP        `json:"ip"`
	InterfaceName  string        `json:"interfaceName"`
	Interface      net.Interface `json:"-"`
	MAC            HardwareAddr  `json:"mac,omitempty"`
	SubnetPrefix   int           `json:"subnetPrefix,omitempty"`
	DefaultGateway net.IP        `json:"defaultGateway,omitempty"`
	MTU            uint32        `json:"mtu,omitempty"`

	engine   *netruntime.Engine
	recorder *packetRecorder
	services map[string]operations.Service
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

func (identity *Identity) Init(listener netruntime.PacketEndpoint) error {
	if !common.ValidLabel(identity.Label) {
		return fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	if identity.Interface.Flags&net.FlagLoopback != 0 {
		return errors.New("loopback interface cannot be adopted")
	}

	ip := identity.IP.To4()
	if ip == nil {
		return errors.New("a valid IPv4 address is required")
	}

	var defaultGateway net.IP
	if len(identity.DefaultGateway) != 0 {
		var err error
		defaultGateway, err = common.NormalizeDefaultGateway(identity.DefaultGateway.String(), ip)
		if err != nil {
			return err
		}
	}

	subnetPrefix, err := normalizeIdentitySubnetPrefix(identity.SubnetPrefix)
	if err != nil {
		return err
	}

	mtu, err := normalizeIdentityMTU(identity.Interface, int(identity.MTU))
	if err != nil {
		return err
	}

	identity.IP = ip
	if len(identity.MAC) == 0 {
		identity.MAC = HardwareAddr(identity.Interface.HardwareAddr)
	}
	identity.SubnetPrefix = subnetPrefix
	identity.DefaultGateway = defaultGateway
	identity.MTU = mtu

	engine, err := netruntime.NewEngine(netruntime.EngineConfig{
		IP:             identity.IP,
		Label:          identity.Label,
		InterfaceName:  identity.InterfaceName,
		MAC:            net.HardwareAddr(identity.MAC),
		SubnetPrefix:   identity.SubnetPrefix,
		DefaultGateway: identity.DefaultGateway,
		MTU:            identity.MTU,
		PacketEndpoint: listener,
	})
	if err != nil {
		return err
	}
	identity.engine = engine
	identity.services = make(map[string]operations.Service)
	return nil
}

func (identity *Identity) Close() error {
	identity.StopRecording()
	for _, service := range identity.services {
		_ = service.Close()
	}
	identity.engine.Close()
	return nil
}

func (identity *Identity) StartService(service operations.Service) error {
	metadata := service.Metadata()
	if identity.services[metadata.Service] != nil {
		return fmt.Errorf("%s service is already running", metadata.Service)
	}

	listener, err := identity.engine.ListenTCP(metadata.Port)
	if err != nil {
		return err
	}
	if err := service.Start(listener); err != nil {
		_ = listener.Close()
		return err
	}

	identity.services[metadata.Service] = service
	return nil
}

func (identity *Identity) StopRecording() {
	if identity.recorder != nil {
		identity.recorder.Stop()
		identity.recorder = nil
	}
}

func (identity *Identity) StartRecording(outputPath string) error {
	if identity.recorder != nil {
		return fmt.Errorf("recording is already active for %s", identity.IP)
	}
	recorder, err := startPacketRecorder(netruntime.PcapOptions{
		DeviceName:  identity.InterfaceName,
		BufferSize:  recordingHandleBufferSize,
		ReadTimeout: recordingReadTimeout,
		BPFFilter:   buildRecordingBPFFilter(*identity, identity.Interface.HardwareAddr),
	}, outputPath)
	if err == nil {
		identity.recorder = recorder
	}
	return err
}

func (identity Identity) Services() []operations.ServiceMetadata {
	if len(identity.services) == 0 {
		return nil
	}

	services := make([]operations.ServiceMetadata, 0, len(identity.services))
	for _, service := range identity.services {
		services = append(services, service.Metadata())
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Service < services[j].Service
	})
	return services
}

func (identity Identity) MarshalJSON() ([]byte, error) {
	type identityJSON Identity
	transportScriptName, applicationScriptName := identity.engine.ScriptNames()
	return json.Marshal(struct {
		identityJSON
		TransportScriptName   string                       `json:"transportScriptName,omitempty"`
		ApplicationScriptName string                       `json:"applicationScriptName,omitempty"`
		Recording             *PacketRecordingStatus       `json:"recording,omitempty"`
		Services              []operations.ServiceMetadata `json:"services,omitempty"`
	}{
		identityJSON:          identityJSON(identity),
		TransportScriptName:   transportScriptName,
		ApplicationScriptName: applicationScriptName,
		Recording:             identity.recorder.Status(),
		Services:              identity.Services(),
	})
}

func normalizeIdentityMTU(iface net.Interface, mtu int) (uint32, error) {
	if mtu == 0 {
		mtu = iface.MTU
	}
	if mtu == 0 {
		mtu = defaultIdentityMTU
	}
	if mtu < 68 || mtu > 65535 {
		return 0, fmt.Errorf("mtu must be between 68 and 65535")
	}
	return uint32(mtu), nil
}

func normalizeIdentitySubnetPrefix(prefix int) (int, error) {
	if prefix == 0 {
		return defaultSubnetPrefix, nil
	}
	if prefix < 1 || prefix > 32 {
		return 0, fmt.Errorf("subnetPrefix must be between 1 and 32")
	}
	return prefix, nil
}
