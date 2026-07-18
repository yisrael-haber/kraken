package adoption

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
)

const defaultIdentityMTU = 1500

type Identity struct {
	Label          string        `json:"label"`
	IP             net.IP        `json:"ip"`
	Interface      net.Interface `json:"interface"`
	MAC            HardwareAddr  `json:"mac,omitempty"`
	SubnetPrefix   int           `json:"subnetPrefix,omitempty"`
	DefaultGateway net.IP        `json:"defaultGateway,omitempty"`
	MTU            uint32        `json:"mtu,omitempty"`

	engine   *netruntime.Engine
	recorder *packetRecorder
	services map[string]operations.Service
	network  uint32
	mask     uint32
}

type HardwareAddr net.HardwareAddr

func (addr HardwareAddr) MarshalText() ([]byte, error) {
	return []byte(net.HardwareAddr(addr).String()), nil
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

func (identity *Identity) init(listener netruntime.PacketEndpoint) error {
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

	subnetPrefix, err := common.NormalizeSubnetPrefix(identity.SubnetPrefix)
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
	identity.mask = ^uint32(0) << (32 - subnetPrefix)
	identity.network = binary.BigEndian.Uint32(ip) & identity.mask

	engine, err := netruntime.NewEngine(netruntime.EngineConfig{
		IP:             identity.IP,
		Label:          identity.Label,
		InterfaceName:  identity.Interface.Name,
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

func (identity *Identity) close() {
	identity.stopRecording()
	for name := range identity.services {
		identity.stopService(name)
	}
	identity.engine.Shutdown()
}

func (identity *Identity) startService(service operations.Service) error {
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

func (identity *Identity) stopService(name string) {
	service := identity.services[name]
	delete(identity.services, name)
	if service != nil {
		_ = service.Close()
	}
}

func (identity *Identity) stopRecording() {
	if identity.recorder != nil {
		identity.recorder.Stop()
		identity.recorder = nil
	}
}

func (identity *Identity) startRecording(outputPath string) error {
	if identity.recorder != nil {
		return fmt.Errorf("recording is already active for %s", identity.IP)
	}
	recorder, err := startPacketRecorder(netruntime.PcapOptions{
		DeviceName:  identity.Interface.Name,
		BufferSize:  recordingHandleBufferSize,
		ReadTimeout: recordingReadTimeout,
		BPFFilter:   buildRecordingBPFFilter(identity, identity.Interface.HardwareAddr),
	}, outputPath)
	if err == nil {
		identity.recorder = recorder
	}
	return err
}

func (identity *Identity) servicesMetadata() []operations.ServiceMetadata {
	if len(identity.services) == 0 {
		return nil
	}

	services := make([]operations.ServiceMetadata, 0, len(identity.services))
	for _, service := range identity.services {
		services = append(services, service.Metadata())
	}
	return services
}

func (identity *Identity) MarshalJSON() ([]byte, error) {
	type identityJSON Identity
	transportScriptName := identity.engine.ScriptName()
	return json.Marshal(struct {
		identityJSON
		TransportScriptName string                       `json:"transportScriptName,omitempty"`
		Recording           *PacketRecordingStatus       `json:"recording,omitempty"`
		Services            []operations.ServiceMetadata `json:"services,omitempty"`
	}{
		identityJSON:        identityJSON(*identity),
		TransportScriptName: transportScriptName,
		Recording:           identity.recorder.Status(),
		Services:            identity.servicesMetadata(),
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
