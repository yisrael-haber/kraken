package adoption

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"gvisor.dev/gvisor/pkg/buffer"
)

const defaultIdentityMTU = 1500

func prepareIdentity(identity *Identity) error {
	if !common.ValidLabel(identity.Label) {
		return fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	ifacePtr, err := net.InterfaceByName(identity.InterfaceName)
	if err != nil {
		return err
	}
	iface := *ifacePtr
	if iface.Flags&net.FlagLoopback != 0 {
		return errors.New("loopback interface cannot be adopted")
	}

	ip := identity.IP.To4()
	if ip == nil {
		return errors.New("a valid IPv4 address is required")
	}

	defaultGateway, err := common.NormalizeDefaultGateway(ipString(identity.DefaultGateway), ip)
	if err != nil {
		return err
	}

	subnetMask, err := normalizeIdentitySubnetMask(net.IPMask(identity.SubnetMask))
	if err != nil {
		return err
	}

	mtu, err := normalizeIdentityMTU(iface, int(identity.MTU))
	if err != nil {
		return err
	}

	identity.IP = ip
	identity.InterfaceName = iface.Name
	identity.Interface = iface
	if len(identity.MAC) == 0 {
		identity.MAC = HardwareAddr(iface.HardwareAddr)
	}
	identity.SubnetMask = IPv4Mask(subnetMask)
	identity.DefaultGateway = defaultGateway
	identity.MTU = mtu
	return nil
}

func (identity *Identity) Init(listener Listener, transportScript, applicationScript *script.CompiledScript) error {
	engine, err := netruntime.NewEngine(netruntime.EngineConfig{
		IP:              identity.IP,
		Label:           identity.Label,
		InterfaceName:   identity.InterfaceName,
		MAC:             net.HardwareAddr(identity.MAC),
		SubnetMask:      net.IPMask(identity.SubnetMask),
		DefaultGateway:  identity.DefaultGateway,
		MTU:             identity.MTU,
		TransportScript: transportScript,
		PacketIO:        listener.PacketIO(),
	})
	if err != nil {
		return err
	}
	identity.listener = listener
	identity.engine = engine
	identity.transportScript = transportScript
	identity.applicationScript = applicationScript
	return nil
}

func (identity *Identity) InjectFrame(frame buffer.Buffer) {
	if identity.engine != nil {
		identity.engine.InjectFrame(frame)
		return
	}
	frame.Release()
}

func (identity *Identity) CloseEngine() {
	identity.engine.Close()
	identity.engine = nil
}

func (identity *Identity) Close() error {
	if recorder := identity.TakeRecorder(); recorder != nil {
		recorder.Stop()
	}
	for _, service := range identity.services {
		service.Stop()
	}
	identity.services = nil
	identity.CloseEngine()
	err := identity.listener.Close()
	identity.listener = nil
	return err
}

func (identity *Identity) ListenTCP(port int) (net.Listener, error) {
	return identity.engine.ListenTCP(port)
}

func (identity *Identity) DialTCP(ctx context.Context, remoteIP net.IP, remotePort int) (net.Conn, error) {
	return identity.engine.DialTCP(ctx, remoteIP, remotePort)
}

func (identity *Identity) DialUDP(remoteIP net.IP, remotePort int) (net.Conn, error) {
	return identity.engine.DialUDP(remoteIP, remotePort)
}

func (identity Identity) ApplicationScript() *script.CompiledScript {
	return identity.applicationScript
}

func (identity Identity) TransportScriptName() string {
	return identity.transportScript.Name()
}

func (identity Identity) ApplicationScriptName() string {
	return identity.applicationScript.Name()
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
	if identity.services == nil {
		identity.services = make(map[string]*ManagedService)
	}
	identity.services[service.Service] = service
}

func (identity *Identity) takeService(service string) *ManagedService {
	running := identity.services[service]
	delete(identity.services, service)
	return running
}

func (identity Identity) Services() []ManagedService {
	if len(identity.services) == 0 {
		return nil
	}

	services := make([]ManagedService, 0, len(identity.services))
	for _, service := range identity.services {
		services = append(services, service.Snapshot())
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Service < services[j].Service
	})
	return services
}

func (identity Identity) MarshalJSON() ([]byte, error) {
	type identityJSON Identity
	return json.Marshal(struct {
		identityJSON
		TransportScriptName   string           `json:"transportScriptName,omitempty"`
		ApplicationScriptName string           `json:"applicationScriptName,omitempty"`
		Services              []ManagedService `json:"services,omitempty"`
	}{
		identityJSON:          identityJSON(identity),
		TransportScriptName:   identity.TransportScriptName(),
		ApplicationScriptName: identity.ApplicationScriptName(),
		Services:              identity.Services(),
	})
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
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

func normalizeIdentitySubnetMask(mask net.IPMask) (net.IPMask, error) {
	if len(mask) == 0 {
		return net.CIDRMask(24, 32), nil
	}
	if len(mask) != net.IPv4len {
		return nil, fmt.Errorf("subnetMask must be an IPv4 mask")
	}
	if ones, bits := mask.Size(); ones < 0 || bits != 32 {
		return nil, fmt.Errorf("subnetMask must be a contiguous IPv4 mask")
	}
	return mask, nil
}
