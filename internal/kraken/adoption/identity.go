package adoption

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/netruntime"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"gvisor.dev/gvisor/pkg/buffer"
)

const defaultIdentityMTU = 1500

func normalizeIdentity(identity *Identity) error {
	if !common.ValidLabel(identity.Label) {
		return fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	ifacePtr, err := net.InterfaceByName(strings.TrimSpace(identity.InterfaceName))
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

	if len(identity.MAC) == 0 {
		return errors.New("a valid MAC address is required")
	}

	defaultGateway, err := common.NormalizeDefaultGateway(ipString(identity.DefaultGateway), ip)
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
	identity.DefaultGateway = defaultGateway
	identity.MTU = mtu
	return nil
}

func newIdentityWithGatewayAndScripts(label string, iface net.Interface, ip net.IP, mac net.HardwareAddr, defaultGateway net.IP, mtu uint32, transportScriptName string, applicationScriptName string) Identity {
	return Identity{
		Label:                 label,
		IP:                    ip.To4(),
		InterfaceName:         iface.Name,
		Interface:             iface,
		MAC:                   HardwareAddr(mac),
		DefaultGateway:        defaultGateway.To4(),
		MTU:                   mtu,
		TransportScriptName:   transportScriptName,
		ApplicationScriptName: applicationScriptName,
	}
}

func (identity *Identity) Init(listener Listener) error {
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
	identity.listener = listener
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
	if identity.services == nil {
		identity.services = make(map[string]*ManagedService)
	}
	identity.services[strings.ToLower(strings.TrimSpace(service.status.Service))] = service
}

func (identity *Identity) takeService(service string) *ManagedService {
	service = strings.ToLower(strings.TrimSpace(service))
	running := identity.services[service]
	delete(identity.services, service)
	return running
}

func (identity *Identity) Snapshot() Identity {
	snapshot := *identity
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
