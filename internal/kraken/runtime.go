package kraken

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type Runtime struct {
	adoptions     *adoptionpkg.Manager
	storedConfigs *storage.ConfigStore
	storedRoutes  *storage.RoutingStore
	storedScripts *scriptpkg.Store
}

// NewRuntime creates the backend runtime used by the Wails-facing app shell.
func NewRuntime() *Runtime {
	storedScripts := scriptpkg.NewStore()
	storedRoutes := storage.NewRoutingStore()

	return &Runtime{
		adoptions:     adoptionpkg.NewManager(storedRoutes.MatchDestination),
		storedConfigs: storage.NewConfigStore(),
		storedRoutes:  storedRoutes,
		storedScripts: storedScripts,
	}
}

func (a *Runtime) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List()
}

func (a *Runtime) GetConfigurationDirectory() (string, error) {
	return storage.DefaultKrakenConfigRoot()
}

func (a *Runtime) AdoptIPAddress(request adoptionpkg.Identity) (adoptionpkg.Identity, error) {
	if err := a.ensureAdoptionListener(request.InterfaceName); err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Adopt(request)
}

func (a *Runtime) ListAdoptedIPAddresses() []adoptionpkg.Identity {
	return a.adoptions.Snapshot()
}

func (a *Runtime) GetAdoptedIPAddressDetails(ip string) (adoptionpkg.Identity, error) {
	return a.adoptions.Details(ip)
}

func (a *Runtime) ListStoredAdoptionConfigurations() ([]storage.StoredAdoptionConfiguration, error) {
	return a.storedConfigs.List()
}

func (a *Runtime) SaveStoredAdoptionConfiguration(config storage.StoredAdoptionConfiguration) (storage.StoredAdoptionConfiguration, error) {
	return a.storedConfigs.Save(config)
}

func (a *Runtime) DeleteStoredAdoptionConfiguration(label string) error {
	return a.storedConfigs.Delete(label)
}

func (a *Runtime) ListStoredRoutes() ([]storage.StoredRoute, error) {
	return ((*storage.JSONStore[storage.StoredRoute])(a.storedRoutes)).List()
}

func (a *Runtime) SaveStoredRoute(route storage.StoredRoute) (storage.StoredRoute, error) {
	return ((*storage.JSONStore[storage.StoredRoute])(a.storedRoutes)).Save(route)
}

func (a *Runtime) DeleteStoredRoute(label string) error {
	return ((*storage.JSONStore[storage.StoredRoute])(a.storedRoutes)).Delete(label)
}

func (a *Runtime) ListStoredScripts() ([]scriptpkg.StoredScriptSummary, error) {
	return a.storedScripts.List()
}

func (a *Runtime) GetStoredScript(ref scriptpkg.StoredScriptRef) (scriptpkg.StoredScript, error) {
	return a.storedScripts.Get(ref)
}

func (a *Runtime) SaveStoredScript(request scriptpkg.SaveStoredScriptRequest) (scriptpkg.StoredScript, error) {
	return a.storedScripts.Save(request)
}

func (a *Runtime) DeleteStoredScript(ref scriptpkg.StoredScriptRef) error {
	return a.storedScripts.Delete(ref)
}

func (a *Runtime) RefreshStoredScripts() ([]scriptpkg.StoredScriptSummary, error) {
	return a.storedScripts.Refresh()
}

func (a *Runtime) AdoptStoredAdoptionConfiguration(label string) (adoptionpkg.Identity, error) {
	config, err := a.storedConfigs.Load(label)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	mac, err := net.ParseMAC(config.MAC)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}

	identity := adoptionpkg.Identity{
		Label:          config.Label,
		InterfaceName:  config.InterfaceName,
		Interface:      net.Interface{Name: config.InterfaceName},
		IP:             net.ParseIP(config.IP),
		MAC:            adoptionpkg.HardwareAddr(mac),
		DefaultGateway: net.ParseIP(config.DefaultGateway),
		MTU:            uint32(config.MTU),
	}
	if err := a.ensureAdoptionListener(identity.InterfaceName); err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Adopt(identity)
}

func (a *Runtime) UpdateAdoptedIPAddressScripts(request adoptionpkg.UpdateAdoptedIPAddressScriptsRequest) (adoptionpkg.Identity, error) {
	transportScriptName, err := a.normalizeStoredScriptName("transportScriptName", request.TransportScriptName, scriptpkg.SurfaceTransport)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	applicationScriptName, err := a.normalizeStoredScriptName("applicationScriptName", request.ApplicationScriptName, scriptpkg.SurfaceApplication)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}

	if err := a.adoptions.UpdateScripts(request.IP, transportScriptName, applicationScriptName); err != nil {
		return adoptionpkg.Identity{}, err
	}

	return a.adoptions.Details(request.IP)
}

func (a *Runtime) UpdateAdoptedIPAddress(request adoptionpkg.UpdateAdoptedIPAddressRequest) (adoptionpkg.Identity, error) {
	if err := a.ensureAdoptionListener(request.InterfaceName); err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Update(request)
}

func (a *Runtime) ReleaseIPAddress(ip string) error {
	return a.adoptions.Release(ip)
}

func (a *Runtime) PingAdoptedIPAddress(request adoptionpkg.PingAdoptedIPAddressRequest) (adoptionpkg.PingAdoptedIPAddressResult, error) {
	return a.adoptions.Ping(request)
}

func (a *Runtime) ResolveDNSAdoptedIPAddress(request adoptionpkg.ResolveDNSAdoptedIPAddressRequest) (adoptionpkg.ResolveDNSAdoptedIPAddressResult, error) {
	return a.adoptions.ResolveDNS(request)
}

func (a *Runtime) StartAdoptedIPAddressRecording(request adoptionpkg.StartAdoptedIPAddressRecordingRequest) (adoptionpkg.Identity, error) {
	outputPath := strings.TrimSpace(request.OutputPath)
	if outputPath == "" {
		normalizedIP, err := common.NormalizeAdoptionIP(request.IP)
		if err != nil {
			return adoptionpkg.Identity{}, err
		}
		downloadsDir, err := storage.DefaultDownloadsDir()
		if err != nil {
			return adoptionpkg.Identity{}, err
		}
		outputPath = filepath.Join(downloadsDir, fmt.Sprintf("%s-%s.pcap", normalizedIP.String(), time.Now().UTC().Format("20060102-150405")))
	}

	return a.adoptions.StartRecording(request.IP, outputPath)
}

func (a *Runtime) StopAdoptedIPAddressRecording(ip string) (adoptionpkg.Identity, error) {
	return a.adoptions.StopRecording(ip)
}

func (a *Runtime) ListServiceDefinitions() []adoptionpkg.ServiceDefinition {
	return operations.ListServiceDefinitions()
}

func (a *Runtime) StartAdoptedIPAddressService(request adoptionpkg.StartAdoptedIPAddressServiceRequest) (adoptionpkg.Identity, error) {
	return a.adoptions.StartService(request)
}

func (a *Runtime) StopAdoptedIPAddressService(request adoptionpkg.StopAdoptedIPAddressServiceRequest) (adoptionpkg.Identity, error) {
	return a.adoptions.StopService(request)
}

func (a *Runtime) Shutdown() error {
	return a.adoptions.Close()
}

func (a *Runtime) ensureAdoptionListener(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if a.adoptions.HasListener(interfaceName) {
		return nil
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	listener, err := operations.NewListener(*iface, a.adoptions.ResolveForwarding, a.storedScripts.Lookup)
	if err != nil {
		return err
	}
	if err := a.adoptions.SetListener(*iface, listener); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

func (a *Runtime) normalizeStoredScriptName(fieldName, scriptName string, surface scriptpkg.Surface) (string, error) {
	normalized := strings.TrimSpace(scriptName)
	if normalized == "" {
		return "", nil
	}
	_, err := a.storedScripts.Lookup(scriptpkg.StoredScriptRef{
		Name:    normalized,
		Surface: surface,
	})
	if err == nil {
		return normalized, nil
	}

	switch {
	case errors.Is(err, scriptpkg.ErrStoredScriptInvalid):
		return "", fmt.Errorf("%s: %w", fieldName, err)
	case errors.Is(err, scriptpkg.ErrStoredScriptNotFound):
		return "", fmt.Errorf("%s: stored script %q was not found", fieldName, normalized)
	default:
		return "", fmt.Errorf("%s: %w", fieldName, err)
	}
}
