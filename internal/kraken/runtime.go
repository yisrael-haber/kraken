package kraken

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type Runtime struct {
	adoptions     *adoptionpkg.Manager
	storedConfigs *storage.ConfigStore
	storedRoutes  *storage.RoutingStore
	storedScripts *storage.ScriptStore
}

// NewRuntime creates the backend runtime used by the Wails-facing app shell.
func NewRuntime() *Runtime {
	storedScripts := storage.NewScriptStore()
	storedRoutes := storage.NewRoutingStore()

	return &Runtime{
		adoptions: adoptionpkg.NewManager(func(destinationIP net.IP) (net.IP, bool) {
			route, exists := storedRoutes.MatchDestination(destinationIP)
			if !exists {
				return nil, false
			}
			return net.ParseIP(route.ViaAdoptedIP), true
		}, storedScripts),
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
	listener, err := a.ensureAdoptionListener(request.InterfaceName)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Adopt(request, listener)
}

func (a *Runtime) ListAdoptedIPAddresses() []adoptionpkg.Identity {
	return a.adoptions.Snapshot()
}

func (a *Runtime) GetAdoptedIPAddressDetails(ip string) (adoptionpkg.Identity, error) {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Lookup(adoptedIP)
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
	return a.storedRoutes.List()
}

func (a *Runtime) SaveStoredRoute(route storage.StoredRoute) (storage.StoredRoute, error) {
	return a.storedRoutes.Save(route)
}

func (a *Runtime) DeleteStoredRoute(label string) error {
	return a.storedRoutes.Delete(label)
}

func (a *Runtime) ListStoredScripts() ([]storage.StoredScriptSummary, error) {
	items, err := a.storedScripts.List()
	if err != nil {
		return nil, err
	}
	summaries := make([]storage.StoredScriptSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, item.Summary())
	}
	return summaries, nil
}

func (a *Runtime) GetStoredScript(ref storage.StoredScriptRef) (storage.StoredScript, error) {
	return a.storedScripts.Get(ref)
}

func (a *Runtime) SaveStoredScript(request storage.SaveStoredScriptRequest) (storage.StoredScript, error) {
	return a.storedScripts.Save(request)
}

func (a *Runtime) DeleteStoredScript(ref storage.StoredScriptRef) error {
	return a.storedScripts.Delete(ref)
}

func (a *Runtime) RefreshStoredScripts() ([]storage.StoredScriptSummary, error) {
	if _, err := a.storedScripts.Refresh(); err != nil {
		return nil, err
	}
	return a.ListStoredScripts()
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
	listener, err := a.ensureAdoptionListener(identity.InterfaceName)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Adopt(identity, listener)
}

func (a *Runtime) UpdateAdoptedIPAddressScripts(request adoptionpkg.UpdateAdoptedIPAddressScriptsRequest) (adoptionpkg.Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}

	if err := a.adoptions.UpdateScripts(ip, request.TransportScriptName, request.ApplicationScriptName); err != nil {
		return adoptionpkg.Identity{}, err
	}

	return a.adoptions.Lookup(ip)
}

func (a *Runtime) UpdateAdoptedIPAddress(request adoptionpkg.UpdateAdoptedIPAddressRequest) (adoptionpkg.Identity, error) {
	currentIP, err := common.NormalizeAdoptionIP(request.CurrentIP)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	if err := a.adoptions.Release(currentIP); err != nil {
		return adoptionpkg.Identity{}, err
	}
	listener, err := a.ensureAdoptionListener(request.InterfaceName)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.Adopt(request.Identity, listener)
}

func (a *Runtime) ReleaseIPAddress(ip string) error {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return err
	}
	return a.adoptions.Release(adoptedIP)
}

func (a *Runtime) ResolveDNSAdoptedIPAddress(request operations.ResolveDNSAdoptedIPAddressRequest) (operations.ResolveDNSAdoptedIPAddressResult, error) {
	sourceIP, err := common.NormalizeAdoptionIP(request.SourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	source, err := a.adoptions.Lookup(sourceIP)
	if err != nil {
		return operations.ResolveDNSAdoptedIPAddressResult{}, err
	}
	return operations.ResolveDNS(&source, request)
}

func (a *Runtime) StartAdoptedIPAddressRecording(request adoptionpkg.StartAdoptedIPAddressRecordingRequest) (adoptionpkg.Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}

	outputPath := strings.TrimSpace(request.OutputPath)
	if outputPath == "" {
		downloadsDir, err := storage.DefaultDownloadsDir()
		if err != nil {
			return adoptionpkg.Identity{}, err
		}
		outputPath = filepath.Join(downloadsDir, fmt.Sprintf("%s-%s.pcap", ip.String(), time.Now().UTC().Format("20060102-150405")))
	}

	return a.adoptions.StartRecording(ip, outputPath)
}

func (a *Runtime) StopAdoptedIPAddressRecording(ip string) (adoptionpkg.Identity, error) {
	adoptedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.StopRecording(adoptedIP)
}

func (a *Runtime) ListServiceDefinitions() []adoptionpkg.ServiceDefinition {
	return operations.ListServiceDefinitions()
}

func (a *Runtime) StartAdoptedIPAddressService(request adoptionpkg.StartAdoptedIPAddressServiceRequest) (adoptionpkg.Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return operations.StartService(a.adoptions, ip, request.Service, request.Config)
}

func (a *Runtime) StopAdoptedIPAddressService(request adoptionpkg.StopAdoptedIPAddressServiceRequest) (adoptionpkg.Identity, error) {
	ip, err := common.NormalizeAdoptionIP(request.IP)
	if err != nil {
		return adoptionpkg.Identity{}, err
	}
	return a.adoptions.StopService(ip, request.Service)
}

func (a *Runtime) Shutdown() error {
	return a.adoptions.Close()
}

func (a *Runtime) ensureAdoptionListener(interfaceName string) (adoptionpkg.Listener, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}
	return operations.NewListener(*iface, a.adoptions.ForwardFrame)
}
