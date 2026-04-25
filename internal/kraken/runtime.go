package kraken

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	configpkg "github.com/yisrael-haber/kraken/internal/kraken/config"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	routingpkg "github.com/yisrael-haber/kraken/internal/kraken/routing"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

type Runtime struct {
	adoptions     *adoptionpkg.Service
	storedConfigs *configpkg.Store
	storedRoutes  *routingpkg.Store
	storedScripts *scriptpkg.Store
}

// NewRuntime creates the backend runtime used by the Wails-facing app shell.
func NewRuntime() *Runtime {
	storedScripts := scriptpkg.NewStore()
	storedRoutes := routingpkg.NewStore()

	return &Runtime{
		adoptions:     adoptionpkg.NewService(storedScripts.Lookup, storedRoutes.MatchDestination, operations.NewListener),
		storedConfigs: configpkg.NewStore(),
		storedRoutes:  storedRoutes,
		storedScripts: storedScripts,
	}
}

func (a *Runtime) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List()
}

func (a *Runtime) GetConfigurationDirectory() (string, error) {
	return storeutil.DefaultKrakenConfigRoot()
}

func (a *Runtime) AdoptIPAddress(request adoptionpkg.AdoptIPAddressRequest) (adoptionpkg.AdoptedIPAddress, error) {
	return a.adoptions.Adopt(request)
}

func (a *Runtime) ListAdoptedIPAddresses() []adoptionpkg.AdoptedIPAddress {
	return a.adoptions.Snapshot()
}

func (a *Runtime) GetAdoptedIPAddressDetails(ip string) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.Details(ip)
}

func (a *Runtime) ListStoredAdoptionConfigurations() ([]configpkg.StoredAdoptionConfiguration, error) {
	return a.storedConfigs.List()
}

func (a *Runtime) SaveStoredAdoptionConfiguration(config configpkg.StoredAdoptionConfiguration) (configpkg.StoredAdoptionConfiguration, error) {
	return a.storedConfigs.Save(config)
}

func (a *Runtime) DeleteStoredAdoptionConfiguration(label string) error {
	return a.storedConfigs.Delete(label)
}

func (a *Runtime) ListStoredRoutes() ([]routingpkg.StoredRoute, error) {
	return a.storedRoutes.List()
}

func (a *Runtime) SaveStoredRoute(route routingpkg.StoredRoute) (routingpkg.StoredRoute, error) {
	transportScriptName, err := a.normalizeStoredScriptName("transportScriptName", route.TransportScriptName, scriptpkg.SurfaceTransport)
	if err != nil {
		return routingpkg.StoredRoute{}, err
	}
	route.TransportScriptName = transportScriptName

	return a.storedRoutes.Save(route)
}

func (a *Runtime) DeleteStoredRoute(label string) error {
	return a.storedRoutes.Delete(label)
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

func (a *Runtime) AdoptStoredAdoptionConfiguration(label string) (adoptionpkg.AdoptedIPAddress, error) {
	config, err := a.storedConfigs.Load(label)
	if err != nil {
		return adoptionpkg.AdoptedIPAddress{}, err
	}

	return a.adoptions.Adopt(adoptionpkg.AdoptIPAddressRequest{
		Label:          config.Label,
		InterfaceName:  config.InterfaceName,
		IP:             config.IP,
		MAC:            config.MAC,
		DefaultGateway: config.DefaultGateway,
		MTU:            config.MTU,
	})
}

func (a *Runtime) UpdateAdoptedIPAddressScripts(request adoptionpkg.UpdateAdoptedIPAddressScriptsRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	transportScriptName, err := a.normalizeStoredScriptName("transportScriptName", request.TransportScriptName, scriptpkg.SurfaceTransport)
	if err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}
	applicationScriptName, err := a.normalizeStoredScriptName("applicationScriptName", request.ApplicationScriptName, scriptpkg.SurfaceApplication)
	if err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}

	if err := a.adoptions.UpdateScripts(request.IP, transportScriptName, applicationScriptName); err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}

	return a.adoptions.Details(request.IP)
}

func (a *Runtime) UpdateAdoptedIPAddress(request adoptionpkg.UpdateAdoptedIPAddressRequest) (adoptionpkg.AdoptedIPAddress, error) {
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

func (a *Runtime) StartAdoptedIPAddressRecording(request adoptionpkg.StartAdoptedIPAddressRecordingRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	outputPath := strings.TrimSpace(request.OutputPath)
	if outputPath == "" {
		normalizedIP, err := common.NormalizeAdoptionIP(request.IP)
		if err != nil {
			return adoptionpkg.AdoptedIPAddressDetails{}, err
		}
		downloadsDir, err := storeutil.DefaultDownloadsDir()
		if err != nil {
			return adoptionpkg.AdoptedIPAddressDetails{}, err
		}
		outputPath = filepath.Join(downloadsDir, fmt.Sprintf("%s-%s.pcap", normalizedIP.String(), time.Now().UTC().Format("20060102-150405")))
	}

	return a.adoptions.StartRecording(request.IP, outputPath)
}

func (a *Runtime) StopAdoptedIPAddressRecording(ip string) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.StopRecording(ip)
}

func (a *Runtime) ListServiceDefinitions() []adoptionpkg.ServiceDefinition {
	return operations.ListServiceDefinitions()
}

func (a *Runtime) StartAdoptedIPAddressService(request adoptionpkg.StartAdoptedIPAddressServiceRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.StartService(request)
}

func (a *Runtime) StopAdoptedIPAddressService(request adoptionpkg.StopAdoptedIPAddressServiceRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.StopService(request)
}

func (a *Runtime) Shutdown() error {
	return a.adoptions.Close()
}

func (a *Runtime) normalizeStoredScriptName(fieldName, scriptName string, surface scriptpkg.Surface) (string, error) {
	normalized := adoptionpkg.NormalizeScriptName(scriptName)
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
