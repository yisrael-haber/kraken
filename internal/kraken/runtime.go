package kraken

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/capture"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	configpkg "github.com/yisrael-haber/kraken/internal/kraken/config"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
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
		adoptions:     adoptionpkg.NewService(storedScripts.Lookup, storedRoutes.MatchDestination, capture.NewListener),
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
	scriptName, err := a.validateAndNormalizeScriptName(route.ScriptName, scriptpkg.SurfacePacket)
	if err != nil {
		return routingpkg.StoredRoute{}, err
	}
	route.ScriptName = scriptName

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
	})
}

func (a *Runtime) UpdateAdoptedIPAddressScript(request adoptionpkg.UpdateAdoptedIPAddressScriptRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	scriptName, err := a.validateAndNormalizeScriptName(request.ScriptName, scriptpkg.SurfacePacket)
	if err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}

	if err := a.adoptions.UpdateScript(request.IP, scriptName); err != nil {
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

func (a *Runtime) StartAdoptedIPAddressRecording(request adoptionpkg.StartAdoptedIPAddressRecordingRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	outputPath, err := a.recordingOutputPath(request)
	if err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}

	return a.adoptions.StartRecording(request.IP, outputPath)
}

func (a *Runtime) StopAdoptedIPAddressRecording(ip string) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.StopRecording(ip)
}

func (a *Runtime) StartAdoptedIPAddressTCPService(request adoptionpkg.StartAdoptedIPAddressTCPServiceRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	scriptName, err := a.validateAndNormalizeScriptName(request.ScriptName, scriptpkg.SurfaceHTTPService)
	if err != nil {
		return adoptionpkg.AdoptedIPAddressDetails{}, err
	}
	request.ScriptName = scriptName

	return a.adoptions.StartTCPService(request)
}

func (a *Runtime) StopAdoptedIPAddressTCPService(request adoptionpkg.StopAdoptedIPAddressTCPServiceRequest) (adoptionpkg.AdoptedIPAddressDetails, error) {
	return a.adoptions.StopTCPService(request)
}

func (a *Runtime) Shutdown() error {
	return a.adoptions.Close()
}

func (a *Runtime) validateStoredScriptName(name string, surface scriptpkg.Surface) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	_, err := a.storedScripts.Lookup(scriptpkg.StoredScriptRef{
		Name:    name,
		Surface: surface,
	})
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, scriptpkg.ErrStoredScriptInvalid):
		return err
	case errors.Is(err, scriptpkg.ErrStoredScriptNotFound):
		return fmt.Errorf("stored script %q was not found", name)
	default:
		return err
	}
}

func (a *Runtime) validateAndNormalizeScriptName(scriptName string, surface scriptpkg.Surface) (string, error) {
	normalized := adoptionpkg.NormalizeScriptName(scriptName)
	if err := a.validateStoredScriptName(normalized, surface); err != nil {
		return "", fmt.Errorf("scriptName: %w", err)
	}

	return normalized, nil
}

func (a *Runtime) recordingOutputPath(request adoptionpkg.StartAdoptedIPAddressRecordingRequest) (string, error) {
	outputPath := strings.TrimSpace(request.OutputPath)
	if outputPath != "" {
		return outputPath, nil
	}

	return DefaultAdoptedIPAddressRecordingPath(request.IP, time.Now())
}

func DefaultAdoptedIPAddressRecordingPath(ip string, now time.Time) (string, error) {
	normalizedIP, err := common.NormalizeAdoptionIP(ip)
	if err != nil {
		return "", err
	}

	downloadsDir, err := storeutil.DefaultDownloadsDir()
	if err != nil {
		return "", err
	}

	fileName := fmt.Sprintf("%s-%s.pcap", normalizedIP.String(), now.UTC().Format("20060102-150405"))
	return filepath.Join(downloadsDir, fileName), nil
}
