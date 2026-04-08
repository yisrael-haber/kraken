package kraken

import (
	"errors"
	"fmt"
	"strings"

	adoptionpkg "github.com/yisrael-haber/kraken/internal/kraken/adoption"
	"github.com/yisrael-haber/kraken/internal/kraken/capture"
	configpkg "github.com/yisrael-haber/kraken/internal/kraken/config"
	"github.com/yisrael-haber/kraken/internal/kraken/inventory"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
	scriptpkg "github.com/yisrael-haber/kraken/internal/kraken/script"
)

type Runtime struct {
	adoptions       *adoptionpkg.Service
	storedConfigs   *configpkg.Store
	storedOverrides *packetpkg.Store
	storedScripts   *scriptpkg.Store
}

// NewRuntime creates the backend runtime used by the Wails-facing app shell.
func NewRuntime() *Runtime {
	storedOverrides := packetpkg.NewStore()
	storedScripts := scriptpkg.NewStore()

	return &Runtime{
		adoptions: adoptionpkg.NewService(func(name string) (packetpkg.StoredPacketOverride, error) {
			return storedOverrides.Lookup(name)
		}, func(name string) (scriptpkg.StoredScript, error) {
			return storedScripts.Lookup(name)
		}, capture.NewListener),
		storedConfigs:   configpkg.NewStore(),
		storedOverrides: storedOverrides,
		storedScripts:   storedScripts,
	}
}

func (a *Runtime) ListInterfaces() (InterfaceSnapshot, error) {
	return inventory.List()
}

func (a *Runtime) AdoptIPAddress(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	return a.adoptions.Adopt(request)
}

func (a *Runtime) ListAdoptedIPAddresses() []AdoptedIPAddress {
	return a.adoptions.Snapshot()
}

func (a *Runtime) GetAdoptedIPAddressDetails(ip string) (AdoptedIPAddressDetails, error) {
	return a.adoptions.Details(ip)
}

func (a *Runtime) ListStoredAdoptionConfigurations() ([]StoredAdoptionConfiguration, error) {
	return a.storedConfigs.List()
}

func (a *Runtime) SaveStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	return a.storedConfigs.Save(config)
}

func (a *Runtime) DeleteStoredAdoptionConfiguration(label string) error {
	return a.storedConfigs.Delete(label)
}

func (a *Runtime) ListStoredPacketOverrides() ([]StoredPacketOverride, error) {
	return a.storedOverrides.List()
}

func (a *Runtime) SaveStoredPacketOverride(override StoredPacketOverride) (StoredPacketOverride, error) {
	return a.storedOverrides.Save(override)
}

func (a *Runtime) DeleteStoredPacketOverride(name string) error {
	return a.storedOverrides.Delete(name)
}

func (a *Runtime) ListStoredScripts() ([]scriptpkg.StoredScriptSummary, error) {
	return a.storedScripts.List()
}

func (a *Runtime) GetStoredScript(name string) (scriptpkg.StoredScript, error) {
	return a.storedScripts.Get(name)
}

func (a *Runtime) SaveStoredScript(request scriptpkg.SaveStoredScriptRequest) (scriptpkg.StoredScript, error) {
	return a.storedScripts.Save(request)
}

func (a *Runtime) DeleteStoredScript(name string) error {
	return a.storedScripts.Delete(name)
}

func (a *Runtime) RefreshStoredScripts() ([]scriptpkg.StoredScriptSummary, error) {
	return a.storedScripts.Refresh()
}

func (a *Runtime) AdoptStoredAdoptionConfiguration(label string) (AdoptedIPAddress, error) {
	config, err := a.storedConfigs.Load(label)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return a.adoptions.Adopt(AdoptIPAddressRequest{
		Label:          config.Label,
		InterfaceName:  config.InterfaceName,
		IP:             config.IP,
		MAC:            config.MAC,
		DefaultGateway: config.DefaultGateway,
	})
}

func (a *Runtime) ClearAdoptedIPAddressActivity(ip string, scope string) error {
	return a.adoptions.ClearActivity(ip, scope)
}

func (a *Runtime) UpdateAdoptedIPAddressOverrideBindings(request UpdateAdoptedIPAddressOverrideBindingsRequest) (AdoptedIPAddressDetails, error) {
	bindings := adoptionpkg.NormalizeOverrideBindings(request.Bindings)
	fields := []struct {
		name  string
		value string
		kind  string
	}{
		{name: "bindings.arpRequestOverride", value: bindings.ARPRequestOverride, kind: "override"},
		{name: "bindings.arpRequestScript", value: bindings.ARPRequestScript, kind: "script"},
		{name: "bindings.arpReplyOverride", value: bindings.ARPReplyOverride, kind: "override"},
		{name: "bindings.arpReplyScript", value: bindings.ARPReplyScript, kind: "script"},
		{name: "bindings.icmpEchoRequestOverride", value: bindings.ICMPEchoRequestOverride, kind: "override"},
		{name: "bindings.icmpEchoRequestScript", value: bindings.ICMPEchoRequestScript, kind: "script"},
		{name: "bindings.icmpEchoReplyOverride", value: bindings.ICMPEchoReplyOverride, kind: "override"},
		{name: "bindings.icmpEchoReplyScript", value: bindings.ICMPEchoReplyScript, kind: "script"},
	}

	for _, field := range fields {
		var err error
		switch field.kind {
		case "script":
			err = a.validateScriptBindingExists(field.value)
		default:
			err = a.validateOverrideBindingExists(field.value)
		}
		if err != nil {
			return AdoptedIPAddressDetails{}, fmt.Errorf("%s: %w", field.name, err)
		}
	}

	if err := a.adoptions.UpdateOverrideBindings(request.IP, bindings); err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return a.adoptions.Details(request.IP)
}

func (a *Runtime) UpdateAdoptedIPAddress(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	return a.adoptions.Update(request)
}

func (a *Runtime) ReleaseIPAddress(ip string) error {
	return a.adoptions.Release(ip)
}

func (a *Runtime) PingAdoptedIPAddress(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	return a.adoptions.Ping(request)
}

func (a *Runtime) validateOverrideBindingExists(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}

	if _, err := a.storedOverrides.Lookup(name); err == nil {
		return nil
	} else if !errors.Is(err, packetpkg.ErrStoredPacketOverrideNotFound) {
		return err
	}

	return fmt.Errorf("stored packet override %q was not found", name)
}

func (a *Runtime) validateScriptBindingExists(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}

	if _, err := a.storedScripts.Lookup(name); err == nil {
		return nil
	} else if !errors.Is(err, scriptpkg.ErrStoredScriptNotFound) && !errors.Is(err, scriptpkg.ErrStoredScriptInvalid) {
		return err
	} else if errors.Is(err, scriptpkg.ErrStoredScriptInvalid) {
		return err
	}

	return fmt.Errorf("stored script %q was not found", name)
}
