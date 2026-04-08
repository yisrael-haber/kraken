package main

import (
	"fmt"
	"strings"
)

type App struct {
	adoptions       *adoptionManager
	storedConfigs   *storedAdoptionConfigurationStore
	storedOverrides *storedPacketOverrideStore
}

// NewApp creates a new App application struct.
func NewApp() *App {
	storedOverrides := newStoredPacketOverrideStore()

	return &App{
		adoptions: newAdoptionManager(func(name string) (StoredPacketOverride, bool) {
			return storedOverrides.lookup(name)
		}),
		storedConfigs:   newStoredAdoptionConfigurationStore(),
		storedOverrides: storedOverrides,
	}
}

func (a *App) AdoptIPAddress(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	return a.adoptions.adopt(request)
}

func (a *App) ListAdoptedIPAddresses() []AdoptedIPAddress {
	return a.adoptions.snapshot()
}

func (a *App) GetAdoptedIPAddressDetails(ip string) (AdoptedIPAddressDetails, error) {
	return a.adoptions.details(ip)
}

func (a *App) ListStoredAdoptionConfigurations() ([]StoredAdoptionConfiguration, error) {
	return a.storedConfigs.list()
}

func (a *App) SaveStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	return a.storedConfigs.save(config)
}

func (a *App) DeleteStoredAdoptionConfiguration(label string) error {
	return a.storedConfigs.delete(label)
}

func (a *App) ListStoredPacketOverrides() ([]StoredPacketOverride, error) {
	return a.storedOverrides.list()
}

func (a *App) SaveStoredPacketOverride(override StoredPacketOverride) (StoredPacketOverride, error) {
	return a.storedOverrides.save(override)
}

func (a *App) DeleteStoredPacketOverride(name string) error {
	return a.storedOverrides.delete(name)
}

func (a *App) AdoptStoredAdoptionConfiguration(label string) (AdoptedIPAddress, error) {
	config, err := a.storedConfigs.load(label)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return a.adoptions.adopt(AdoptIPAddressRequest{
		Label:          config.Label,
		InterfaceName:  config.InterfaceName,
		IP:             config.IP,
		MAC:            config.MAC,
		DefaultGateway: config.DefaultGateway,
	})
}

func (a *App) ClearAdoptedIPAddressActivity(ip string, scope string) error {
	return a.adoptions.clearActivity(ip, scope)
}

func (a *App) UpdateAdoptedIPAddressOverrideBindings(request UpdateAdoptedIPAddressOverrideBindingsRequest) (AdoptedIPAddressDetails, error) {
	bindings := normalizeAdoptedIPAddressOverrideBindings(request.Bindings)
	fields := []struct {
		name  string
		value string
	}{
		{name: "bindings.arpRequestOverride", value: bindings.ARPRequestOverride},
		{name: "bindings.arpReplyOverride", value: bindings.ARPReplyOverride},
		{name: "bindings.icmpEchoRequestOverride", value: bindings.ICMPEchoRequestOverride},
		{name: "bindings.icmpEchoReplyOverride", value: bindings.ICMPEchoReplyOverride},
	}

	for _, field := range fields {
		if err := a.validateOverrideBindingExists(field.value); err != nil {
			return AdoptedIPAddressDetails{}, fmt.Errorf("%s: %w", field.name, err)
		}
	}

	if err := a.adoptions.updateOverrideBindings(request.IP, bindings); err != nil {
		return AdoptedIPAddressDetails{}, err
	}

	return a.adoptions.details(request.IP)
}

func (a *App) UpdateAdoptedIPAddress(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	return a.adoptions.update(request)
}

func (a *App) ReleaseIPAddress(ip string) error {
	return a.adoptions.release(ip)
}

func (a *App) PingAdoptedIPAddress(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	return a.adoptions.ping(request)
}

func (a *App) validateOverrideBindingExists(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}

	if _, exists := a.storedOverrides.lookup(name); exists {
		return nil
	}

	return fmt.Errorf("stored packet override %q was not found", name)
}
