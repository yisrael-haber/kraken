package main

import backend "github.com/yisrael-haber/kraken/internal/kraken"

type App struct {
	runtime *backend.Runtime
}

func NewApp() *App {
	return &App{runtime: backend.NewRuntime()}
}

func (a *App) ListInterfaces() (InterfaceSnapshot, error) {
	return a.runtime.ListInterfaces()
}

func (a *App) AdoptIPAddress(request AdoptIPAddressRequest) (AdoptedIPAddress, error) {
	return a.runtime.AdoptIPAddress(request)
}

func (a *App) ListAdoptedIPAddresses() []AdoptedIPAddress {
	return a.runtime.ListAdoptedIPAddresses()
}

func (a *App) GetAdoptedIPAddressDetails(ip string) (AdoptedIPAddressDetails, error) {
	return a.runtime.GetAdoptedIPAddressDetails(ip)
}

func (a *App) ListStoredAdoptionConfigurations() ([]StoredAdoptionConfiguration, error) {
	return a.runtime.ListStoredAdoptionConfigurations()
}

func (a *App) SaveStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	return a.runtime.SaveStoredAdoptionConfiguration(config)
}

func (a *App) DeleteStoredAdoptionConfiguration(label string) error {
	return a.runtime.DeleteStoredAdoptionConfiguration(label)
}

func (a *App) ListStoredPacketOverrides() ([]StoredPacketOverride, error) {
	return a.runtime.ListStoredPacketOverrides()
}

func (a *App) SaveStoredPacketOverride(override StoredPacketOverride) (StoredPacketOverride, error) {
	return a.runtime.SaveStoredPacketOverride(override)
}

func (a *App) DeleteStoredPacketOverride(name string) error {
	return a.runtime.DeleteStoredPacketOverride(name)
}

func (a *App) ListStoredScripts() ([]StoredScriptSummary, error) {
	return a.runtime.ListStoredScripts()
}

func (a *App) GetStoredScript(name string) (StoredScript, error) {
	return a.runtime.GetStoredScript(name)
}

func (a *App) SaveStoredScript(request SaveStoredScriptRequest) (StoredScript, error) {
	return a.runtime.SaveStoredScript(request)
}

func (a *App) DeleteStoredScript(name string) error {
	return a.runtime.DeleteStoredScript(name)
}

func (a *App) RefreshStoredScripts() ([]StoredScriptSummary, error) {
	return a.runtime.RefreshStoredScripts()
}

func (a *App) AdoptStoredAdoptionConfiguration(label string) (AdoptedIPAddress, error) {
	return a.runtime.AdoptStoredAdoptionConfiguration(label)
}

func (a *App) ClearAdoptedIPAddressActivity(ip string, scope string) error {
	return a.runtime.ClearAdoptedIPAddressActivity(ip, scope)
}

func (a *App) UpdateAdoptedIPAddressOverrideBindings(request UpdateAdoptedIPAddressOverrideBindingsRequest) (AdoptedIPAddressDetails, error) {
	return a.runtime.UpdateAdoptedIPAddressOverrideBindings(request)
}

func (a *App) UpdateAdoptedIPAddress(request UpdateAdoptedIPAddressRequest) (AdoptedIPAddress, error) {
	return a.runtime.UpdateAdoptedIPAddress(request)
}

func (a *App) ReleaseIPAddress(ip string) error {
	return a.runtime.ReleaseIPAddress(ip)
}

func (a *App) PingAdoptedIPAddress(request PingAdoptedIPAddressRequest) (PingAdoptedIPAddressResult, error) {
	return a.runtime.PingAdoptedIPAddress(request)
}
