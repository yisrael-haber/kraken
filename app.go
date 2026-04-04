package main

type App struct {
	adoptions     *adoptionManager
	storedConfigs *storedAdoptionConfigurationStore
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		adoptions:     newAdoptionManager(),
		storedConfigs: newStoredAdoptionConfigurationStore(),
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

func (a *App) AdoptStoredAdoptionConfiguration(label string) (AdoptedIPAddress, error) {
	config, err := a.storedConfigs.load(label)
	if err != nil {
		return AdoptedIPAddress{}, err
	}

	return a.adoptions.adopt(AdoptIPAddressRequest{
		Label:         config.Label,
		InterfaceName: config.InterfaceName,
		IP:            config.IP,
		MAC:           config.MAC,
	})
}

func (a *App) ClearAdoptedIPAddressActivity(ip string, scope string) error {
	return a.adoptions.clearActivity(ip, scope)
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
