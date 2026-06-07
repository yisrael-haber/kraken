package storage

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const storedAdoptionConfigurationFolder = "stored_adoption_configuration"

type StoredAdoptionConfiguration struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	SubnetPrefix   int    `json:"subnetPrefix,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type ConfigStore struct {
	store *JSONStore[StoredAdoptionConfiguration]
}

func NewConfigStore() *ConfigStore {
	dir, err := DefaultKrakenConfigDir(storedAdoptionConfigurationFolder)
	return newConfigStore(dir, err)
}

func NewConfigStoreAtDir(dir string) *ConfigStore {
	return newConfigStore(dir, nil)
}

func newConfigStore(dir string, initErr error) *ConfigStore {
	return &ConfigStore{store: NewJSONStore[StoredAdoptionConfiguration](dir, initErr, "stored adoption configuration")}
}

func (store *ConfigStore) List() ([]StoredAdoptionConfiguration, error) {
	files, err := store.store.List()
	if err != nil {
		return nil, err
	}

	items := make([]StoredAdoptionConfiguration, 0, len(files))
	for name, value := range files {
		item, err := normalizeStoredAdoptionConfiguration(value)
		if err != nil {
			return nil, fmt.Errorf("validate stored adoption configuration %q: %w", name+".json", err)
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Label) < strings.ToLower(items[j].Label)
	})
	return items, nil
}

func (store *ConfigStore) Load(label string) (StoredAdoptionConfiguration, error) {
	item, err := store.store.Load(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return normalizeStoredAdoptionConfiguration(item)
}

func (store *ConfigStore) Save(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	normalized, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	if err := store.store.Save(normalized.Label, normalized); err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return normalized, nil
}

func (store *ConfigStore) Delete(label string) error {
	return store.store.Delete(label)
}

func normalizeStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	if !common.ValidLabel(config.Label) {
		return StoredAdoptionConfiguration{}, fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	interfaceName := strings.TrimSpace(config.InterfaceName)
	if interfaceName == "" {
		return StoredAdoptionConfiguration{}, fmt.Errorf("interfaceName is required")
	}

	ip, err := common.NormalizeAdoptionIP(config.IP)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	defaultGateway, err := common.NormalizeDefaultGateway(config.DefaultGateway, ip)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	subnetPrefix, err := normalizeStoredSubnetPrefix(config.SubnetPrefix)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	macText := strings.TrimSpace(config.MAC)
	if macText != "" {
		if _, err := net.ParseMAC(macText); err != nil {
			return StoredAdoptionConfiguration{}, fmt.Errorf("invalid MAC address %q: %w", config.MAC, err)
		}
	}
	if config.MTU != 0 && (config.MTU < 68 || config.MTU > 65535) {
		return StoredAdoptionConfiguration{}, fmt.Errorf("mtu must be between 68 and 65535")
	}

	return StoredAdoptionConfiguration{
		Label:          config.Label,
		InterfaceName:  interfaceName,
		IP:             ip.String(),
		MAC:            macText,
		SubnetPrefix:   subnetPrefix,
		DefaultGateway: ipString(defaultGateway),
		MTU:            config.MTU,
	}, nil
}

func normalizeStoredSubnetPrefix(prefix int) (int, error) {
	if prefix == 0 {
		return 24, nil
	}
	if prefix < 1 || prefix > 32 {
		return 0, fmt.Errorf("subnetPrefix must be between 1 and 32")
	}
	return prefix, nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
