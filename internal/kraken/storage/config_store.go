package storage

import (
	"fmt"
	"net"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const storedAdoptionConfigurationFolder = "stored_adoption_configuration"

type StoredAdoptionConfiguration struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
}

type ConfigStore = JSONStore[StoredAdoptionConfiguration]

func NewConfigStore() *ConfigStore {
	dir, err := DefaultKrakenConfigDir(storedAdoptionConfigurationFolder)
	return newConfigStore(dir, err)
}

func NewConfigStoreAtDir(dir string) *ConfigStore {
	return newConfigStore(dir, nil)
}

func newConfigStore(dir string, initErr error) *ConfigStore {
	itemStore := NewJSONStore(
		dir,
		initErr,
		"stored adoption configuration",
		normalizeStoredAdoptionConfiguration,
		func(item StoredAdoptionConfiguration) string {
			return item.Label
		},
		func(items map[string]StoredAdoptionConfiguration) []StoredAdoptionConfiguration {
			return SortedItems(items, func(left, right StoredAdoptionConfiguration) bool {
				return strings.ToLower(left.Label) < strings.ToLower(right.Label)
			})
		},
	)
	return (*ConfigStore)(itemStore)
}

func normalizeStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	label, err := common.NormalizeAdoptionLabel(config.Label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
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
		Label:          label,
		InterfaceName:  interfaceName,
		IP:             ip.String(),
		MAC:            macText,
		DefaultGateway: common.IPString(defaultGateway),
		MTU:            config.MTU,
	}, nil
}
