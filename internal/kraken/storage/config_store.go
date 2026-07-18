package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	files storedFileSet
}

func NewConfigStore() (*ConfigStore, error) {
	dir, err := CreateKrakenConfigDir(storedAdoptionConfigurationFolder)
	if err != nil {
		return nil, err
	}
	return &ConfigStore{files: storedFileSet{
		dir:       dir,
		extension: ".json",
	}}, nil
}

func (store *ConfigStore) List() ([]StoredAdoptionConfiguration, error) {
	entries, err := os.ReadDir(store.files.dir)
	if err != nil {
		return nil, err
	}

	items := make([]StoredAdoptionConfiguration, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != store.files.extension {
			continue
		}
		item, err := readStoredAdoptionConfiguration(filepath.Join(store.files.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (store *ConfigStore) Load(label string) (StoredAdoptionConfiguration, error) {
	path, err := store.files.path(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return readStoredAdoptionConfiguration(path)
}

func (store *ConfigStore) Save(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	normalized, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	if err := writeStoredAdoptionConfiguration(store.files, normalized); err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return normalized, nil
}

func (store *ConfigStore) Copy(label, newLabel string) (StoredAdoptionConfiguration, error) {
	config, err := store.Load(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	config.Label = newLabel
	return store.Save(config)
}

func (store *ConfigStore) Delete(label string) error {
	return store.files.delete(label)
}

func readStoredAdoptionConfiguration(path string) (StoredAdoptionConfiguration, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	var config StoredAdoptionConfiguration
	return config, json.Unmarshal(payload, &config)
}

func writeStoredAdoptionConfiguration(files storedFileSet, config StoredAdoptionConfiguration) error {
	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode stored adoption configuration: %w", err)
	}
	return files.write(config.Label, append(payload, '\n'))
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
	subnetPrefix, err := common.NormalizeSubnetPrefix(config.SubnetPrefix)
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
	defaultGatewayText := ""
	if defaultGateway != nil {
		defaultGatewayText = defaultGateway.String()
	}

	return StoredAdoptionConfiguration{
		Label:          config.Label,
		InterfaceName:  interfaceName,
		IP:             ip.String(),
		MAC:            macText,
		SubnetPrefix:   subnetPrefix,
		DefaultGateway: defaultGatewayText,
		MTU:            config.MTU,
	}, nil
}
