package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	files storedFileSet
}

func NewConfigStore() *ConfigStore {
	dir, err := DefaultKrakenConfigDir(storedAdoptionConfigurationFolder)
	return &ConfigStore{files: storedFileSet{
		dir:       dir,
		initErr:   err,
		itemLabel: "stored adoption configuration",
		extension: ".json",
	}}
}

func (store *ConfigStore) List() ([]StoredAdoptionConfiguration, error) {
	entries, err := store.files.entries()
	if err != nil {
		return nil, err
	}

	items := make([]StoredAdoptionConfiguration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != store.files.extension {
			continue
		}
		item, err := readStoredAdoptionConfiguration(store.files, filepath.Join(store.files.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		item, err = normalizeStoredAdoptionConfiguration(item)
		if err != nil {
			return nil, fmt.Errorf("validate stored adoption configuration %q: %w", entry.Name(), err)
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Label) < strings.ToLower(items[j].Label)
	})
	return items, nil
}

func (store *ConfigStore) Load(label string) (StoredAdoptionConfiguration, error) {
	if err := store.files.ensureDir(); err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	path, err := store.files.path(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	item, err := readStoredAdoptionConfiguration(store.files, path)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return normalizeStoredAdoptionConfiguration(item)
}

func (store *ConfigStore) Replace(previousLabel string, config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	normalized, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	if previousLabel != "" && previousLabel != normalized.Label {
		err = store.rename(previousLabel, normalized)
	} else {
		err = writeStoredAdoptionConfiguration(store.files, normalized.Label, normalized)
	}
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	return normalized, nil
}

func (store *ConfigStore) Delete(label string) error {
	return store.files.delete(label)
}

func (store *ConfigStore) rename(previousLabel string, config StoredAdoptionConfiguration) error {
	if err := store.files.ensureDir(); err != nil {
		return err
	}
	previousPath, err := store.files.path(previousLabel)
	if err != nil {
		return err
	}
	previous, err := readStoredAdoptionConfiguration(store.files, previousPath)
	if err != nil {
		return err
	}
	path, err := store.files.path(config.Label)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("stored adoption configuration %q already exists", config.Label)
	}
	if err := writeStoredAdoptionConfiguration(store.files, previousLabel, config); err != nil {
		return err
	}
	if err := os.Rename(previousPath, path); err != nil {
		_ = writeStoredAdoptionConfiguration(store.files, previousLabel, previous)
		return fmt.Errorf("rename stored adoption configuration %q to %q: %w", previousLabel, config.Label, err)
	}
	return nil
}

func readStoredAdoptionConfiguration(files storedFileSet, path string) (StoredAdoptionConfiguration, error) {
	payload, err := files.read(path)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	var config StoredAdoptionConfiguration
	if err := json.Unmarshal(payload, &config); err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("decode stored adoption configuration %q: %w", filepath.Base(path), err)
	}
	return config, nil
}

func writeStoredAdoptionConfiguration(files storedFileSet, label string, config StoredAdoptionConfiguration) error {
	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode stored adoption configuration: %w", err)
	}
	_, err = files.write(label, append(payload, '\n'))
	return err
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

func normalizeStoredSubnetPrefix(prefix int) (int, error) {
	if prefix == 0 {
		return 24, nil
	}
	if prefix < 1 || prefix > 32 {
		return 0, fmt.Errorf("subnetPrefix must be between 1 and 32")
	}
	return prefix, nil
}
