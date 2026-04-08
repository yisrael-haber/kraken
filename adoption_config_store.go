package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const storedAdoptionConfigurationFolder = "stored_adoption_configuration"

type StoredAdoptionConfiguration struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type storedAdoptionConfigurationStore struct {
	mu      sync.Mutex
	dir     string
	initErr error
}

func newStoredAdoptionConfigurationStore() *storedAdoptionConfigurationStore {
	dir, err := defaultKrakenConfigDir(storedAdoptionConfigurationFolder)
	return &storedAdoptionConfigurationStore{dir: dir, initErr: err}
}

func newStoredAdoptionConfigurationStoreAtDir(dir string) *storedAdoptionConfigurationStore {
	return &storedAdoptionConfigurationStore{dir: dir}
}

func (store *storedAdoptionConfigurationStore) list() ([]StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := ensureStoreDir(store.dir, store.initErr, "stored adoption configuration"); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return nil, fmt.Errorf("list stored adoption configurations: %w", err)
	}

	items := make([]StoredAdoptionConfiguration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := readStoredItem(filepath.Join(store.dir, entry.Name()), "stored adoption configuration", normalizeStoredAdoptionConfiguration)
		if err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Label) < strings.ToLower(items[j].Label)
	})

	return items, nil
}

func (store *storedAdoptionConfigurationStore) load(label string) (StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := ensureStoreDir(store.dir, store.initErr, "stored adoption configuration"); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	path, err := pathForStoredItem(store.dir, label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	return readStoredItem(path, "stored adoption configuration", normalizeStoredAdoptionConfiguration)
}

func (store *storedAdoptionConfigurationStore) save(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	config, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := ensureStoreDir(store.dir, store.initErr, "stored adoption configuration"); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	path, err := pathForStoredItem(store.dir, config.Label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	if err := writeStoredItem(path, "stored adoption configuration", config.Label, config); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	return config, nil
}

func (store *storedAdoptionConfigurationStore) delete(label string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := ensureStoreDir(store.dir, store.initErr, "stored adoption configuration"); err != nil {
		return err
	}

	path, err := pathForStoredItem(store.dir, label)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored adoption configuration %q: %w", label, err)
	}

	return nil
}

func normalizeStoredAdoptionConfiguration(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	label, err := normalizeAdoptionLabel(config.Label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	interfaceName := strings.TrimSpace(config.InterfaceName)
	if interfaceName == "" {
		return StoredAdoptionConfiguration{}, fmt.Errorf("interfaceName is required")
	}

	ip, err := normalizeAdoptionIP(config.IP)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	defaultGateway, err := normalizeDefaultGateway(config.DefaultGateway, ip)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	macText := strings.TrimSpace(config.MAC)
	if macText != "" {
		if _, err := net.ParseMAC(macText); err != nil {
			return StoredAdoptionConfiguration{}, fmt.Errorf("invalid MAC address %q: %w", config.MAC, err)
		}
	}

	return StoredAdoptionConfiguration{
		Label:          label,
		InterfaceName:  interfaceName,
		IP:             ip.String(),
		MAC:            macText,
		DefaultGateway: ipString(defaultGateway),
	}, nil
}
