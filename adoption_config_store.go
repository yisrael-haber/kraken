package main

import (
	"encoding/json"
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
	Label         string `json:"label"`
	InterfaceName string `json:"interfaceName"`
	IP            string `json:"ip"`
	MAC           string `json:"mac,omitempty"`
}

type storedAdoptionConfigurationStore struct {
	mu      sync.Mutex
	dir     string
	initErr error
}

func newStoredAdoptionConfigurationStore() *storedAdoptionConfigurationStore {
	dir, err := defaultStoredAdoptionConfigurationDir()
	return &storedAdoptionConfigurationStore{
		dir:     dir,
		initErr: err,
	}
}

func newStoredAdoptionConfigurationStoreAtDir(dir string) *storedAdoptionConfigurationStore {
	return &storedAdoptionConfigurationStore{dir: dir}
}

func defaultStoredAdoptionConfigurationDir() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}

	return filepath.Join(baseDir, "Kraken", storedAdoptionConfigurationFolder), nil
}

func (store *storedAdoptionConfigurationStore) list() ([]StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureReadyLocked(); err != nil {
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

		item, err := store.readConfigLocked(filepath.Join(store.dir, entry.Name()))
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

	if err := store.ensureReadyLocked(); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	path, err := store.pathForLabelLocked(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	return store.readConfigLocked(path)
}

func (store *storedAdoptionConfigurationStore) save(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	config, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureReadyLocked(); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	path, err := store.pathForLabelLocked(config.Label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("encode stored adoption configuration: %w", err)
	}

	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("write stored adoption configuration %q: %w", config.Label, err)
	}

	return config, nil
}

func (store *storedAdoptionConfigurationStore) ensureReadyLocked() error {
	if store.initErr != nil {
		return store.initErr
	}

	if store.dir == "" {
		return fmt.Errorf("stored adoption configuration directory is unavailable")
	}

	if err := os.MkdirAll(store.dir, 0o755); err != nil {
		return fmt.Errorf("create stored adoption configuration directory: %w", err)
	}

	return nil
}

func (store *storedAdoptionConfigurationStore) pathForLabelLocked(label string) (string, error) {
	normalized, err := normalizeAdoptionLabel(label)
	if err != nil {
		return "", err
	}

	return filepath.Join(store.dir, normalized+".json"), nil
}

func (store *storedAdoptionConfigurationStore) readConfigLocked(path string) (StoredAdoptionConfiguration, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("read stored adoption configuration %q: %w", filepath.Base(path), err)
	}

	var config StoredAdoptionConfiguration
	if err := json.Unmarshal(payload, &config); err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("decode stored adoption configuration %q: %w", filepath.Base(path), err)
	}

	normalized, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, fmt.Errorf("validate stored adoption configuration %q: %w", filepath.Base(path), err)
	}

	return normalized, nil
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

	macText := strings.TrimSpace(config.MAC)
	if macText != "" {
		if _, err := net.ParseMAC(macText); err != nil {
			return StoredAdoptionConfiguration{}, fmt.Errorf("invalid MAC address %q: %w", config.MAC, err)
		}
	}

	return StoredAdoptionConfiguration{
		Label:         label,
		InterfaceName: interfaceName,
		IP:            ip.String(),
		MAC:           macText,
	}, nil
}
