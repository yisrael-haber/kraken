package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

const storedAdoptionConfigurationFolder = "stored_adoption_configuration"

type StoredAdoptionConfiguration struct {
	Label          string `json:"label"`
	InterfaceName  string `json:"interfaceName"`
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredAdoptionConfiguration
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedAdoptionConfigurationFolder)
	return newStore(dir, err)
}

func NewStoreAtDir(dir string) *Store {
	return newStore(dir, nil)
}

func newStore(dir string, initErr error) *Store {
	return &Store{
		dir:     dir,
		initErr: initErr,
		cache:   make(map[string]StoredAdoptionConfiguration),
	}
}

func (store *Store) List() ([]StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	return storeutil.SortedItems(store.cache, func(left, right StoredAdoptionConfiguration) bool {
		return strings.ToLower(left.Label) < strings.ToLower(right.Label)
	}), nil
}

func (store *Store) Load(label string) (StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	item, exists := store.cache[key]
	if !exists {
		return StoredAdoptionConfiguration{}, fmt.Errorf("stored adoption configuration %q: %w", label, os.ErrNotExist)
	}

	return item, nil
}

func (store *Store) Save(config StoredAdoptionConfiguration) (StoredAdoptionConfiguration, error) {
	config, err := normalizeStoredAdoptionConfiguration(config)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	path, err := storeutil.PathForStoredItem(store.dir, config.Label)
	if err != nil {
		return StoredAdoptionConfiguration{}, err
	}
	if err := storeutil.WriteStoredItem(path, "stored adoption configuration", config.Label, config); err != nil {
		return StoredAdoptionConfiguration{}, err
	}

	store.cache[config.Label] = config
	return config, nil
}

func (store *Store) Delete(label string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := storeutil.PathForStoredItem(store.dir, label)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored adoption configuration %q: %w", label, err)
	}

	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return err
	}

	delete(store.cache, key)
	return nil
}

func (store *Store) ensureLoadedLocked() error {
	if store.loaded {
		return nil
	}

	items, err := loadStoredAdoptionConfigurations(store.dir, store.initErr)
	if err != nil {
		return err
	}

	store.cache = items
	store.loaded = true
	return nil
}

func loadStoredAdoptionConfigurations(dir string, initErr error) (map[string]StoredAdoptionConfiguration, error) {
	return storeutil.LoadStoredJSONItems(
		dir,
		initErr,
		"stored adoption configuration",
		normalizeStoredAdoptionConfiguration,
		func(item StoredAdoptionConfiguration) string {
			return item.Label
		},
	)
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

	return StoredAdoptionConfiguration{
		Label:          label,
		InterfaceName:  interfaceName,
		IP:             ip.String(),
		MAC:            macText,
		DefaultGateway: common.IPString(defaultGateway),
	}, nil
}
