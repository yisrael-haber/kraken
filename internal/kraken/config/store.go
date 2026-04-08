package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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
	return &Store{
		dir:     dir,
		initErr: err,
		cache:   make(map[string]StoredAdoptionConfiguration),
	}
}

func NewStoreAtDir(dir string) *Store {
	return &Store{
		dir:   dir,
		cache: make(map[string]StoredAdoptionConfiguration),
	}
}

func (store *Store) List() ([]StoredAdoptionConfiguration, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	items := make([]StoredAdoptionConfiguration, 0, len(store.cache))
	for _, item := range store.cache {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Label) < strings.ToLower(items[j].Label)
	})

	return items, nil
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
	if err := storeutil.EnsureStoreDir(store.dir, store.initErr, "stored adoption configuration"); err != nil {
		return err
	}
	if store.loaded {
		return nil
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return fmt.Errorf("list stored adoption configurations: %w", err)
	}

	items := make(map[string]StoredAdoptionConfiguration, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := storeutil.ReadStoredItem(filepath.Join(store.dir, entry.Name()), "stored adoption configuration", normalizeStoredAdoptionConfiguration)
		if err != nil {
			return err
		}

		items[item.Label] = item
	}

	store.cache = items
	store.loaded = true
	return nil
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
