package packet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

var ErrStoredPacketOverrideNotFound = errors.New("stored packet override was not found")

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredPacketOverride
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedPacketOverrideFolder)
	return &Store{
		dir:     dir,
		initErr: err,
		cache:   make(map[string]StoredPacketOverride),
	}
}

func NewStoreAtDir(dir string) *Store {
	return &Store{
		dir:   dir,
		cache: make(map[string]StoredPacketOverride),
	}
}

func (store *Store) List() ([]StoredPacketOverride, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	items := make([]StoredPacketOverride, 0, len(store.cache))
	for _, item := range store.cache {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items, nil
}

func (store *Store) Lookup(name string) (StoredPacketOverride, error) {
	store.mu.RLock()
	loaded := store.loaded
	store.mu.RUnlock()

	if !loaded {
		store.mu.Lock()
		if err := store.ensureLoadedLocked(); err != nil {
			store.mu.Unlock()
			return StoredPacketOverride{}, err
		}
		store.mu.Unlock()
	}

	key := strings.TrimSpace(name)
	if key == "" {
		return StoredPacketOverride{}, ErrStoredPacketOverrideNotFound
	}

	store.mu.RLock()
	item, exists := store.cache[key]
	store.mu.RUnlock()
	if !exists {
		return StoredPacketOverride{}, fmt.Errorf("%w: %q", ErrStoredPacketOverrideNotFound, key)
	}

	return item, nil
}

func (store *Store) Save(override StoredPacketOverride) (StoredPacketOverride, error) {
	override, err := NormalizeStoredPacketOverride(override)
	if err != nil {
		return StoredPacketOverride{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredPacketOverride{}, err
	}

	path, err := storeutil.PathForStoredItem(store.dir, override.Name)
	if err != nil {
		return StoredPacketOverride{}, err
	}
	if err := storeutil.WriteStoredItem(path, "stored packet override", override.Name, override); err != nil {
		return StoredPacketOverride{}, err
	}

	store.cache[override.Name] = override
	return override, nil
}

func (store *Store) Delete(name string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := storeutil.PathForStoredItem(store.dir, name)
	if err != nil {
		return err
	}

	key, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored packet override %q: %w", name, err)
	}

	delete(store.cache, key)
	return nil
}

func (store *Store) ensureLoadedLocked() error {
	if err := storeutil.EnsureStoreDir(store.dir, store.initErr, "stored packet override"); err != nil {
		return err
	}
	if store.loaded {
		return nil
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return fmt.Errorf("list stored packet overrides: %w", err)
	}

	items := make(map[string]StoredPacketOverride, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := storeutil.ReadStoredItem(filepath.Join(store.dir, entry.Name()), "stored packet override", NormalizeStoredPacketOverride)
		if err != nil {
			return err
		}

		items[item.Name] = item
	}

	store.cache = items
	store.loaded = true
	return nil
}
