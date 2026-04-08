package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type storedPacketOverrideStore struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredPacketOverride
}

func newStoredPacketOverrideStore() *storedPacketOverrideStore {
	dir, err := defaultKrakenConfigDir(storedPacketOverrideFolder)
	return &storedPacketOverrideStore{
		dir:     dir,
		initErr: err,
		cache:   make(map[string]StoredPacketOverride),
	}
}

func newStoredPacketOverrideStoreAtDir(dir string) *storedPacketOverrideStore {
	return &storedPacketOverrideStore{
		dir:   dir,
		cache: make(map[string]StoredPacketOverride),
	}
}

func (store *storedPacketOverrideStore) list() ([]StoredPacketOverride, error) {
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

func (store *storedPacketOverrideStore) lookup(name string) (StoredPacketOverride, bool) {
	store.mu.RLock()
	loaded := store.loaded
	store.mu.RUnlock()

	if !loaded {
		store.mu.Lock()
		if err := store.ensureLoadedLocked(); err != nil {
			store.mu.Unlock()
			return StoredPacketOverride{}, false
		}
		store.mu.Unlock()
	}

	key := strings.TrimSpace(name)
	if key == "" {
		return StoredPacketOverride{}, false
	}

	store.mu.RLock()
	item, exists := store.cache[key]
	store.mu.RUnlock()
	return item, exists
}

func (store *storedPacketOverrideStore) save(override StoredPacketOverride) (StoredPacketOverride, error) {
	override, err := normalizeStoredPacketOverride(override)
	if err != nil {
		return StoredPacketOverride{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredPacketOverride{}, err
	}

	path, err := pathForStoredItem(store.dir, override.Name)
	if err != nil {
		return StoredPacketOverride{}, err
	}
	if err := writeStoredItem(path, "stored packet override", override.Name, override); err != nil {
		return StoredPacketOverride{}, err
	}

	store.cache[override.Name] = override
	return override, nil
}

func (store *storedPacketOverrideStore) delete(name string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := pathForStoredItem(store.dir, name)
	if err != nil {
		return err
	}

	key, err := normalizeAdoptionLabel(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored packet override %q: %w", name, err)
	}

	delete(store.cache, key)
	return nil
}

func (store *storedPacketOverrideStore) ensureLoadedLocked() error {
	if err := ensureStoreDir(store.dir, store.initErr, "stored packet override"); err != nil {
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

		item, err := readStoredItem(filepath.Join(store.dir, entry.Name()), "stored packet override", normalizeStoredPacketOverride)
		if err != nil {
			return err
		}

		items[item.Name] = item
	}

	store.cache = items
	store.loaded = true
	return nil
}
