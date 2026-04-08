package main

import (
	"encoding/json"
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
	dir, err := defaultStoredPacketOverrideDir()
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

func defaultStoredPacketOverrideDir() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}

	return filepath.Join(baseDir, "Kraken", storedPacketOverrideFolder), nil
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
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredPacketOverride{}, false
	}

	key, err := normalizeAdoptionLabel(name)
	if err != nil {
		return StoredPacketOverride{}, false
	}

	item, exists := store.cache[key]
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

	path, err := store.pathForNameLocked(override.Name)
	if err != nil {
		return StoredPacketOverride{}, err
	}

	payload, err := json.MarshalIndent(override, "", "  ")
	if err != nil {
		return StoredPacketOverride{}, fmt.Errorf("encode stored packet override: %w", err)
	}

	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return StoredPacketOverride{}, fmt.Errorf("write stored packet override %q: %w", override.Name, err)
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

	path, err := store.pathForNameLocked(name)
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
	if err := store.ensureReadyLocked(); err != nil {
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

		item, err := store.readOverrideLocked(filepath.Join(store.dir, entry.Name()))
		if err != nil {
			return err
		}

		items[item.Name] = item
	}

	store.cache = items
	store.loaded = true
	return nil
}

func (store *storedPacketOverrideStore) ensureReadyLocked() error {
	if store.initErr != nil {
		return store.initErr
	}
	if store.dir == "" {
		return fmt.Errorf("stored packet override directory is unavailable")
	}
	if err := os.MkdirAll(store.dir, 0o755); err != nil {
		return fmt.Errorf("create stored packet override directory: %w", err)
	}

	return nil
}

func (store *storedPacketOverrideStore) pathForNameLocked(name string) (string, error) {
	normalized, err := normalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	return filepath.Join(store.dir, normalized+".json"), nil
}

func (store *storedPacketOverrideStore) readOverrideLocked(path string) (StoredPacketOverride, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredPacketOverride{}, fmt.Errorf("read stored packet override %q: %w", filepath.Base(path), err)
	}

	var override StoredPacketOverride
	if err := json.Unmarshal(payload, &override); err != nil {
		return StoredPacketOverride{}, fmt.Errorf("decode stored packet override %q: %w", filepath.Base(path), err)
	}

	normalized, err := normalizeStoredPacketOverride(override)
	if err != nil {
		return StoredPacketOverride{}, fmt.Errorf("validate stored packet override %q: %w", filepath.Base(path), err)
	}

	return normalized, nil
}
