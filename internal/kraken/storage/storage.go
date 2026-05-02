package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type JSONStore[T any] struct {
	mu        sync.RWMutex
	dir       string
	initErr   error
	itemLabel string
	normalize func(T) (T, error)
	key       func(T) string
	sort      func(map[string]T) []T
	cache     map[string]T
	list      []T
	loaded    bool
}

func NewJSONStore[T any](
	dir string,
	initErr error,
	itemLabel string,
	normalize func(T) (T, error),
	key func(T) string,
	sortFn func(map[string]T) []T,
) *JSONStore[T] {
	return &JSONStore[T]{
		dir:       dir,
		initErr:   initErr,
		itemLabel: itemLabel,
		normalize: normalize,
		key:       key,
		sort:      sortFn,
		cache:     make(map[string]T),
	}
}

func (store *JSONStore[T]) List() ([]T, error) {
	store.mu.RLock()
	if store.loaded && store.list != nil {
		items := store.list
		store.mu.RUnlock()
		return items, nil
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	items, err := store.listLocked()
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (store *JSONStore[T]) Load(label string) (T, error) {
	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		var zero T
		return zero, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[key]
		store.mu.RUnlock()
		if exists {
			return item, nil
		}
		var zero T
		return zero, fmt.Errorf("%s %q: %w", store.itemLabel, label, os.ErrNotExist)
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		var zero T
		return zero, err
	}

	item, exists := store.cache[key]
	if exists {
		return item, nil
	}
	var zero T
	return zero, fmt.Errorf("%s %q: %w", store.itemLabel, label, os.ErrNotExist)
}

func (store *JSONStore[T]) Save(item T) (T, error) {
	normalized, err := store.normalize(item)
	if err != nil {
		var zero T
		return zero, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		var zero T
		return zero, err
	}

	name := store.key(normalized)
	path, err := PathForStoredItemWithExtension(store.dir, name, ".json")
	if err != nil {
		var zero T
		return zero, err
	}
	if err := WriteStoredItem(path, store.itemLabel, name, normalized); err != nil {
		var zero T
		return zero, err
	}

	store.cache[name] = normalized
	store.list = nil
	return normalized, nil
}

func (store *JSONStore[T]) Delete(label string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := PathForStoredItemWithExtension(store.dir, label, ".json")
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete %s %q: %w", store.itemLabel, label, err)
	}

	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return err
	}
	delete(store.cache, key)
	store.list = nil
	return nil
}

func (store *JSONStore[T]) listLocked() ([]T, error) {
	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	if store.list == nil {
		store.list = store.sort(store.cache)
	}
	return store.list, nil
}

func (store *JSONStore[T]) ensureLoadedLocked() error {
	if store.loaded {
		return nil
	}

	items, err := LoadStoredJSONItems(store.dir, store.initErr, store.itemLabel, store.normalize, store.key)
	if err != nil {
		return err
	}

	store.cache = items
	store.list = nil
	store.loaded = true
	return nil
}

func DefaultKrakenConfigRoot() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}

	return filepath.Join(baseDir, "Kraken"), nil
}

func DefaultDownloadsDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}

	downloadsDir := filepath.Join(homeDir, "Downloads")
	if stat, err := os.Stat(downloadsDir); err == nil && stat.IsDir() {
		return downloadsDir, nil
	}

	return homeDir, nil
}

func DefaultKrakenConfigDir(folder string) (string, error) {
	rootDir, err := DefaultKrakenConfigRoot()
	if err != nil {
		return "", err
	}

	return filepath.Join(rootDir, folder), nil
}

func EnsureStoreDir(dir string, initErr error, itemLabel string) error {
	if initErr != nil {
		return initErr
	}
	if dir == "" {
		return fmt.Errorf("%s directory is unavailable", itemLabel)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s directory: %w", itemLabel, err)
	}

	return nil
}

func PathForStoredItemWithExtension(dir, name, extension string) (string, error) {
	normalized, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, normalized+extension), nil
}

func ReadStoredItem[T any](path, itemLabel string, normalize func(T) (T, error)) (T, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("read %s %q: %w", itemLabel, filepath.Base(path), err)
	}

	var item T
	if err := json.Unmarshal(payload, &item); err != nil {
		var zero T
		return zero, fmt.Errorf("decode %s %q: %w", itemLabel, filepath.Base(path), err)
	}

	normalized, err := normalize(item)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("validate %s %q: %w", itemLabel, filepath.Base(path), err)
	}

	return normalized, nil
}

func WriteStoredItem[T any](path, itemLabel, name string, item T) error {
	payload, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", itemLabel, err)
	}

	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s %q: %w", itemLabel, name, err)
	}

	return nil
}

func LoadStoredJSONItems[T any](dir string, initErr error, itemLabel string, normalize func(T) (T, error), key func(T) string) (map[string]T, error) {
	if err := EnsureStoreDir(dir, initErr, itemLabel); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list %ss: %w", itemLabel, err)
	}

	items := make(map[string]T, len(entries))
	seen := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := ReadStoredItem(filepath.Join(dir, entry.Name()), itemLabel, normalize)
		if err != nil {
			return nil, err
		}

		itemKey := key(item)
		if previous, exists := seen[itemKey]; exists {
			return nil, fmt.Errorf("duplicate %s %q in %q and %q", itemLabel, itemKey, previous, entry.Name())
		}

		seen[itemKey] = entry.Name()
		items[itemKey] = item
	}

	return items, nil
}

func SortedItems[T any](items map[string]T, less func(left, right T) bool) []T {
	sorted := make([]T, 0, len(items))
	for _, item := range items {
		sorted = append(sorted, item)
	}

	sort.Slice(sorted, func(i, j int) bool {
		return less(sorted[i], sorted[j])
	})

	return sorted
}
