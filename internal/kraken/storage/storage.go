package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type JSONStore[T any] struct {
	mu        sync.RWMutex
	dir       string
	files     storedFileSet
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
		dir: dir,
		files: storedFileSet{
			dir:       dir,
			initErr:   initErr,
			itemLabel: itemLabel,
			extension: ".json",
		},
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
		return zero, fmt.Errorf("%s %q: %w", store.files.itemLabel, label, os.ErrNotExist)
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
	return zero, fmt.Errorf("%s %q: %w", store.files.itemLabel, label, os.ErrNotExist)
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
	if err := store.files.writeJSON(name, normalized); err != nil {
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

	key, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return err
	}
	if err := store.files.delete(key, false); err != nil {
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

	items, err := loadJSONItems(store.files, store.normalize, store.key)
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

type storedFileSet struct {
	dir       string
	initErr   error
	itemLabel string
	extension string
}

func (files storedFileSet) ensureDir() error {
	if files.initErr != nil {
		return files.initErr
	}
	if files.dir == "" {
		return fmt.Errorf("%s directory is unavailable", files.itemLabel)
	}
	if err := os.MkdirAll(files.dir, 0o755); err != nil {
		return fmt.Errorf("create %s directory: %w", files.itemLabel, err)
	}

	return nil
}

func (files storedFileSet) path(name string) (string, error) {
	normalized, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	return filepath.Join(files.dir, normalized+files.extension), nil
}

func (files storedFileSet) entries() ([]os.DirEntry, error) {
	if err := files.ensureDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(files.dir)
	if err != nil {
		return nil, fmt.Errorf("list %ss: %w", files.itemLabel, err)
	}
	return entries, nil
}

func (files storedFileSet) read(path string) ([]byte, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", files.itemLabel, filepath.Base(path), err)
	}
	return payload, nil
}

func (files storedFileSet) write(name string, payload []byte) (string, error) {
	if err := files.ensureDir(); err != nil {
		return "", err
	}
	path, err := files.path(name)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", fmt.Errorf("write %s %q: %w", files.itemLabel, name, err)
	}
	return path, nil
}

func (files storedFileSet) delete(name string, ignoreMissing bool) error {
	if err := files.ensureDir(); err != nil {
		return err
	}
	path, err := files.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if ignoreMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("delete %s %q: %w", files.itemLabel, name, err)
	}
	return nil
}

func storedFileModTime(path string) (time.Time, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return stat.ModTime().UTC(), nil
}

func readJSONItem[T any](files storedFileSet, path string, normalize func(T) (T, error)) (T, error) {
	payload, err := files.read(path)
	if err != nil {
		var zero T
		return zero, err
	}
	var item T
	if err := json.Unmarshal(payload, &item); err != nil {
		var zero T
		return zero, fmt.Errorf("decode %s %q: %w", files.itemLabel, filepath.Base(path), err)
	}

	normalized, err := normalize(item)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("validate %s %q: %w", files.itemLabel, filepath.Base(path), err)
	}

	return normalized, nil
}

func (files storedFileSet) writeJSON(name string, item any) error {
	payload, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", files.itemLabel, err)
	}
	_, err = files.write(name, append(payload, '\n'))
	return err
}

func loadJSONItems[T any](files storedFileSet, normalize func(T) (T, error), key func(T) string) (map[string]T, error) {
	entries, err := files.entries()
	if err != nil {
		return nil, err
	}

	items := make(map[string]T, len(entries))
	seen := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := readJSONItem(files, filepath.Join(files.dir, entry.Name()), normalize)
		if err != nil {
			return nil, err
		}

		itemKey := key(item)
		if previous, exists := seen[itemKey]; exists {
			return nil, fmt.Errorf("duplicate %s %q in %q and %q", files.itemLabel, itemKey, previous, entry.Name())
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
