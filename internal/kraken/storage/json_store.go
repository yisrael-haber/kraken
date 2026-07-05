package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type JSONStore[T any] struct {
	mu    sync.Mutex
	files storedFileSet
	cache map[string]T
}

func NewJSONStore[T any](dir string, initErr error, itemLabel string) *JSONStore[T] {
	return &JSONStore[T]{
		files: storedFileSet{
			dir:       dir,
			initErr:   initErr,
			itemLabel: itemLabel,
			extension: ".json",
		},
	}
}

func (store *JSONStore[T]) List() (map[string]T, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	items := make(map[string]T, len(store.cache))
	for name, item := range store.cache {
		items[name] = item
	}
	return items, nil
}

func (store *JSONStore[T]) Load(name string) (T, error) {
	var zero T

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return zero, err
	}
	item, exists := store.cache[name]
	if exists {
		return item, nil
	}
	return zero, fmt.Errorf("%s %q: %w", store.files.itemLabel, name, os.ErrNotExist)
}

func (store *JSONStore[T]) Save(name string, item T) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}
	if err := writeJSONFile(store.files, name, item); err != nil {
		return err
	}
	store.cache[name] = item
	return nil
}

func (store *JSONStore[T]) Rename(oldName, newName string, item T) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}
	oldItem, exists := store.cache[oldName]
	if !exists {
		return fmt.Errorf("%s %q: %w", store.files.itemLabel, oldName, os.ErrNotExist)
	}
	if _, exists := store.cache[newName]; exists {
		return fmt.Errorf("%s %q already exists", store.files.itemLabel, newName)
	}
	if err := writeJSONFile(store.files, oldName, item); err != nil {
		return err
	}
	if err := store.files.rename(oldName, newName); err != nil {
		_ = writeJSONFile(store.files, oldName, oldItem)
		return err
	}
	delete(store.cache, oldName)
	store.cache[newName] = item
	return nil
}

func (store *JSONStore[T]) Delete(name string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}
	if err := store.files.delete(name, false); err != nil {
		return err
	}
	delete(store.cache, name)
	return nil
}

func (store *JSONStore[T]) ensureLoadedLocked() error {
	if store.cache != nil {
		return nil
	}

	items, err := loadJSONItems[T](store.files)
	if err != nil {
		return err
	}

	store.cache = items
	return nil
}

func readJSONFile[T any](files storedFileSet, name string) (T, error) {
	path, err := files.path(name)
	if err != nil {
		var zero T
		return zero, err
	}
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
	return item, nil
}

func writeJSONFile(files storedFileSet, name string, item any) error {
	payload, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", files.itemLabel, err)
	}
	_, err = files.write(name, append(payload, '\n'))
	return err
}

func loadJSONItems[T any](files storedFileSet) (map[string]T, error) {
	entries, err := files.entries()
	if err != nil {
		return nil, err
	}

	items := make(map[string]T, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != files.extension {
			continue
		}

		name := entry.Name()[:len(entry.Name())-len(files.extension)]
		item, err := readJSONFile[T](files, name)
		if err != nil {
			return nil, err
		}
		items[name] = item
	}

	return items, nil
}
