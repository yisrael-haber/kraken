package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
)

const storedScriptFolder = "scripts"

var (
	ErrStoredScriptNotFound = errors.New("stored script was not found")
	ErrStoredScriptInvalid  = errors.New("stored script is invalid")
)

type StoredScript struct {
	Name         string                 `json:"name"`
	Source       string                 `json:"source"`
	Available    bool                   `json:"available"`
	CompileError string                 `json:"compileError,omitempty"`
	UpdatedAt    string                 `json:"updatedAt,omitempty"`
	Compiled     *script.CompiledScript `json:"-"`
}

type StoredScriptSummary struct {
	Name         string `json:"name"`
	Available    bool   `json:"available"`
	CompileError string `json:"compileError,omitempty"`
	UpdatedAt    string `json:"updatedAt,omitempty"`
}

type SaveStoredScriptRequest struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type ScriptStore struct {
	mu     sync.RWMutex
	files  storedFileSet
	loaded bool
	cache  map[string]StoredScript
	list   []StoredScript
}

func NewScriptStore() *ScriptStore {
	dir, err := DefaultKrakenConfigDir(storedScriptFolder)
	return newScriptStore(dir, err)
}

func NewScriptStoreAtDir(dir string) *ScriptStore {
	return newScriptStore(dir, nil)
}

func newScriptStore(dir string, initErr error) *ScriptStore {
	return &ScriptStore{
		files: storedFileSet{
			dir:       filepath.Join(dir, "Transport"),
			initErr:   initErr,
			itemLabel: "stored script",
			extension: ".star",
		},
		cache: make(map[string]StoredScript),
	}
}

func (store *ScriptStore) List() ([]StoredScript, error) {
	store.mu.RLock()
	if store.loaded && store.list != nil {
		items := store.list
		store.mu.RUnlock()
		return items, nil
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	if store.list == nil {
		items := make([]StoredScript, 0, len(store.cache))
		for name, item := range store.cache {
			if needsStoredScriptValidation(item) {
				item = validateStoredScript(item, false)
				store.cache[name] = item
			}
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			left := items[i]
			right := items[j]
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		})
		store.list = items
	}
	return store.list, nil
}

func (store *ScriptStore) Get(name string) (StoredScript, error) {
	name, err := normalizeStoredScriptName(name)
	if err != nil {
		return StoredScript{}, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[name]
		if exists && !needsStoredScriptValidation(item) {
			store.mu.RUnlock()
			return item, nil
		}
		if !exists {
			store.mu.RUnlock()
			return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, name)
		}
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}
	item, exists := store.cache[name]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, name)
	}
	if needsStoredScriptValidation(item) {
		item = validateStoredScript(item, false)
		store.cache[name] = item
		store.list = nil
	}
	return item, nil
}

func (store *ScriptStore) Lookup(name string) (StoredScript, error) {
	name, err := normalizeStoredScriptName(name)
	if err != nil {
		return StoredScript{}, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[name]
		switch {
		case !exists:
			store.mu.RUnlock()
			return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, name)
		case needsStoredScriptValidation(item):
		case !item.Available:
			err := storedScriptInvalidError(item)
			store.mu.RUnlock()
			return StoredScript{}, err
		case item.Compiled != nil:
			store.mu.RUnlock()
			return item, nil
		}
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}
	item, exists := store.cache[name]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, name)
	}
	if needsStoredScriptValidation(item) || (item.Available && item.Compiled == nil) {
		item = validateStoredScript(item, true)
		store.cache[name] = item
		if !item.Available {
			store.list = nil
			return StoredScript{}, storedScriptInvalidError(item)
		}
	}
	if !item.Available {
		return StoredScript{}, storedScriptInvalidError(item)
	}
	return item, nil
}

func (store *ScriptStore) Save(request SaveStoredScriptRequest) (StoredScript, error) {
	item, err := NormalizeStoredScript(StoredScript{
		Name:   request.Name,
		Source: request.Source,
	})
	if err != nil {
		return StoredScript{}, err
	}
	item = validateStoredScript(item, true)

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}

	path, err := store.files.write(item.Name, []byte(item.Source))
	if err != nil {
		return StoredScript{}, err
	}

	stampStoredScriptUpdatedAt(path, &item)
	store.cache[item.Name] = item
	store.list = nil
	return item, nil
}

func (store *ScriptStore) Delete(name string) error {
	name, err := normalizeStoredScriptName(name)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	if err := store.files.delete(name, true); err != nil {
		return err
	}

	delete(store.cache, name)
	store.list = nil
	return nil
}

func (store *ScriptStore) Refresh() ([]StoredScript, error) {
	store.mu.Lock()
	store.loaded = false
	store.list = nil
	store.mu.Unlock()
	return store.List()
}

func (item StoredScript) Summary() StoredScriptSummary {
	return StoredScriptSummary{
		Name:         item.Name,
		Available:    item.Available,
		CompileError: item.CompileError,
		UpdatedAt:    item.UpdatedAt,
	}
}

func (store *ScriptStore) ensureLoadedLocked() error {
	if store.loaded {
		return nil
	}

	items, err := loadStoredScripts(store.files)
	if err != nil {
		return err
	}

	store.cache = items
	store.list = nil
	store.loaded = true
	return nil
}

func loadStoredScripts(files storedFileSet) (map[string]StoredScript, error) {
	items := make(map[string]StoredScript)
	if err := loadStoredScriptsFromDir(items, files); err != nil {
		return nil, err
	}

	return items, nil
}

func loadStoredScriptsFromDir(items map[string]StoredScript, files storedFileSet) error {
	entries, err := files.entries()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !isStoredScriptExtension(filepath.Ext(entry.Name())) {
			continue
		}

		item, err := readStoredScript(files, entry.Name())
		if err != nil {
			return err
		}
		if _, exists := items[item.Name]; exists {
			return fmt.Errorf("duplicate stored script %q", item.Name)
		}
		items[item.Name] = item
	}

	return nil
}

func readStoredScript(files storedFileSet, name string) (StoredScript, error) {
	path := filepath.Join(files.dir, name)
	payload, err := files.read(path)
	if err != nil {
		return StoredScript{}, err
	}

	label := strings.TrimSuffix(name, filepath.Ext(name))
	script, err := NormalizeStoredScript(StoredScript{
		Name:   label,
		Source: string(payload),
	})
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}
	stampStoredScriptUpdatedAt(path, &script)

	return script, nil
}

func NormalizeStoredScript(script StoredScript) (StoredScript, error) {
	if !common.ValidLabel(script.Name) {
		return StoredScript{}, fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}
	if strings.TrimSpace(script.Source) == "" {
		return StoredScript{}, fmt.Errorf("source is required")
	}

	return StoredScript{
		Name:   script.Name,
		Source: script.Source,
	}, nil
}

func normalizeStoredScriptName(name string) (string, error) {
	if !common.ValidLabel(name) {
		return "", fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}
	return name, nil
}

func validateStoredScript(item StoredScript, keepCompiled bool) StoredScript {
	compiled, compileErr := script.Compile(item.Name, item.Source)
	item.Available = compileErr == nil
	item.CompileError = ""
	item.Compiled = nil
	if compileErr != nil {
		item.CompileError = compileErr.Error()
		return item
	}
	if keepCompiled {
		item.Compiled = compiled
	}
	return item
}

func needsStoredScriptValidation(item StoredScript) bool {
	return !item.Available && item.CompileError == "" && item.Compiled == nil
}

func storedScriptInvalidError(item StoredScript) error {
	if item.CompileError == "" {
		return fmt.Errorf("%w: %q", ErrStoredScriptInvalid, item.Name)
	}
	return fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
}

func stampStoredScriptUpdatedAt(path string, script *StoredScript) {
	if modTime, err := storedFileModTime(path); err == nil {
		script.UpdatedAt = modTime.Format(time.RFC3339Nano)
	}
}

func isStoredScriptExtension(extension string) bool {
	return strings.EqualFold(extension, ".star")
}
