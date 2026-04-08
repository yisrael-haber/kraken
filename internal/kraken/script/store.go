package script

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
)

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredScript
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedScriptFolder)
	return &Store{
		dir:     dir,
		initErr: err,
		cache:   make(map[string]StoredScript),
	}
}

func NewStoreAtDir(dir string) *Store {
	return &Store{
		dir:   dir,
		cache: make(map[string]StoredScript),
	}
}

func (store *Store) List() ([]StoredScriptSummary, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	items := make([]StoredScriptSummary, 0, len(store.cache))
	for _, item := range store.cache {
		items = append(items, item.summary())
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items, nil
}

func (store *Store) Get(name string) (StoredScript, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}

	key, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return StoredScript{}, err
	}

	item, exists := store.cache[key]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, key)
	}

	return cloneStoredScript(item), nil
}

func (store *Store) Lookup(name string) (StoredScript, error) {
	item, err := store.Get(name)
	if err != nil {
		return StoredScript{}, err
	}
	if item.compiled == nil || !item.Available {
		if item.CompileError == "" {
			return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptInvalid, item.Name)
		}
		return StoredScript{}, fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
	}

	return item, nil
}

func (store *Store) Save(request SaveStoredScriptRequest) (StoredScript, error) {
	script, err := normalizeStoredScript(StoredScript{
		Name:       request.Name,
		Source:     request.Source,
		EntryPoint: entryPointName,
	})
	if err != nil {
		return StoredScript{}, err
	}

	compiled, compileErr := compileStoredScript(script.Name, script.Source, false)
	script.EntryPoint = entryPointName
	script.Available = compileErr == nil
	if compileErr != nil {
		script.CompileError = compileErr.Error()
	} else {
		script.compiled = compiled
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}

	path, err := pathForStoredScript(store.dir, script.Name)
	if err != nil {
		return StoredScript{}, err
	}
	if err := os.WriteFile(path, []byte(script.Source), 0o644); err != nil {
		return StoredScript{}, fmt.Errorf("write stored script %q: %w", script.Name, err)
	}

	if stat, err := os.Stat(path); err == nil {
		script.UpdatedAt = stat.ModTime().UTC().Format(time.RFC3339Nano)
	}

	store.cache[script.Name] = script
	return cloneStoredScript(script), nil
}

func (store *Store) Delete(name string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	path, err := pathForStoredScript(store.dir, name)
	if err != nil {
		return err
	}

	key, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete stored script %q: %w", key, err)
	}

	delete(store.cache, key)
	return nil
}

func (store *Store) Refresh() ([]StoredScriptSummary, error) {
	store.mu.Lock()
	store.loaded = false
	store.mu.Unlock()
	return store.List()
}

func (store *Store) ensureLoadedLocked() error {
	if err := storeutil.EnsureStoreDir(store.dir, store.initErr, "stored script"); err != nil {
		return err
	}
	if store.loaded {
		return nil
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return fmt.Errorf("list stored scripts: %w", err)
	}

	items := make(map[string]StoredScript, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".js" {
			continue
		}

		item, err := readStoredScript(filepath.Join(store.dir, entry.Name()))
		if err != nil {
			return err
		}
		items[item.Name] = item
	}

	store.cache = items
	store.loaded = true
	return nil
}

func readStoredScript(path string) (StoredScript, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredScript{}, fmt.Errorf("read stored script %q: %w", filepath.Base(path), err)
	}

	label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	name, err := common.NormalizeAdoptionLabel(label)
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}

	script, err := normalizeStoredScript(StoredScript{
		Name:       name,
		Source:     string(payload),
		EntryPoint: entryPointName,
	})
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}

	compiled, compileErr := compileStoredScript(script.Name, script.Source, false)
	script.Available = compileErr == nil
	if compileErr != nil {
		script.CompileError = compileErr.Error()
	} else {
		script.compiled = compiled
	}

	if stat, err := os.Stat(path); err == nil {
		script.UpdatedAt = stat.ModTime().UTC().Format(time.RFC3339Nano)
	}

	return script, nil
}

func pathForStoredScript(dir, name string) (string, error) {
	normalized, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, normalized+".js"), nil
}

func normalizeStoredScript(script StoredScript) (StoredScript, error) {
	name, err := common.NormalizeAdoptionLabel(script.Name)
	if err != nil {
		return StoredScript{}, err
	}

	source := strings.TrimSpace(script.Source)
	if source == "" {
		return StoredScript{}, fmt.Errorf("source is required")
	}

	return StoredScript{
		Name:       name,
		Source:     script.Source,
		EntryPoint: entryPointName,
	}, nil
}

func cloneStoredScript(item StoredScript) StoredScript {
	cloned := item
	if item.compiled != nil {
		cloned.compiled = &compiledScript{program: item.compiled.program}
	}
	return cloned
}

func (item StoredScript) summary() StoredScriptSummary {
	return StoredScriptSummary{
		Name:         item.Name,
		EntryPoint:   item.EntryPoint,
		Available:    item.Available,
		CompileError: item.CompileError,
		UpdatedAt:    item.UpdatedAt,
	}
}

func compileStoredScript(name, source string, allowSleep bool) (*compiledScript, error) {
	program, err := goja.Compile(name, source, true)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	if err := installRuntime(vm, runtimeOptions{
		AllowSleep: allowSleep,
	}); err != nil {
		return nil, err
	}

	if _, err := vm.RunProgram(program); err != nil {
		return nil, err
	}
	if _, ok := goja.AssertFunction(vm.Get(entryPointName)); !ok {
		return nil, fmt.Errorf("%s must define a %q function", name, entryPointName)
	}

	return &compiledScript{program: program}, nil
}

func isScriptNotFound(err error) bool {
	return errors.Is(err, ErrStoredScriptNotFound)
}
