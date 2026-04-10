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

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/storeutil"
	"go.starlark.net/starlark"
)

const storedScriptCompileTimeout = time.Second

var errStoredScriptCompileTimedOut = errors.New("stored script validation timed out")

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[string]StoredScript
}

func NewStore() *Store {
	dir, err := storeutil.DefaultKrakenConfigDir(storedScriptFolder)
	return newStore(dir, err)
}

func NewStoreAtDir(dir string) *Store {
	return newStore(dir, nil)
}

func newStore(dir string, initErr error) *Store {
	return &Store{
		dir:     dir,
		initErr: initErr,
		cache:   make(map[string]StoredScript),
	}
}

func (store *Store) List() ([]StoredScriptSummary, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return nil, err
	}

	items := make(map[string]StoredScriptSummary, len(store.cache))
	for key, item := range store.cache {
		if needsStoredScriptValidation(item) {
			item = validateStoredScript(item, false)
			store.cache[key] = item
		}
		items[key] = item.summary()
	}

	return storeutil.SortedItems(items, func(left, right StoredScriptSummary) bool {
		return strings.ToLower(left.Name) < strings.ToLower(right.Name)
	}), nil
}

func (store *Store) ListNames() ([]string, error) {
	return listStoredScriptNames(store.dir, store.initErr)
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
	if needsStoredScriptValidation(item) {
		item = validateStoredScript(item, false)
		store.cache[key] = item
	}

	return cloneStoredScript(item), nil
}

func (store *Store) Lookup(name string) (StoredScript, error) {
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
	if needsStoredScriptValidation(item) {
		compiled, err := compileStoredScript(item.Name, item.Source, false)
		if err != nil {
			item.Available = false
			item.CompileError = err.Error()
			item.compiled = nil
			store.cache[key] = item
			return StoredScript{}, fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
		}
		item.Available = true
		item.CompileError = ""
		item.compiled = compiled
		store.cache[key] = item
	}
	if !item.Available {
		if item.CompileError == "" {
			return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptInvalid, item.Name)
		}
		return StoredScript{}, fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
	}
	if item.compiled == nil {
		compiled, err := compileStoredScript(item.Name, item.Source, false)
		if err != nil {
			item.Available = false
			item.CompileError = err.Error()
			item.compiled = nil
			store.cache[key] = item
			return StoredScript{}, fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
		}
		item.compiled = compiled
		store.cache[key] = item
	}

	return cloneStoredScript(item), nil
}

func (store *Store) Save(request SaveStoredScriptRequest) (StoredScript, error) {
	script, err := prepareStoredScript(StoredScript{
		Name:   request.Name,
		Source: request.Source,
	})
	if err != nil {
		return StoredScript{}, err
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
	_ = removeLegacyStoredScriptPath(store.dir, script.Name)

	stampStoredScriptUpdatedAt(path, &script)

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
	removeErr := os.Remove(path)
	legacyErr := removeLegacyStoredScriptPath(store.dir, key)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("delete stored script %q: %w", key, removeErr)
	}
	if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
		return fmt.Errorf("delete stored script %q: %w", key, legacyErr)
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
	if store.loaded {
		return nil
	}

	items, err := loadStoredScripts(store.dir, store.initErr)
	if err != nil {
		return err
	}

	store.cache = items
	store.loaded = true
	return nil
}

func loadStoredScripts(dir string, initErr error) (map[string]StoredScript, error) {
	if err := storeutil.EnsureStoreDir(dir, initErr, "stored script"); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list stored scripts: %w", err)
	}

	items := make(map[string]StoredScript, len(entries))
	extensions := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isStoredScriptExtension(filepath.Ext(entry.Name())) {
			continue
		}

		item, err := readStoredScript(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if existingExt, exists := extensions[item.Name]; exists && existingExt == ".star" && ext != ".star" {
			continue
		}
		extensions[item.Name] = ext
		items[item.Name] = item
	}

	return items, nil
}

func listStoredScriptNames(dir string, initErr error) ([]string, error) {
	if err := storeutil.EnsureStoreDir(dir, initErr, "stored script"); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list stored scripts: %w", err)
	}

	extensions := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isStoredScriptExtension(filepath.Ext(entry.Name())) {
			continue
		}

		label := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		name, err := common.NormalizeAdoptionLabel(label)
		if err != nil {
			return nil, fmt.Errorf("validate stored script %q: %w", entry.Name(), err)
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if existingExt, exists := extensions[name]; exists && existingExt == ".star" && ext != ".star" {
			continue
		}
		extensions[name] = ext
	}

	names := make([]string, 0, len(extensions))
	for name := range extensions {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool {
		return strings.ToLower(names[left]) < strings.ToLower(names[right])
	})
	return names, nil
}

func readStoredScript(path string) (StoredScript, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredScript{}, fmt.Errorf("read stored script %q: %w", filepath.Base(path), err)
	}

	label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	script, err := normalizeStoredScript(StoredScript{
		Name:   label,
		Source: string(payload),
	})
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}
	stampStoredScriptUpdatedAt(path, &script)

	return script, nil
}

func pathForStoredScript(dir, name string) (string, error) {
	return storeutil.PathForStoredItemWithExtension(dir, name, ".star")
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
		Name:   name,
		Source: script.Source,
	}, nil
}

func prepareStoredScript(script StoredScript) (StoredScript, error) {
	script, err := normalizeStoredScript(script)
	if err != nil {
		return StoredScript{}, err
	}

	return validateStoredScript(script, true), nil
}

func stampStoredScriptUpdatedAt(path string, script *StoredScript) {
	if stat, err := os.Stat(path); err == nil {
		script.UpdatedAt = stat.ModTime().UTC().Format(time.RFC3339Nano)
	}
}

func cloneStoredScript(item StoredScript) StoredScript {
	cloned := item
	if item.compiled != nil {
		cloned.compiled = &compiledScript{program: item.compiled.program}
	}
	return cloned
}

func needsStoredScriptValidation(item StoredScript) bool {
	return !item.Available && item.CompileError == "" && item.compiled == nil
}

func validateStoredScript(script StoredScript, keepCompiled bool) StoredScript {
	compiled, compileErr := compileStoredScript(script.Name, script.Source, false)
	script.Available = compileErr == nil
	script.CompileError = ""
	script.compiled = nil
	if compileErr != nil {
		script.CompileError = compileErr.Error()
		return script
	}
	if keepCompiled {
		script.compiled = compiled
	}
	return script
}

func (item StoredScript) summary() StoredScriptSummary {
	return StoredScriptSummary{
		Name:         item.Name,
		Available:    item.Available,
		CompileError: item.CompileError,
		UpdatedAt:    item.UpdatedAt,
	}
}

func compileStoredScript(name, source string, allowSleep bool) (*compiledScript, error) {
	predeclared, modules, err := buildRuntime(runtimeOptions{
		AllowSleep: allowSleep,
	})
	if err != nil {
		return nil, err
	}

	_, program, err := starlark.SourceProgramOptions(scriptFileOptions, name, source, predeclared.Has)
	if err != nil {
		return nil, err
	}

	thread := newRuntimeThread(name, modules, runtimeOptions{
		AllowSleep: allowSleep,
	})
	thread.SetMaxExecutionSteps(storedScriptCompileStepLimit)
	thread.OnMaxSteps = func(thread *starlark.Thread) {
		thread.Cancel(errStoredScriptCompileTimedOut.Error())
	}

	timer := time.AfterFunc(storedScriptCompileTimeout, func() {
		thread.Cancel(errStoredScriptCompileTimedOut.Error())
	})
	defer timer.Stop()

	globals, err := program.Init(thread, predeclared)
	if err != nil {
		if strings.Contains(err.Error(), errStoredScriptCompileTimedOut.Error()) {
			return nil, fmt.Errorf("%w after %s", errStoredScriptCompileTimedOut, storedScriptCompileTimeout)
		}
		return nil, err
	}
	if _, ok := globals[entryPointName].(starlark.Callable); !ok {
		return nil, fmt.Errorf("%s must define a %q function", name, entryPointName)
	}

	return &compiledScript{program: program}, nil
}

func isStoredScriptExtension(extension string) bool {
	switch strings.ToLower(extension) {
	case ".star", ".js":
		return true
	default:
		return false
	}
}

func removeLegacyStoredScriptPath(dir, name string) error {
	legacyPath, err := storeutil.PathForStoredItemWithExtension(dir, name, ".js")
	if err != nil {
		return err
	}
	return os.Remove(legacyPath)
}
