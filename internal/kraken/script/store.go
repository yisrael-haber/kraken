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
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
	"go.starlark.net/starlark"
)

const storedScriptCompileTimeout = time.Second

var errStoredScriptCompileTimedOut = errors.New("stored script validation timed out")

type storedScriptKey struct {
	name    string
	surface Surface
}

type Store struct {
	mu      sync.RWMutex
	dir     string
	initErr error
	loaded  bool
	cache   map[storedScriptKey]StoredScript
	list    []StoredScriptSummary
}

func NewStore() *Store {
	dir, err := storage.DefaultKrakenConfigDir(storedScriptFolder)
	return newStore(dir, err)
}

func NewStoreAtDir(dir string) *Store {
	return newStore(dir, nil)
}

func newStore(dir string, initErr error) *Store {
	return &Store{
		dir:     dir,
		initErr: initErr,
		cache:   make(map[storedScriptKey]StoredScript),
	}
}

func (store *Store) List() ([]StoredScriptSummary, error) {
	store.mu.RLock()
	if store.loaded && store.list != nil {
		items := append([]StoredScriptSummary(nil), store.list...)
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
		items := make([]StoredScriptSummary, 0, len(store.cache))
		for key, item := range store.cache {
			if needsStoredScriptValidation(item) {
				item = validateStoredScript(item, false)
				store.cache[key] = item
			}
			items = append(items, item.summary())
		}

		sort.Slice(items, func(i, j int) bool {
			left := items[i]
			right := items[j]
			if left.Surface != right.Surface {
				return left.Surface < right.Surface
			}
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		})
		store.list = items
	}

	return append([]StoredScriptSummary(nil), store.list...), nil
}

func (store *Store) Get(ref StoredScriptRef) (StoredScript, error) {
	key, err := normalizeStoredScriptKey(ref)
	if err != nil {
		return StoredScript{}, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[key]
		if exists && !needsStoredScriptValidation(item) {
			store.mu.RUnlock()
			return item, nil
		}
		if !exists {
			store.mu.RUnlock()
			return StoredScript{}, fmt.Errorf("%w: %s/%q", ErrStoredScriptNotFound, key.surface, key.name)
		}
	}
	store.mu.RUnlock()

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}

	item, exists := store.cache[key]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %s/%q", ErrStoredScriptNotFound, key.surface, key.name)
	}
	if needsStoredScriptValidation(item) {
		item = validateStoredScript(item, false)
		store.cache[key] = item
		store.list = nil
	}

	return item, nil
}

func (store *Store) Lookup(ref StoredScriptRef) (StoredScript, error) {
	key, err := normalizeStoredScriptKey(ref)
	if err != nil {
		return StoredScript{}, err
	}

	store.mu.RLock()
	if store.loaded {
		item, exists := store.cache[key]
		switch {
		case !exists:
			store.mu.RUnlock()
			return StoredScript{}, fmt.Errorf("%w: %s/%q", ErrStoredScriptNotFound, key.surface, key.name)
		case needsStoredScriptValidation(item):
		case !item.Available:
			err := storedScriptInvalidError(item)
			store.mu.RUnlock()
			return StoredScript{}, err
		case item.compiled != nil:
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

	item, exists := store.cache[key]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %s/%q", ErrStoredScriptNotFound, key.surface, key.name)
	}
	if needsStoredScriptValidation(item) || (item.Available && item.compiled == nil) {
		item, err = store.compileAndCacheStoredScriptLocked(key, item)
		if err != nil {
			return StoredScript{}, err
		}
	}
	if !item.Available {
		return StoredScript{}, storedScriptInvalidError(item)
	}

	return item, nil
}

func (store *Store) Save(request SaveStoredScriptRequest) (StoredScript, error) {
	script, err := prepareStoredScript(StoredScript{
		Name:    request.Name,
		Surface: request.Surface,
		Source:  request.Source,
	})
	if err != nil {
		return StoredScript{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return StoredScript{}, err
	}

	path, err := pathForStoredScript(store.dir, StoredScriptRef{
		Name:    script.Name,
		Surface: script.Surface,
	})
	if err != nil {
		return StoredScript{}, err
	}
	if err := os.WriteFile(path, []byte(script.Source), 0o644); err != nil {
		return StoredScript{}, fmt.Errorf("write stored script %q: %w", script.Name, err)
	}

	stampStoredScriptUpdatedAt(path, &script)
	store.cache[storedScriptKey{name: script.Name, surface: script.Surface}] = script
	store.list = nil
	return script, nil
}

func (store *Store) Delete(ref StoredScriptRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	key, err := normalizeStoredScriptKey(ref)
	if err != nil {
		return err
	}

	path, err := pathForStoredScript(store.dir, StoredScriptRef{
		Name:    key.name,
		Surface: key.surface,
	})
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete stored script %q: %w", key.name, err)
	}

	delete(store.cache, key)
	store.list = nil
	return nil
}

func (store *Store) Refresh() ([]StoredScriptSummary, error) {
	store.mu.Lock()
	store.loaded = false
	store.list = nil
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
	store.list = nil
	store.loaded = true
	return nil
}

func loadStoredScripts(dir string, initErr error) (map[storedScriptKey]StoredScript, error) {
	if err := storage.EnsureStoreDir(dir, initErr, "stored script"); err != nil {
		return nil, err
	}

	items := make(map[storedScriptKey]StoredScript)
	for _, surface := range allScriptSurfaces {
		surfaceDir := filepath.Join(dir, storedScriptSurfaceDir(surface))
		if err := os.MkdirAll(surfaceDir, 0o755); err != nil {
			return nil, fmt.Errorf("ensure stored script directory %q: %w", surfaceDir, err)
		}
		if err := loadStoredScriptsFromDir(items, surfaceDir, surface); err != nil {
			return nil, err
		}
	}

	return items, nil
}

func loadStoredScriptsFromDir(items map[storedScriptKey]StoredScript, dir string, surface Surface) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("list stored scripts: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !isStoredScriptExtension(filepath.Ext(entry.Name())) {
			continue
		}

		item, err := readStoredScript(filepath.Join(dir, entry.Name()), surface)
		if err != nil {
			return err
		}
		key := storedScriptKey{name: item.Name, surface: item.Surface}
		if _, exists := items[key]; exists {
			return fmt.Errorf("duplicate stored script %s/%q", item.Surface, item.Name)
		}
		items[key] = item
	}

	return nil
}

func readStoredScript(path string, surface Surface) (StoredScript, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return StoredScript{}, fmt.Errorf("read stored script %q: %w", filepath.Base(path), err)
	}

	label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	script, err := normalizeStoredScript(StoredScript{
		Name:    label,
		Surface: surface,
		Source:  string(payload),
	})
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}
	stampStoredScriptUpdatedAt(path, &script)

	return script, nil
}

func pathForStoredScript(dir string, ref StoredScriptRef) (string, error) {
	normalized, err := normalizeStoredScriptRef(ref)
	if err != nil {
		return "", err
	}

	scriptDir := filepath.Join(dir, storedScriptSurfaceDir(normalized.Surface))
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return "", fmt.Errorf("ensure stored script directory %q: %w", scriptDir, err)
	}
	return storage.PathForStoredItemWithExtension(scriptDir, normalized.Name, ".star")
}

func storedScriptSurfaceDir(surface Surface) string {
	switch surface {
	case SurfaceApplication:
		return "Application"
	default:
		return "Transport"
	}
}

func normalizeStoredScript(script StoredScript) (StoredScript, error) {
	name, err := common.NormalizeAdoptionLabel(script.Name)
	if err != nil {
		return StoredScript{}, err
	}
	surface, err := NormalizeSurface(script.Surface)
	if err != nil {
		return StoredScript{}, err
	}

	source := strings.TrimSpace(script.Source)
	if source == "" {
		return StoredScript{}, fmt.Errorf("source is required")
	}

	return StoredScript{
		Name:    name,
		Surface: surface,
		Source:  script.Source,
	}, nil
}

func normalizeStoredScriptRef(ref StoredScriptRef) (StoredScriptRef, error) {
	name, err := common.NormalizeAdoptionLabel(ref.Name)
	if err != nil {
		return StoredScriptRef{}, err
	}
	surface, err := NormalizeSurface(ref.Surface)
	if err != nil {
		return StoredScriptRef{}, err
	}
	return StoredScriptRef{
		Name:    name,
		Surface: surface,
	}, nil
}

func normalizeStoredScriptKey(ref StoredScriptRef) (storedScriptKey, error) {
	normalized, err := normalizeStoredScriptRef(ref)
	if err != nil {
		return storedScriptKey{}, err
	}
	return storedScriptKey{
		name:    normalized.Name,
		surface: normalized.Surface,
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

func storedScriptInvalidError(item StoredScript) error {
	if item.CompileError == "" {
		return fmt.Errorf("%w: %q", ErrStoredScriptInvalid, item.Name)
	}
	return fmt.Errorf("%w: %s", ErrStoredScriptInvalid, item.CompileError)
}

func needsStoredScriptValidation(item StoredScript) bool {
	return !item.Available && item.CompileError == "" && item.compiled == nil
}

func validateStoredScript(script StoredScript, keepCompiled bool) StoredScript {
	compiled, compileErr := compileStoredScript(script.Name, script.Surface, script.Source, false)
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

func (store *Store) compileAndCacheStoredScriptLocked(key storedScriptKey, item StoredScript) (StoredScript, error) {
	listWasLive := item.Available && item.CompileError == ""
	item = validateStoredScript(item, true)
	store.cache[key] = item
	if !listWasLive || !item.Available {
		store.list = nil
	}
	if !item.Available {
		return StoredScript{}, storedScriptInvalidError(item)
	}

	return item, nil
}

func (item StoredScript) summary() StoredScriptSummary {
	return StoredScriptSummary{
		Name:         item.Name,
		Surface:      item.Surface,
		Available:    item.Available,
		CompileError: item.CompileError,
		UpdatedAt:    item.UpdatedAt,
	}
}

func compileStoredScript(name string, surface Surface, source string, allowSleep bool) (*compiledScript, error) {
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
	if err := validateCompiledScriptSurface(name, surface, globals); err != nil {
		return nil, err
	}

	return &compiledScript{program: program}, nil
}

func validateCompiledScriptSurface(name string, surface Surface, globals starlark.StringDict) error {
	switch surface {
	case SurfaceTransport, SurfaceApplication:
		if _, ok := globals[entryPointName].(starlark.Callable); !ok {
			return fmt.Errorf("%s must define a %q function", name, entryPointName)
		}
	default:
		return fmt.Errorf("unsupported script surface %q", surface)
	}

	return nil
}

func isStoredScriptExtension(extension string) bool {
	return strings.EqualFold(extension, ".star")
}
