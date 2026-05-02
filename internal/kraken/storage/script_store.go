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

type Surface string

const (
	SurfaceTransport   Surface = "transport"
	SurfaceApplication Surface = "application"
)

var allScriptSurfaces = []Surface{
	SurfaceTransport,
	SurfaceApplication,
}

type StoredScript struct {
	Name         string                 `json:"name"`
	Surface      Surface                `json:"surface"`
	Source       string                 `json:"source"`
	Available    bool                   `json:"available"`
	CompileError string                 `json:"compileError,omitempty"`
	UpdatedAt    string                 `json:"updatedAt,omitempty"`
	Compiled     *script.CompiledScript `json:"-"`
}

type StoredScriptSummary struct {
	Name         string  `json:"name"`
	Surface      Surface `json:"surface"`
	Available    bool    `json:"available"`
	CompileError string  `json:"compileError,omitempty"`
	UpdatedAt    string  `json:"updatedAt,omitempty"`
}

type StoredScriptRef struct {
	Name    string  `json:"name"`
	Surface Surface `json:"surface"`
}

type SaveStoredScriptRequest struct {
	Name    string  `json:"name"`
	Surface Surface `json:"surface"`
	Source  string  `json:"source"`
}

type storedScriptKey struct {
	name    string
	surface Surface
}

type ScriptStore struct {
	mu     sync.RWMutex
	dir    string
	files  storedFileSet
	loaded bool
	cache  map[storedScriptKey]StoredScript
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
		dir: dir,
		files: storedFileSet{
			dir:       dir,
			initErr:   initErr,
			itemLabel: "stored script",
		},
		cache: make(map[storedScriptKey]StoredScript),
	}
}

func (store *ScriptStore) Dir() string {
	return store.dir
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
		for key, item := range store.cache {
			if needsStoredScriptValidation(item) {
				item = validateStoredScript(item, false)
				store.cache[key] = item
			}
			items = append(items, item)
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
	return store.list, nil
}

func (store *ScriptStore) Get(ref StoredScriptRef) (StoredScript, error) {
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

func (store *ScriptStore) Lookup(ref StoredScriptRef) (StoredScript, error) {
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
	item, exists := store.cache[key]
	if !exists {
		return StoredScript{}, fmt.Errorf("%w: %s/%q", ErrStoredScriptNotFound, key.surface, key.name)
	}
	if needsStoredScriptValidation(item) || (item.Available && item.Compiled == nil) {
		item = validateStoredScript(item, true)
		store.cache[key] = item
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
		Name:    request.Name,
		Surface: request.Surface,
		Source:  request.Source,
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

	path, err := scriptFiles(store.dir, item.Surface).write(item.Name, []byte(item.Source))
	if err != nil {
		return StoredScript{}, err
	}

	stampStoredScriptUpdatedAt(path, &item)
	store.cache[storedScriptKey{name: item.Name, surface: item.Surface}] = item
	store.list = nil
	return item, nil
}

func (store *ScriptStore) Delete(ref StoredScriptRef) error {
	key, err := normalizeStoredScriptKey(ref)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.ensureLoadedLocked(); err != nil {
		return err
	}

	if err := scriptFiles(store.dir, key.surface).delete(key.name, true); err != nil {
		return err
	}

	delete(store.cache, key)
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
		Surface:      item.Surface,
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

func loadStoredScripts(root storedFileSet) (map[storedScriptKey]StoredScript, error) {
	if err := root.ensureDir(); err != nil {
		return nil, err
	}

	items := make(map[storedScriptKey]StoredScript)
	for _, surface := range allScriptSurfaces {
		if err := loadStoredScriptsFromDir(items, scriptFiles(root.dir, surface), surface); err != nil {
			return nil, err
		}
	}

	return items, nil
}

func loadStoredScriptsFromDir(items map[storedScriptKey]StoredScript, files storedFileSet, surface Surface) error {
	entries, err := files.entries()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !isStoredScriptExtension(filepath.Ext(entry.Name())) {
			continue
		}

		item, err := readStoredScript(files, entry.Name(), surface)
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

func readStoredScript(files storedFileSet, name string, surface Surface) (StoredScript, error) {
	path := filepath.Join(files.dir, name)
	payload, err := files.read(path)
	if err != nil {
		return StoredScript{}, err
	}

	label := strings.TrimSuffix(name, filepath.Ext(name))
	script, err := NormalizeStoredScript(StoredScript{
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

func scriptFiles(dir string, surface Surface) storedFileSet {
	return storedFileSet{
		dir:       filepath.Join(dir, storedScriptSurfaceDir(surface)),
		itemLabel: "stored script",
		extension: ".star",
	}
}

func storedScriptSurfaceDir(surface Surface) string {
	if surface == SurfaceApplication {
		return "Application"
	}
	return "Transport"
}

func NormalizeStoredScript(script StoredScript) (StoredScript, error) {
	name, err := common.NormalizeAdoptionLabel(script.Name)
	if err != nil {
		return StoredScript{}, err
	}
	surface, err := NormalizeSurface(script.Surface)
	if err != nil {
		return StoredScript{}, err
	}
	if strings.TrimSpace(script.Source) == "" {
		return StoredScript{}, fmt.Errorf("source is required")
	}

	return StoredScript{
		Name:    name,
		Surface: surface,
		Source:  script.Source,
	}, nil
}

func NormalizeStoredScriptRef(ref StoredScriptRef) (StoredScriptRef, error) {
	name, err := common.NormalizeAdoptionLabel(ref.Name)
	if err != nil {
		return StoredScriptRef{}, err
	}
	surface, err := NormalizeSurface(ref.Surface)
	if err != nil {
		return StoredScriptRef{}, err
	}
	return StoredScriptRef{Name: name, Surface: surface}, nil
}

func normalizeStoredScriptKey(ref StoredScriptRef) (storedScriptKey, error) {
	normalized, err := NormalizeStoredScriptRef(ref)
	if err != nil {
		return storedScriptKey{}, err
	}
	return storedScriptKey{name: normalized.Name, surface: normalized.Surface}, nil
}

func validateStoredScript(item StoredScript, keepCompiled bool) StoredScript {
	compiled, compileErr := script.Compile(item.Name, script.Surface(item.Surface), item.Source, false)
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

func NormalizeSurface(surface Surface) (Surface, error) {
	switch Surface(strings.TrimSpace(string(surface))) {
	case "", SurfaceTransport:
		return SurfaceTransport, nil
	case SurfaceApplication:
		return SurfaceApplication, nil
	default:
		return "", fmt.Errorf("unsupported script surface %q", surface)
	}
}

func stampStoredScriptUpdatedAt(path string, script *StoredScript) {
	if modTime, err := storedFileModTime(path); err == nil {
		script.UpdatedAt = modTime.Format(time.RFC3339Nano)
	}
}

func isStoredScriptExtension(extension string) bool {
	return strings.EqualFold(extension, ".star")
}
