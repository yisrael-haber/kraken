package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
	"github.com/yisrael-haber/kraken/internal/kraken/script"
)

const storedScriptFolder = "scripts"

var (
	ErrStoredScriptNotFound = errors.New("stored script was not found")
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
	files storedFileSet
	kind  script.ScriptKind
}

func NewScriptStore() *ScriptStore {
	dir, err := DefaultKrakenConfigDir(storedScriptFolder)
	return newScriptStore(dir, "Transport", script.ScriptKindTransport, err)
}

func NewGenericScriptStore() *ScriptStore {
	dir, err := DefaultKrakenConfigDir(storedScriptFolder)
	return newScriptStore(dir, "Generic", script.ScriptKindGeneric, err)
}

func newScriptStore(dir, folder string, kind script.ScriptKind, initErr error) *ScriptStore {
	return &ScriptStore{
		files: storedFileSet{
			dir:       filepath.Join(dir, folder),
			initErr:   initErr,
			itemLabel: "stored script",
			extension: ".star",
		},
		kind: kind,
	}
}

func (store *ScriptStore) List() ([]StoredScript, error) {
	entries, err := store.files.entries()
	if err != nil {
		return nil, err
	}

	items := make([]StoredScript, 0, len(entries))
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != store.files.extension {
			continue
		}
		item, err := readStoredScript(store.files, filepath.Join(store.files.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if _, exists := names[item.Name]; exists {
			return nil, fmt.Errorf("duplicate stored script %q", item.Name)
		}
		names[item.Name] = struct{}{}
		items = append(items, validateStoredScript(item, false, store.kind))
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}

func (store *ScriptStore) Get(name string) (StoredScript, error) {
	return store.load(name, false)
}

func (store *ScriptStore) Lookup(name string) (StoredScript, error) {
	item, err := store.load(name, true)
	if err != nil {
		return StoredScript{}, err
	}
	if !item.Available {
		return StoredScript{}, storedScriptInvalidError(item)
	}
	return item, nil
}

func (store *ScriptStore) Save(request SaveStoredScriptRequest) (StoredScript, error) {
	item, err := normalizeStoredScript(StoredScript{
		Name:   request.Name,
		Source: request.Source,
	})
	if err != nil {
		return StoredScript{}, err
	}
	item = validateStoredScript(item, true, store.kind)

	path, err := store.files.write(item.Name, []byte(item.Source))
	if err != nil {
		return StoredScript{}, err
	}
	if info, err := os.Stat(path); err == nil {
		item.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	return item, nil
}

func (store *ScriptStore) Delete(name string) error {
	name, err := normalizeStoredScriptName(name)
	if err != nil {
		return err
	}
	err = store.files.delete(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (item StoredScript) Summary() StoredScriptSummary {
	return StoredScriptSummary{
		Name:         item.Name,
		Available:    item.Available,
		CompileError: item.CompileError,
		UpdatedAt:    item.UpdatedAt,
	}
}

func (store *ScriptStore) load(name string, keepCompiled bool) (StoredScript, error) {
	name, err := normalizeStoredScriptName(name)
	if err != nil {
		return StoredScript{}, err
	}
	if err := store.files.ensureDir(); err != nil {
		return StoredScript{}, err
	}
	path, err := store.files.path(name)
	if err != nil {
		return StoredScript{}, err
	}
	item, err := readStoredScript(store.files, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StoredScript{}, fmt.Errorf("%w: %q", ErrStoredScriptNotFound, name)
		}
		return StoredScript{}, err
	}
	return validateStoredScript(item, keepCompiled, store.kind), nil
}

func readStoredScript(files storedFileSet, path string) (StoredScript, error) {
	payload, err := files.read(path)
	if err != nil {
		return StoredScript{}, err
	}

	item, err := normalizeStoredScript(StoredScript{
		Name:   strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Source: string(payload),
	})
	if err != nil {
		return StoredScript{}, fmt.Errorf("validate stored script %q: %w", filepath.Base(path), err)
	}
	if info, err := os.Stat(path); err == nil {
		item.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	return item, nil
}

func normalizeStoredScript(script StoredScript) (StoredScript, error) {
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

func validateStoredScript(item StoredScript, keepCompiled bool, kind script.ScriptKind) StoredScript {
	var compiled *script.CompiledScript
	var compileErr error
	switch kind {
	case script.ScriptKindGeneric:
		compiled, compileErr = script.CompileGeneric(item.Name, item.Source)
	default:
		compiled, compileErr = script.CompileTransport(item.Name, item.Source)
	}
	item.Available = compileErr == nil
	item.CompileError = ""
	item.Compiled = nil
	if compileErr != nil {
		item.CompileError = compileErr.Error()
	} else if keepCompiled {
		item.Compiled = compiled
	}
	return item
}

func storedScriptInvalidError(item StoredScript) error {
	if item.CompileError == "" {
		return fmt.Errorf("stored script %q is invalid", item.Name)
	}
	return fmt.Errorf("stored script is invalid: %s", item.CompileError)
}
