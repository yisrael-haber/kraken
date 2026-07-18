package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

const storedScriptFolder = "scripts"

type StoredScript struct {
	Name         string `json:"name"`
	Source       string `json:"source"`
	Available    bool   `json:"available"`
	CompileError string `json:"compileError,omitempty"`
}

type ScriptStore struct {
	files storedFileSet
}

func NewScriptStore(folder string) (*ScriptStore, error) {
	dir, err := CreateKrakenConfigDir(filepath.Join(storedScriptFolder, folder))
	if err != nil {
		return nil, err
	}
	return &ScriptStore{
		files: storedFileSet{
			dir:       dir,
			extension: ".star",
		},
	}, nil
}

func (store *ScriptStore) List() ([]StoredScript, error) {
	entries, err := os.ReadDir(store.files.dir)
	if err != nil {
		return nil, err
	}

	items := make([]StoredScript, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != store.files.extension {
			continue
		}
		item, err := readStoredScript(filepath.Join(store.files.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

func (store *ScriptStore) Get(name string) (StoredScript, error) {
	path, err := store.files.path(name)
	if err != nil {
		return StoredScript{}, err
	}
	return readStoredScript(path)
}

func (store *ScriptStore) Save(item StoredScript) (StoredScript, error) {
	item, err := normalizeStoredScript(item)
	if err != nil {
		return StoredScript{}, err
	}
	if err := store.files.write(item.Name, []byte(item.Source)); err != nil {
		return StoredScript{}, err
	}
	return item, nil
}

func (store *ScriptStore) Delete(name string) error {
	return store.files.delete(name)
}

func readStoredScript(path string) (StoredScript, error) {
	payload, err := os.ReadFile(path)
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
	return item, nil
}

func normalizeStoredScript(script StoredScript) (StoredScript, error) {
	if !common.ValidLabel(script.Name) {
		return StoredScript{}, fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}
	if strings.TrimSpace(script.Source) == "" {
		return StoredScript{}, fmt.Errorf("source is required")
	}

	return script, nil
}
