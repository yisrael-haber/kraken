package storeutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

func DefaultKrakenConfigRoot() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}

	return filepath.Join(baseDir, "Kraken"), nil
}

func DefaultKrakenConfigDir(folder string) (string, error) {
	rootDir, err := DefaultKrakenConfigRoot()
	if err != nil {
		return "", err
	}

	if folder == "" {
		return rootDir, nil
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

func PathForStoredItem(dir, name string) (string, error) {
	normalized, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, normalized+".json"), nil
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
