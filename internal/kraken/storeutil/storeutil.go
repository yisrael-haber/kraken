package storeutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

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
	return PathForStoredItemWithExtension(dir, name, ".json")
}

func PathForStoredItemWithExtension(dir, name, extension string) (string, error) {
	normalized, err := common.NormalizeAdoptionLabel(name)
	if err != nil {
		return "", err
	}

	extension = strings.TrimSpace(extension)
	if extension == "" || extension == "." {
		return "", fmt.Errorf("file extension is required")
	}
	if !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}

	return filepath.Join(dir, normalized+extension), nil
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

func LoadStoredJSONItems[T any](dir string, initErr error, itemLabel string, normalize func(T) (T, error), key func(T) string) (map[string]T, error) {
	if err := EnsureStoreDir(dir, initErr, itemLabel); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list %ss: %w", itemLabel, err)
	}

	items := make(map[string]T, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		item, err := ReadStoredItem(filepath.Join(dir, entry.Name()), itemLabel, normalize)
		if err != nil {
			return nil, err
		}

		items[key(item)] = item
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
