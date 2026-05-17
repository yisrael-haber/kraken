package storage

import (
	"fmt"
	"os"
	"path/filepath"
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

	return filepath.Join(rootDir, folder), nil
}
