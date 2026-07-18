package storage

import (
	"os"
	"path/filepath"
)

func DefaultKrakenConfigRoot() (string, error) {
	baseDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(baseDir, "Kraken"), nil
}

func DefaultDownloadsDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	downloadsDir := filepath.Join(homeDir, "Downloads")
	if stat, err := os.Stat(downloadsDir); err == nil && stat.IsDir() {
		return downloadsDir, nil
	}

	return homeDir, nil
}

func CreateKrakenConfigDir(folder string) (string, error) {
	rootDir, err := DefaultKrakenConfigRoot()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(rootDir, folder)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
