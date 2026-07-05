package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type storedFileSet struct {
	dir       string
	initErr   error
	itemLabel string
	extension string
}

func (files storedFileSet) ensureDir() error {
	if files.initErr != nil {
		return files.initErr
	}
	if files.dir == "" {
		return fmt.Errorf("%s directory is unavailable", files.itemLabel)
	}
	if err := os.MkdirAll(files.dir, 0o755); err != nil {
		return fmt.Errorf("create %s directory: %w", files.itemLabel, err)
	}

	return nil
}

func (files storedFileSet) path(name string) (string, error) {
	if !common.ValidLabel(name) {
		return "", fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	return filepath.Join(files.dir, name+files.extension), nil
}

func (files storedFileSet) entries() ([]os.DirEntry, error) {
	if err := files.ensureDir(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(files.dir)
	if err != nil {
		return nil, fmt.Errorf("list %ss: %w", files.itemLabel, err)
	}
	return entries, nil
}

func (files storedFileSet) read(path string) ([]byte, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", files.itemLabel, filepath.Base(path), err)
	}
	return payload, nil
}

func (files storedFileSet) write(name string, payload []byte) (string, error) {
	if err := files.ensureDir(); err != nil {
		return "", err
	}
	path, err := files.path(name)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", fmt.Errorf("write %s %q: %w", files.itemLabel, name, err)
	}
	return path, nil
}

func (files storedFileSet) delete(name string, ignoreMissing bool) error {
	if err := files.ensureDir(); err != nil {
		return err
	}
	path, err := files.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if ignoreMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("delete %s %q: %w", files.itemLabel, name, err)
	}
	return nil
}

func (files storedFileSet) rename(oldName, newName string) error {
	oldPath, err := files.path(oldName)
	if err != nil {
		return err
	}
	newPath, err := files.path(newName)
	if err != nil {
		return err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename %s %q to %q: %w", files.itemLabel, oldName, newName, err)
	}
	return nil
}

func storedFileModTime(path string) (time.Time, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return stat.ModTime().UTC(), nil
}
