package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/yisrael-haber/kraken/internal/kraken/common"
)

type storedFileSet struct {
	dir       string
	extension string
}

func (files storedFileSet) path(name string) (string, error) {
	if !common.ValidLabel(name) {
		return "", fmt.Errorf("label must contain only letters, numbers, spaces, dots, underscores, and hyphens")
	}

	return filepath.Join(files.dir, name+files.extension), nil
}

func (files storedFileSet) write(name string, payload []byte) error {
	path, err := files.path(name)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func (files storedFileSet) delete(name string) error {
	path, err := files.path(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}
