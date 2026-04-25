package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	backend "github.com/yisrael-haber/kraken/internal/kraken"
)

type App struct {
	*backend.Runtime
	ctx context.Context
}

func NewApp() *App {
	return &App{Runtime: backend.NewRuntime()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(context.Context) {
	if a.Runtime != nil {
		_ = a.Runtime.Shutdown()
	}
}

func (a *App) ChooseDirectory(currentPath string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("application context is unavailable")
	}

	defaultDirectory := strings.TrimSpace(currentPath)
	if defaultDirectory != "" {
		info, err := os.Stat(defaultDirectory)
		if err == nil {
			if !info.IsDir() {
				defaultDirectory = filepath.Dir(defaultDirectory)
			}
		}
	}
	if defaultDirectory == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			defaultDirectory = home
		}
	}

	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title:            "Choose Directory",
		DefaultDirectory: defaultDirectory,
	})
}
