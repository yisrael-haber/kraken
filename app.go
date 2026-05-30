package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type App struct {
	*adoption.Manager
	ctx context.Context
}

func NewApp() *App {
	return &App{Manager: adoption.NewManager()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(context.Context) {
	if a.Manager != nil {
		_ = a.Manager.Close()
	}
}

func (a *App) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List(), nil
}

func (a *App) GetConfigurationDirectory() (string, error) {
	return storage.DefaultKrakenConfigRoot()
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
