package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/yisrael-haber/kraken/internal/kraken/adoption"
	interfacespkg "github.com/yisrael-haber/kraken/internal/kraken/interfaces"
	"github.com/yisrael-haber/kraken/internal/kraken/offline"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type App struct {
	manager        *adoption.Manager
	configurations *storage.ConfigStore
	ctx            context.Context
}

func NewApp() (*App, error) {
	manager, err := adoption.NewManager()
	if err != nil {
		return nil, err
	}
	configurations, err := storage.NewConfigStore()
	if err != nil {
		return nil, err
	}
	return &App{manager: manager, configurations: configurations}, nil
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.manager.SetGenericScriptOutputSink(func(event adoption.GenericScriptOutputEvent) {
		wailsruntime.EventsEmit(ctx, "kraken:generic-script-output", event)
	})
}

func (a *App) shutdown(context.Context) {
	a.manager.Close()
}

func (a *App) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List(), nil
}

func (a *App) GetConfigurationDirectory() (string, error) {
	return storage.DefaultKrakenConfigRoot()
}

func (a *App) ListStoredAdoptionConfigurations() ([]storage.StoredAdoptionConfiguration, error) {
	return a.configurations.List()
}

func (a *App) SaveStoredAdoptionConfiguration(config storage.StoredAdoptionConfiguration) (storage.StoredAdoptionConfiguration, error) {
	return a.configurations.Save(config)
}

func (a *App) CopyStoredAdoptionConfiguration(label, newLabel string) (storage.StoredAdoptionConfiguration, error) {
	return a.configurations.Copy(label, newLabel)
}

func (a *App) DeleteStoredAdoptionConfiguration(label string) error {
	return a.configurations.Delete(label)
}

func (a *App) CreateKeytab(request offline.CreateKeytabRequest) (offline.CreateKeytabResult, error) {
	return offline.CreateKeytab(request)
}

func (a *App) ChooseDirectory(currentPath string) (string, error) {
	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title:            "Choose Directory",
		DefaultDirectory: dialogDirectory(currentPath),
	})
}

func dialogDirectory(currentPath string) string {
	directory := strings.TrimSpace(currentPath)
	if directory != "" {
		if info, err := os.Stat(directory); err == nil && !info.IsDir() {
			directory = filepath.Dir(directory)
		}
	}
	if directory == "" {
		if home, err := os.UserHomeDir(); err == nil {
			directory = home
		}
	}
	return directory
}
