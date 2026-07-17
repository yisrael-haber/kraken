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
	"github.com/yisrael-haber/kraken/internal/kraken/operations"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type App struct {
	manager *adoption.Manager
	ctx     context.Context
}

func NewApp() *App {
	return &App{manager: adoption.NewManager()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.manager.SetGenericScriptOutputSink(func(event adoption.GenericScriptOutputEvent) {
		wailsruntime.EventsEmit(ctx, "kraken:generic-script-output", event)
	})
	a.manager.SetPingOutputSink(func(result operations.PingAdoptedIPAddressResult) {
		wailsruntime.EventsEmit(ctx, "kraken:ping-progress", result)
	})
}

func (a *App) shutdown(context.Context) {
	_ = a.manager.Close()
}

func (a *App) ListAdoptionInterfaces() (interfacespkg.Selection, error) {
	return interfacespkg.List(), nil
}

func (a *App) GetConfigurationDirectory() (string, error) {
	return storage.DefaultKrakenConfigRoot()
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
