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
	if a.manager != nil {
		a.manager.SetGenericScriptOutputSink(func(event adoption.GenericScriptOutputEvent) {
			wailsruntime.EventsEmit(ctx, "kraken:generic-script-output", event)
		})
		a.manager.SetPingOutputSink(func(result operations.PingAdoptedIPAddressResult) {
			wailsruntime.EventsEmit(ctx, "kraken:ping-progress", result)
		})
	}
}

func (a *App) shutdown(context.Context) {
	if a.manager != nil {
		_ = a.manager.Close()
	}
}

func (a *App) ResetSignalHandlers() {
	wailsruntime.ResetSignalHandlers()
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

func (a *App) ExtractHiveSecrets(request offline.ExtractHiveSecretsRequest) (offline.ExtractHiveSecretsResult, error) {
	return offline.ExtractHiveSecrets(request)
}

func (a *App) ChooseFile(currentPath string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("application context is unavailable")
	}
	return wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title:            "Choose File",
		DefaultDirectory: dialogDirectory(currentPath),
	})
}

func (a *App) ChooseHiveSecretsOutput(systemPath, currentPath string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("application context is unavailable")
	}
	return wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:            "Save Hive Secrets Report",
		DefaultDirectory: dialogDirectory(currentPath),
		DefaultFilename:  offline.DefaultHiveSecretsOutputName(systemPath),
		Filters: []wailsruntime.FileFilter{{
			DisplayName: "Text Report (*.txt)",
			Pattern:     "*.txt",
		}},
	})
}

func (a *App) ChooseDirectory(currentPath string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("application context is unavailable")
	}

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
