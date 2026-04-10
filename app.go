package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

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

func (a *App) ChooseAdoptedIPAddressRecordingPath(ip string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("application context is unavailable")
	}

	defaultPath, err := backend.DefaultAdoptedIPAddressRecordingPath(ip, time.Now())
	if err != nil {
		return "", err
	}

	return wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:                "Save Packet Recording",
		DefaultDirectory:     filepath.Dir(defaultPath),
		DefaultFilename:      filepath.Base(defaultPath),
		CanCreateDirectories: true,
		Filters: []wailsruntime.FileFilter{
			{
				DisplayName: "Packet Capture (*.pcap)",
				Pattern:     "*.pcap",
			},
		},
	})
}
