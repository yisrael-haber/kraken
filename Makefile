APP_NAME ?= kraken
FRONTEND_DIR ?= frontend
GO ?= go
NPM ?= npm
WAILS ?= wails

LINUX_TAGS ?= webkit2_41
WINDOWS_PLATFORM ?= windows/amd64
WINDOWS_EXE ?= build/bin/$(APP_NAME).exe

WIN_USER ?= yisra
WIN_DESKTOP ?= /mnt/c/Users/$(WIN_USER)/Desktop

.DEFAULT_GOAL := help

.PHONY: help install test dev build build-debug build-windows windows clean \
	frontend-install test-go copy-windows-desktop build-windows-desktop

help:
	@printf '%s\n' \
		'Targets:' \
		'  make install        Install frontend dependencies' \
		'  make test           Run Go tests' \
		'  make dev            Start Wails in development mode' \
		'  make build          Build the Linux app' \
		'  make build-debug    Build the Linux app in debug mode' \
		'  make build-windows  Build the Windows exe' \
		'  make windows        Build the Windows exe and copy it to the Windows Desktop' \
		'  make clean          Remove generated build artifacts'

install:
	cd $(FRONTEND_DIR) && $(NPM) install

test:
	$(GO) test -tags "$(LINUX_TAGS)" ./...

dev:
	$(WAILS) dev -tags "$(LINUX_TAGS)"

build:
	$(WAILS) build -tags "$(LINUX_TAGS)"

build-debug:
	$(WAILS) build -debug -tags "$(LINUX_TAGS)"

build-windows:
	$(WAILS) build -platform "$(WINDOWS_PLATFORM)"

copy-windows-desktop:
	@test -f "$(WINDOWS_EXE)" || (echo "Missing Windows build at $(WINDOWS_EXE). Run 'make build-windows' first." >&2; exit 1)
	@test -d "$(WIN_DESKTOP)" || (echo "Windows desktop not found at $(WIN_DESKTOP). Override with WIN_DESKTOP=... or WIN_USER=..." >&2; exit 1)
	@rm -f "$(WIN_DESKTOP)/$(APP_NAME).exe"
	cp "$(WINDOWS_EXE)" "$(WIN_DESKTOP)/$(APP_NAME).exe"
	@echo "✓ Windows build copied to $(WIN_DESKTOP)/kraken.exe"

windows: build-windows copy-windows-desktop

frontend-install: install

test-go: test

build-windows-desktop: windows

clean:
	rm -rf build/bin frontend/dist
