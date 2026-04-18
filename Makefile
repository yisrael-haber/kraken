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

.PHONY: help install test dev elf elf-debug pe pe-debug clean frontend-install

help:
	@printf '%s\n' \
		'Targets:' \
		'  make install        Install frontend dependencies' \
		'  make test           Run Go tests' \
		'  make dev            Start Wails in development mode' \
		'  make elf            Build the Linux app' \
		'  make elf-debug      Build the Linux app in debug mode' \
		'  make pe             Build the Windows exe' \
		'  make pe-debug       Build the Windows exe in debug mode' \
		'  make clean          Remove generated build artifacts'

install:
	cd $(FRONTEND_DIR) && $(NPM) install

test:
	$(GO) test -tags "$(LINUX_TAGS)" ./...

dev:
	$(WAILS) dev -tags "$(LINUX_TAGS)"

elf:
	$(WAILS) build -tags "$(LINUX_TAGS)" -platform linux/amd64

elf-debug:
	$(WAILS) build -debug -tags "$(LINUX_TAGS)" -platform linux/amd64

pe:
	$(WAILS) build -platform "$(WINDOWS_PLATFORM)"

pe-debug:
	$(WAILS) build -debug -platform "$(WINDOWS_PLATFORM)"

frontend-install: install

clean:
	rm -rf build/bin frontend/dist
