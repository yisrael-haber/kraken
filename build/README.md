# Build Assets

This directory contains Wails packaging metadata and generated build outputs for Kraken.

## Layout

- `bin`
  Generated application binaries.
- `darwin`
  macOS-specific Wails metadata such as `Info.plist` and `Info.dev.plist`.
- `windows`
  Windows-specific packaging files such as the manifest, icon, installer metadata, and `info.json`.

## Project Notes

- Root build/test commands live in the repository [README](../README.md) and `Makefile`.
- `main.go` embeds `frontend/dist`, so frontend asset generation is part of the application build shape.
- `make clean` removes generated artifacts from `build/bin` and `frontend/dist`.

## Common Commands

- `make dev`
  Start the Wails development app.
- `make build`
  Build the Linux desktop app.
- `make build-debug`
  Build the Linux desktop app with Wails debug output.
- `make build-windows`
  Build the Windows executable.
- `make windows`
  Build the Windows executable and copy it to the configured Windows desktop path.

## Customizing Wails Packaging Files

- `build/darwin/*`
  Adjust macOS bundle metadata here if Kraken needs platform-specific branding or plist changes.
- `build/windows/*`
  Adjust Windows icon, installer, manifest, or version metadata here if packaging needs change.

If you need to restore these packaging files to Wails defaults, regenerate them through the normal Wails build flow.
