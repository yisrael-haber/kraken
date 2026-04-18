# Build Assets

This directory holds Wails packaging metadata and generated desktop build output for Kraken.

## Layout

- `bin/`
  Generated application binaries.
- `darwin/`
  macOS bundle metadata such as `Info.plist`.
- `windows/`
  Windows manifest, installer metadata, icon assets, and version files.

## Notes

- Root development workflow lives in the repository [README](../README.md).
- `main.go` embeds `frontend/dist`, so desktop builds require a built frontend bundle.
- `make clean` removes generated output from `build/bin` and `frontend/dist`.

## Common Commands

- `make dev`
  Start the Wails development app.
- `make elf`
  Build the Linux desktop binary.
- `make elf-debug`
  Build the Linux desktop binary with Wails debug output.
- `make pe`
  Build the Windows desktop binary.
- `make pe-debug`
  Build the Windows desktop binary with Wails debug output.
- `make clean`
  Remove generated output.

## Packaging Files

- `build/darwin/*`
  macOS bundle metadata.
- `build/windows/*`
  Windows manifest, icon, installer, and version metadata.
