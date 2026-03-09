//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// initColors tries to enable ANSI Virtual Terminal Processing on the Windows
// console. Returns true if it succeeded (Windows 10 v1511+), false otherwise
// (older Windows — colors will be suppressed).
func initColors() bool {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
