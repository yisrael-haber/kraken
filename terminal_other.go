//go:build !windows

package main

import "os"

// initColors returns true when stdout is an interactive terminal, which on
// non-Windows platforms is sufficient for ANSI colors to work.
func initColors() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}
