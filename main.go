package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		runShell()
		return
	}

	subcommands := map[string]func([]string) error{
		"devices": cmdDevices,
		"arp":     cmdARP,
		"capture": cmdCapture,
		"script":  cmdScript,
	}

	cmd, ok := subcommands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		os.Exit(1)
	}

	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
