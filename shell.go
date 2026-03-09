package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arnodel/golua/lib/base"
	rt "github.com/arnodel/golua/runtime"
	"github.com/chzyer/readline"
)

// colorsEnabled is set once at startup by the platform-specific initColors().
var colorsEnabled = initColors()

const (
	ansiBold   = "\033[1m"
	ansiReset  = "\033[0m"
	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiDim    = "\033[2m"
)

func color(code, s string) string {
	if !colorsEnabled {
		return s
	}
	return code + s + ansiReset
}
func bold(s string) string   { return color(ansiBold, s) }
func cyan(s string) string   { return color(ansiCyan, s) }
func yellow(s string) string { return color(ansiYellow, s) }
func green(s string) string  { return color(ansiGreen, s) }
func red(s string) string    { return color(ansiRed, s) }
func dim(s string) string    { return color(ansiDim, s) }

// shellPrompt builds the readline prompt string. On Unix the prompt uses
// \001/\002 to hide ANSI bytes from readline's width calculation; on Windows
// (or when colors are off) a plain string is used.
func shellPrompt() string {
	if !colorsEnabled {
		return "moto> "
	}
	// \001 / \002 tell readline not to count the enclosed bytes as printable.
	wrap := func(code, s string) string {
		return "\001" + code + "\002" + s + "\001" + ansiReset + "\002"
	}
	return wrap(ansiCyan+ansiBold, "moto") + wrap(ansiReset, "> ")
}

// ── Runtime ──────────────────────────────────────────────────────────────────

// newRuntime creates a Lua runtime with all moto globals registered.
func newRuntime() *rt.Runtime {
	r := rt.New(os.Stdout)
	base.Load(r)
	r.SetEnvGoFunc(r.GlobalEnv(), "clear", luaClear, 0, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "devices", luaDevices, 0, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "arp", luaARP, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "ping", luaPing, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "capture", luaCapture, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "help", luaHelp, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "arpcache", luaARPCache, 0, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "arpclear", luaARPClear, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "adopt", luaAdopt, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "unadopt", luaUnadopt, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "adopted", luaAdopted, 0, false)
	return r
}

// ── Script runner ────────────────────────────────────────────────────────────

// runScript executes a Lua file inside runtime r, sharing its global namespace.
func runScript(r *rt.Runtime, path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	chunk, err := r.CompileAndLoadLuaChunk(path, src, rt.TableValue(r.GlobalEnv()))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	thread := r.MainThread()
	term := rt.NewTerminationWith(thread.CurrentCont(), 0, true)
	if err := rt.Call(thread, rt.FunctionValue(chunk), nil, term); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// makeLuaScript returns a Lua-callable that runs a script file inside r,
// sharing the same global namespace so the script's variables persist.
func makeLuaScript(r *rt.Runtime) func(*rt.Thread, *rt.GoCont) (rt.Cont, error) {
	return func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		path, err := c.StringArg(0)
		if err != nil {
			return nil, err
		}
		if err := runScript(r, path); err != nil {
			return nil, err
		}
		return c.Next(), nil
	}
}

func cmdScript(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: moto script <file.lua>")
	}
	r := newRuntime()
	r.SetEnvGoFunc(r.GlobalEnv(), "script", makeLuaScript(r), 1, false)
	return runScript(r, args[0])
}

// ── REPL ─────────────────────────────────────────────────────────────────────

func runShell() {
	r := newRuntime()
	r.SetEnvGoFunc(r.GlobalEnv(), "script", makeLuaScript(r), 1, false)

	fmt.Printf("%s — full Lua available. Type %s for commands, %s to quit.\n",
		bold(cyan("moto shell")),
		cyan("help()"),
		dim("exit"),
	)

	prompt := shellPrompt()
	rl, err := readline.New(prompt)
	if err != nil {
		fmt.Fprintln(os.Stderr, red(err.Error()))
		return
	}
	defer rl.Close()

	thread := r.MainThread()

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		// Try as expression (return <line>) first, to display results.
		var chunk *rt.Closure
		exprChunk, err := r.CompileAndLoadLuaChunk("stdin", []byte("return "+line), rt.TableValue(r.GlobalEnv()))
		if err == nil {
			chunk = exprChunk
		} else {
			stmtChunk, err2 := r.CompileAndLoadLuaChunk("stdin", []byte(line), rt.TableValue(r.GlobalEnv()))
			if err2 != nil {
				fmt.Fprintln(os.Stderr, red(err2.Error()))
				continue
			}
			chunk = stmtChunk
		}

		term := rt.NewTerminationWith(thread.CurrentCont(), 0, true)
		if err := rt.Call(thread, rt.FunctionValue(chunk), nil, term); err != nil {
			fmt.Fprintln(os.Stderr, red(err.Error()))
			continue
		}
		for _, v := range term.Etc() {
			s, _ := v.ToString()
			fmt.Println(yellow(s))
		}
	}
}
