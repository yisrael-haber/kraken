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

func tableGetString(tbl *rt.Table, key string) string {
	v := tbl.Get(rt.StringValue(key))
	s, _ := v.TryString()
	return s
}

func luaHelp(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		printHelpSummary()
		return c.Next(), nil
	}
	name, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	fn, ok := helpDetail[name]
	if !ok {
		fmt.Fprintf(os.Stderr, red("unknown command %q")+" — run help() for the list of commands\n", name)
		return c.Next(), nil
	}
	fn()
	return c.Next(), nil
}

func printHelpSummary() {
	fmt.Println(bold("Commands:"))
	fmt.Printf("  %-10s  %s\n", cyan("devices"), "list active network interfaces")
	fmt.Printf("  %-10s  %s\n", cyan("arp"), "send an ARP request")
	fmt.Printf("  %-10s  %s\n", cyan("capture"), "capture packets on an interface")
	fmt.Println()
	fmt.Println(dim(`Run help("command") for detailed usage of a specific command.`))
}

func printSection(title string) { fmt.Println(bold(yellow(title))) }
func printCode(s string)        { fmt.Println("    " + cyan(s)) }
func printField(name, desc string) {
	fmt.Printf("    %-12s %s\n", green(name), desc)
}

var helpDetail = map[string]func(){
	"devices": func() {
		printSection("devices()")
		fmt.Println()
		fmt.Println("  Lists all active network interfaces.")
		fmt.Println()
		printSection("Example:")
		printCode("devices()")
	},
	"arp": func() {
		printSection(`arp{t="<ip>" [, options]}`)
		fmt.Println()
		fmt.Println("  Sends an ARP request for the given target IP.")
		fmt.Println()
		printSection("Required:")
		printField("t", "target IP address")
		fmt.Println()
		printSection("Options:")
		printField("i", "interface to use (default: first active interface)")
		printField("src-ip", "source IP to use  (default: interface IP)")
		printField("src-mac", "source MAC to use (default: interface MAC) — may be blocked by NIC driver on Windows")
		fmt.Println()
		printSection("Examples:")
		printCode(`arp{t="192.168.1.1"}`)
		printCode(`arp{t="192.168.1.1", i="eth0"}`)
		printCode(`arp{t="192.168.1.1", ["src-ip"]="10.0.0.5"}`)
		printCode(`arp{t="192.168.1.1", ["src-mac"]="de:ad:be:ef:00:01"}`)
	},
	"capture": func() {
		printSection("capture([{options}])")
		fmt.Println()
		fmt.Println("  Captures and prints packets on a network interface.")
		fmt.Println()
		printSection("Options:")
		printField("i", "interface to capture on (default: first active interface)")
		fmt.Println()
		printSection("Examples:")
		printCode("capture()")
		printCode(`capture{i="eth0"}`)
	},
}

func luaDevices(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if err := cmdDevices(nil); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaARP(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var args []string
	if c.NArgs() > 0 {
		tbl, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		if v := tableGetString(tbl, "t"); v != "" {
			args = append(args, "-t", v)
		}
		if v := tableGetString(tbl, "i"); v != "" {
			args = append(args, "-i", v)
		}
		if v := tableGetString(tbl, "src-ip"); v != "" {
			args = append(args, "-src-ip", v)
		}
		if v := tableGetString(tbl, "src-mac"); v != "" {
			args = append(args, "-src-mac", v)
		}
	}
	if err := cmdARP(args); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaCapture(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var args []string
	if c.NArgs() > 0 {
		tbl, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		if v := tableGetString(tbl, "i"); v != "" {
			args = append(args, "-i", v)
		}
	}
	if err := cmdCapture(args); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func runShell() {
	r := rt.New(os.Stdout)
	base.Load(r)

	r.SetEnvGoFunc(r.GlobalEnv(), "devices", luaDevices, 0, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "arp", luaARP, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "capture", luaCapture, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "help", luaHelp, 1, false)

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
