package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/arnodel/golua/lib/base"
	rt "github.com/arnodel/golua/runtime"
	"github.com/chzyer/readline"
	"github.com/google/gopacket/layers"
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

// ── Lua table helpers ────────────────────────────────────────────────────────

func tableGetString(tbl *rt.Table, key string) string {
	v := tbl.Get(rt.StringValue(key))
	s, _ := v.TryString()
	return s
}

// luaSubTable returns the sub-table at tbl[key], or nil if absent or not a table.
func luaSubTable(tbl *rt.Table, key string) *rt.Table {
	v := tbl.Get(rt.StringValue(key))
	if t, ok := v.TryTable(); ok {
		return t
	}
	return nil
}

// luaTableUint8 reads an integer field from a table; returns (value, true) if present.
func luaTableUint8(tbl *rt.Table, key string) (uint8, bool) {
	v := tbl.Get(rt.StringValue(key))
	if v.IsNil() {
		return 0, false
	}
	i, ok := v.TryInt()
	return uint8(i), ok
}

// luaTableUint16 reads an integer field from a table; returns (value, true) if present.
func luaTableUint16(tbl *rt.Table, key string) (uint16, bool) {
	v := tbl.Get(rt.StringValue(key))
	if v.IsNil() {
		return 0, false
	}
	i, ok := v.TryInt()
	return uint16(i), ok
}

// luaTableIP parses an IP string field; returns nil if absent or invalid.
func luaTableIP(tbl *rt.Table, key string) net.IP {
	s := tableGetString(tbl, key)
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// luaTableMAC parses a MAC string field; returns nil if absent or invalid.
func luaTableMAC(tbl *rt.Table, key string) net.HardwareAddr {
	s := tableGetString(tbl, key)
	if s == "" {
		return nil
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return mac
}

// ── Layer param parsers ──────────────────────────────────────────────────────

// parseLuaEthParams reads from an eth={...} sub-table.
func parseLuaEthParams(tbl *rt.Table) EthParams {
	var p EthParams
	ethTbl := luaSubTable(tbl, "eth")
	if ethTbl == nil {
		return p
	}
	p.Src = luaTableMAC(ethTbl, "src")
	p.Dst = luaTableMAC(ethTbl, "dst")
	return p
}

// parseLuaIPv4Params reads from an ip={...} sub-table.
func parseLuaIPv4Params(tbl *rt.Table) IPv4Params {
	var p IPv4Params
	ipTbl := luaSubTable(tbl, "ip")
	if ipTbl == nil {
		return p
	}
	p.Src = luaTableIP(ipTbl, "src")
	if v, ok := luaTableUint8(ipTbl, "ttl"); ok {
		p.TTL = v
	}
	if v, ok := luaTableUint8(ipTbl, "tos"); ok {
		p.TOS = v
	}
	if v, ok := luaTableUint16(ipTbl, "id"); ok {
		p.ID = v
	}
	if v, ok := luaTableUint16(ipTbl, "flags"); ok {
		p.Flags = layers.IPv4Flag(v)
	}
	if v, ok := luaTableUint16(ipTbl, "frag"); ok {
		p.FragOffset = v
	}
	return p
}

// parseLuaICMPv4Params reads from a parameters={...} top-level sub-table.
func parseLuaICMPv4Params(tbl *rt.Table) ICMPv4Params {
	var p ICMPv4Params
	paramsTbl := luaSubTable(tbl, "parameters")
	if paramsTbl == nil {
		return p
	}
	if icmpType, okT := luaTableUint8(paramsTbl, "type"); okT {
		code, _ := luaTableUint8(paramsTbl, "code")
		p.TypeCode = layers.CreateICMPv4TypeCode(icmpType, code)
		p.HasTypeCode = true
	}
	if v, ok := luaTableUint16(paramsTbl, "id"); ok {
		p.ID = v
		p.HasID = true
	}
	if v, ok := luaTableUint16(paramsTbl, "seq"); ok {
		p.Seq = v
		p.HasSeq = true
	}
	dataStr := tableGetString(paramsTbl, "data")
	if dataStr != "" {
		data, err := parsePayload(dataStr)
		if err == nil {
			p.Data = data
		}
	}
	return p
}

// parseLuaARPParams reads from a parameters={...} top-level sub-table.
func parseLuaARPParams(tbl *rt.Table) ARPParams {
	var p ARPParams
	paramsTbl := luaSubTable(tbl, "parameters")
	if paramsTbl == nil {
		return p
	}
	if v, ok := luaTableUint16(paramsTbl, "op"); ok {
		p.Op = v
	}
	p.SrcMAC = luaTableMAC(paramsTbl, "src_mac")
	p.DstMAC = luaTableMAC(paramsTbl, "dst_mac")
	p.SrcIP = luaTableIP(paramsTbl, "src_ip")
	p.DstIP = luaTableIP(paramsTbl, "dst_ip")
	return p
}

// ── Help system ──────────────────────────────────────────────────────────────

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
	fmt.Printf("  %-10s  %s\n", cyan("ping"), "send an ICMP echo request")
	fmt.Printf("  %-10s  %s\n", cyan("capture"), "capture packets on an interface")
	fmt.Println()
	fmt.Println(dim(`Run help("command") for detailed usage of a specific command.`))
}

func printSection(title string) { fmt.Println(bold(yellow(title))) }
func printCode(s string)        { fmt.Println("    " + cyan(s)) }
func printField(name, desc string) {
	fmt.Printf("    %-14s %s\n", green(name), desc)
}

var helpDetail = map[string]func(){
	"ping": func() {
		printSection(`ping{t="<ip>" [, options]}`)
		fmt.Println()
		fmt.Println("  Sends an ICMP echo request (ping) to the given target IP.")
		fmt.Println()
		printSection("Required:")
		printField("t", "target IP address")
		fmt.Println()
		printSection("Top-level options:")
		printField("i", "interface to use (default: first active interface)")
		fmt.Println()
		printSection("parameters={} — ICMP layer:")
		printField("type", "ICMP type   (default: 8 = echo request)")
		printField("code", "ICMP code   (default: 0)")
		printField("id", "identifier  (default: 1)")
		printField("seq", "sequence    (default: 1)")
		printField("data", `payload: raw string or 0x-prefixed hex`)
		fmt.Println()
		printSection("ip={} — IPv4 layer:")
		printField("src", "source IP   (default: interface IP)")
		printField("ttl", "TTL         (default: 64)")
		printField("tos", "TOS byte    (default: 0)")
		printField("id", "IP ID field (default: 0)")
		printField("flags", "IP flags    (default: 0)")
		printField("frag", "frag offset (default: 0)")
		fmt.Println()
		printSection("eth={} — Ethernet layer:")
		printField("src", "source MAC  (default: interface MAC)")
		printField("dst", "dest MAC    (default: ff:ff:ff:ff:ff:ff)")
		fmt.Println()
		printSection("Examples:")
		printCode(`ping{t="192.168.1.1"}`)
		printCode(`ping{t="192.168.1.1", i="eth0"}`)
		printCode(`ping{t="192.168.1.1", parameters={id=42, seq=7}}`)
		printCode(`ping{t="192.168.1.1", parameters={data="hello"}}`)
		printCode(`ping{t="192.168.1.1", parameters={data="0xdeadbeef"}}`)
		printCode(`ping{t="192.168.1.1", parameters={type=8, code=0}}`)
		printCode(`ping{t="192.168.1.1", ip={src="10.0.0.5", ttl=128}}`)
		printCode(`ping{t="192.168.1.1", eth={src="aa:bb:cc:dd:ee:ff"}}`)
	},
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
		printSection("Top-level options:")
		printField("i", "interface to use (default: first active interface)")
		fmt.Println()
		printSection("parameters={} — ARP layer:")
		printField("op", "ARP opcode    (default: 1 = request)")
		printField("src_mac", "sender MAC    (default: interface MAC)")
		printField("src_ip", "sender IP     (default: interface IP)")
		printField("dst_mac", "target MAC    (default: 00:00:00:00:00:00)")
		printField("dst_ip", "target IP     (default: t)")
		fmt.Println()
		printSection("eth={} — Ethernet layer:")
		printField("src", "source MAC    (default: interface MAC)")
		printField("dst", "dest MAC      (default: ff:ff:ff:ff:ff:ff)")
		fmt.Println()
		printSection("Examples:")
		printCode(`arp{t="192.168.1.1"}`)
		printCode(`arp{t="192.168.1.1", i="eth0"}`)
		printCode(`arp{t="192.168.1.1", parameters={src_ip="10.0.0.5"}}`)
		printCode(`arp{t="192.168.1.1", parameters={src_mac="de:ad:be:ef:00:01"}}`)
		printCode(`arp{t="192.168.1.1", eth={src="aa:bb:cc:dd:ee:ff"}}`)
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

// ── Lua command wrappers ─────────────────────────────────────────────────────

func luaDevices(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if err := cmdDevices(nil); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaARP(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var ifaceName, targetStr string
	var eth EthParams
	var arp ARPParams

	if c.NArgs() > 0 {
		tbl, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		targetStr = tableGetString(tbl, "t")
		ifaceName = tableGetString(tbl, "i")
		eth = parseLuaEthParams(tbl)
		arp = parseLuaARPParams(tbl)
	}

	if targetStr == "" {
		return nil, fmt.Errorf("arp: target IP required (t=\"<ip>\")")
	}
	dstIP := net.ParseIP(targetStr)
	if dstIP == nil {
		return nil, fmt.Errorf("arp: invalid target IP: %s", targetStr)
	}

	iface, err := resolveIface(ifaceName)
	if err != nil {
		return nil, err
	}

	fmt.Printf("sending ARP request for %s on %s\n", dstIP, iface.Name)
	if err := doARP(iface, dstIP, eth, arp); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaPing(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var ifaceName, targetStr string
	var eth EthParams
	var ip4 IPv4Params
	var icmp ICMPv4Params

	if c.NArgs() > 0 {
		tbl, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		targetStr = tableGetString(tbl, "t")
		ifaceName = tableGetString(tbl, "i")
		eth = parseLuaEthParams(tbl)
		ip4 = parseLuaIPv4Params(tbl)
		icmp = parseLuaICMPv4Params(tbl)
	}

	if targetStr == "" {
		return nil, fmt.Errorf("ping: target IP required (t=\"<ip>\")")
	}
	dstIP := net.ParseIP(targetStr)
	if dstIP == nil {
		return nil, fmt.Errorf("ping: invalid target IP: %s", targetStr)
	}

	iface, err := resolveIface(ifaceName)
	if err != nil {
		return nil, err
	}

	fmt.Printf("sending ICMP echo request to %s on %s\n", dstIP, iface.Name)
	if err := doPing(iface, dstIP, eth, ip4, icmp); err != nil {
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

// ── REPL ─────────────────────────────────────────────────────────────────────

func runShell() {
	r := rt.New(os.Stdout)
	base.Load(r)

	r.SetEnvGoFunc(r.GlobalEnv(), "devices", luaDevices, 0, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "arp", luaARP, 1, false)
	r.SetEnvGoFunc(r.GlobalEnv(), "ping", luaPing, 1, false)
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
