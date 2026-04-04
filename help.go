package main

import (
	"fmt"
	"os"

	rt "github.com/arnodel/golua/runtime"
)

// commandDef is the single source of truth for a Lua command: its Lua name,
// the Go function to register, the minimum declared arg count, the help
// summary shown by help(), and the detail function shown by help("name").
// group controls which section of help() the command appears under;
// an empty group means the command is registered but not listed.
type commandDef struct {
	name    string
	fn      func(*rt.Thread, *rt.GoCont) (rt.Cont, error)
	nArgs   int
	group   string
	summary string
	detail  func()
}

// commands is the authoritative list of all registered Lua commands.
// Adding a new command here automatically registers it in the shell and
// includes it in help output — no other files need to change.
//
// The "script" command is intentionally absent: it needs a closure over the
// runtime instance and is registered separately in newRuntime().
var commands = []commandDef{
	{
		name: "devices", fn: luaDevices, nArgs: 0,
		group:   "Commands",
		summary: "list active network interfaces",
		detail:  helpDevices,
	},
	{
		name: "arp", fn: luaARP, nArgs: 1,
		group:   "Commands",
		summary: "send an ARP request",
		detail:  helpARP,
	},
	{
		name: "ping", fn: luaPing, nArgs: 1,
		group:   "Commands",
		summary: "send ICMP echo requests from an adopted IP",
		detail:  helpPing,
	},
	{
		name: "capture", fn: luaCapture, nArgs: 1,
		group:   "Commands",
		summary: "capture packets on an interface",
		detail:  helpCapture,
	},
	{
		name: "arpcache", fn: luaARPCache, nArgs: 0,
		group:   "Commands",
		summary: "show the ARP cache",
		detail:  helpARPCache,
	},
	{
		name: "arpclear", fn: luaARPClear, nArgs: 1,
		group:   "Commands",
		summary: "clear ARP cache entries",
		detail:  helpARPClear,
	},
	{
		name: "adopt", fn: luaAdopt, nArgs: 1,
		group:   "Commands",
		summary: "respond to ARP and ICMP for an IP not bound to the interface",
		detail:  helpAdopt,
	},
	{
		name: "unadopt", fn: luaUnadopt, nArgs: 1,
		group:   "Commands",
		summary: "stop responding for an adopted IP",
		detail:  helpUnadopt,
	},
	{
		name: "adopted", fn: luaAdopted, nArgs: 0,
		group:   "Commands",
		summary: "list currently adopted IP addresses",
		detail:  helpAdopted,
	},
	{
		name: "listen", fn: luaListen, nArgs: 1,
		group:   "Commands",
		summary: "accept TCP connections on an adopted IP and port",
		detail:  helpListen,
	},
	{
		name: "dial", fn: luaDial, nArgs: 1,
		group:   "Commands",
		summary: "open an outbound TCP connection from an adopted IP",
		detail:  helpDial,
	},
	{
		name: "setmod", fn: luaSetMod, nArgs: 1,
		group:   "Commands",
		summary: "set outbound header overrides for an adopted IP",
		detail:  helpSetMod,
	},
	{
		name: "connlog", fn: luaConnLog, nArgs: 0,
		group:   "Commands",
		summary: "show the TCP connection log",
		detail:  helpConnLog,
	},
	{
		name: "connlogclear", fn: luaConnLogClear, nArgs: 0,
		group:   "Commands",
		summary: "clear the TCP connection log",
		detail:  helpConnLogClear,
	},
	{
		name: "swap", fn: luaSwap, nArgs: 1,
		group:   "Commands",
		summary: "MITM a TCP session between a client and server",
		detail:  helpSwap,
	},
	{
		name: "clear", fn: luaClear, nArgs: 0,
		group:   "Commands",
		summary: "clear the terminal screen",
		detail:  helpClear,
	},
}

// ── Help command ─────────────────────────────────────────────────────────────

func luaHelp(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		printHelpSummary()
		return c.Next(), nil
	}
	name, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	for _, cmd := range commands {
		if cmd.name == name {
			if cmd.detail != nil {
				cmd.detail()
			}
			return c.Next(), nil
		}
	}
	fmt.Fprintf(os.Stderr, red("unknown command %q")+" — run help() for the list of commands\n", name)
	return c.Next(), nil
}

func printHelpSummary() {
	// Emit groups in the order they first appear in commands.
	var groupOrder []string
	groupCmds := map[string][]commandDef{}
	seen := map[string]bool{}
	for _, cmd := range commands {
		if cmd.group == "" {
			continue
		}
		if !seen[cmd.group] {
			groupOrder = append(groupOrder, cmd.group)
			seen[cmd.group] = true
		}
		groupCmds[cmd.group] = append(groupCmds[cmd.group], cmd)
	}
	for _, g := range groupOrder {
		fmt.Println(bold(g + ":"))
		for _, cmd := range groupCmds[g] {
			fmt.Printf("  %-14s  %s\n", cyan(cmd.name), cmd.summary)
		}
		fmt.Println()
	}
	fmt.Println(dim(`Run help("command") for detailed usage of a specific command.`))
}

// ── Formatting helpers ────────────────────────────────────────────────────────

func printSection(title string) { fmt.Println(bold(yellow(title))) }
func printCode(s string)        { fmt.Println("    " + cyan(s)) }
func printField(name, desc string) {
	fmt.Printf("    %-14s %s\n", green(name), desc)
}

// ── Detail functions ─────────────────────────────────────────────────────────

func helpDevices() {
	printSection("devices()")
	fmt.Println()
	fmt.Println("  Lists all active network interfaces.")
	fmt.Println()
	printSection("Example:")
	printCode("devices()")
}

func helpARP() {
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
}

func helpPing() {
	printSection(`ping{ip="<adopted-ip>", t="<target-ip>" [, options]}`)
	fmt.Println()
	fmt.Println("  Sends ICMP echo requests from an adopted IP to a target and prints RTT.")
	fmt.Println("  The source IP must already be adopted. Destination MAC is resolved via ARP.")
	fmt.Println("  Packets are sent with the adopted IP and MAC as the source.")
	fmt.Println()
	printSection("Required:")
	printField("ip", "adopted source IP address")
	printField("t", "target IP address")
	fmt.Println()
	printSection("Options:")
	printField("count", "number of echo requests (default: 20)")
	printField("id", "ICMP identifier (default: 1)")
	fmt.Println()
	printSection("Examples:")
	printCode(`adopt{ip="192.168.1.100"}`)
	printCode(`ping{ip="192.168.1.100", t="192.168.1.1"}`)
	printCode(`ping{ip="192.168.1.100", t="192.168.1.1", count=5}`)
	printCode(`ping{ip="192.168.1.100", t="192.168.1.1", id=42}`)
}

func helpCapture() {
	printSection("capture([{options}])")
	fmt.Println()
	fmt.Println("  Captures packets on a network interface.")
	fmt.Println("  Without file=, prints a one-line summary per packet to stdout.")
	fmt.Println("  With file=, writes raw packets to a pcapng file (timestamp added to name).")
	fmt.Println("  Runs until interrupted (Ctrl+C).")
	fmt.Println()
	printSection("Options:")
	printField("i", "interface to capture on (default: first active interface)")
	printField("file", "write to a pcapng file instead of printing to stdout")
	fmt.Println()
	printSection("Examples:")
	printCode("capture()")
	printCode(`capture{i="eth0"}`)
	printCode(`capture{i="eth0", file="traffic.pcapng"}`)
}

func helpARPCache() {
	printSection("arpcache()")
	fmt.Println()
	fmt.Println("  Displays all entries in the ARP cache.")
	fmt.Println("  Entries expire after 5 minutes; a new ARP request is issued on next use.")
	fmt.Println("  The cache is populated automatically when sending packets (e.g. ping)")
	fmt.Println("  and persists for the lifetime of the process.")
	fmt.Println()
	printSection("Example:")
	printCode("arpcache()")
}

func helpARPClear() {
	printSection(`arpclear()  /  arpclear("<ip>")`)
	fmt.Println()
	fmt.Println("  Removes entries from the ARP cache.")
	fmt.Println("  Called with no arguments, clears the entire cache.")
	fmt.Println("  Called with an IP string, removes only that entry.")
	fmt.Println()
	printSection("Examples:")
	printCode("arpclear()")
	printCode(`arpclear("192.168.1.1")`)
}

func helpAdopt() {
	printSection(`adopt{ip="<ip>" [, options]}`)
	fmt.Println()
	fmt.Println("  Responds to ARP requests and ICMP echo requests for an IP address")
	fmt.Println("  that is not bound to the interface. A background listener handles replies.")
	fmt.Println()
	printSection("Required:")
	printField("ip", "IP address to adopt")
	fmt.Println()
	printSection("Options:")
	printField("mac", "MAC to advertise (default: interface MAC)")
	printField("i", "interface to listen on (default: first active)")
	printField("capture", "pcapng capture filename (default: session.pcapng; timestamp always added)")
	fmt.Println()
	printSection("Examples:")
	printCode(`adopt{ip="192.168.1.100"}`)
	printCode(`adopt{ip="192.168.1.100", i="eth0"}`)
	printCode(`adopt{ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}`)
	printCode(`adopt{ip="192.168.1.100", capture="traffic.pcapng"}`)
}

func helpUnadopt() {
	printSection(`unadopt("<ip>")`)
	fmt.Println()
	fmt.Println("  Stops responding for the given adopted IP.")
	fmt.Println("  The interface listener shuts down automatically when no IPs remain on it.")
	fmt.Println()
	printSection("Example:")
	printCode(`unadopt("192.168.1.100")`)
}

func helpAdopted() {
	printSection("adopted()")
	fmt.Println()
	fmt.Println("  Lists all currently adopted IP addresses, their advertised MAC, and interface.")
	fmt.Println()
	printSection("Example:")
	printCode("adopted()")
}

func helpDial() {
	printSection(`dial{ip="<adopted-ip>", t="<target-ip>", port=<port>}`)
	fmt.Println()
	fmt.Println("  Opens an outbound TCP connection from an adopted IP to a remote host.")
	fmt.Println("  Blocks until connected, then reads up to 4096 bytes (3s deadline)")
	fmt.Println("  and prints whatever the remote sends (banner grab).")
	fmt.Println("  The adopted IP must already be registered with adopt{...}.")
	fmt.Println()
	printSection("Required:")
	printField("ip", "adopted source IP address")
	printField("t", "target (destination) IP address")
	printField("port", "destination TCP port")
	fmt.Println()
	printSection("Examples:")
	printCode(`adopt{ip="192.168.1.100"}`)
	printCode(`dial{ip="192.168.1.100", t="192.168.1.1", port=80}`)
	printCode(`dial{ip="192.168.1.100", t="192.168.1.1", port=22}`)
}

func helpListen() {
	printSection(`listen{ip="<ip>", port=<port> [, options]}`)
	fmt.Println()
	fmt.Println("  Accepts TCP connections on the given port for an adopted IP.")
	fmt.Println("  The IP must already be adopted. The gVisor TCP stack handles")
	fmt.Println("  the handshake; connections are recorded in the connection log.")
	fmt.Println("  Registering a second handler on the same port replaces the first.")
	fmt.Println()
	printSection("Required:")
	printField("ip", "adopted IP address to listen on")
	printField("port", "TCP port number")
	fmt.Println()
	printSection("Options:")
	printField("echo", "echo received data back to the sender (default: false)")
	fmt.Println()
	printSection("Examples:")
	printCode(`adopt{ip="192.168.1.100"}`)
	printCode(`listen{ip="192.168.1.100", port=80}`)
	printCode(`listen{ip="192.168.1.100", port=8080, echo=true}`)
}

func helpConnLog() {
	printSection("connlog()")
	fmt.Println()
	fmt.Println("  Displays the TCP connection log for all adopted IPs.")
	fmt.Println("  Shows local address, remote address, bytes received/sent, status, and time.")
	fmt.Println("  Connections are recorded automatically when using adopt{...}.")
	fmt.Println()
	printSection("Example:")
	printCode("connlog()")
}

func helpConnLogClear() {
	printSection("connlogclear()")
	fmt.Println()
	fmt.Println("  Clears all entries from the TCP connection log.")
	fmt.Println()
	printSection("Example:")
	printCode("connlogclear()")
}

func helpSetMod() {
	printSection(`setmod{ip="<adopted-ip>" [, eth={...}] [, l3={...}] [, l4={...}]}`)
	fmt.Println()
	fmt.Println("  Sets persistent outbound header overrides for all packets sent from an adopted IP.")
	fmt.Println("  Only the fields you specify are overridden; omitted fields use the stack's values.")
	fmt.Println("  Calling with just ip= clears all overrides.")
	fmt.Println()
	printSection("Required:")
	printField("ip", "adopted IP address to configure")
	fmt.Println()
	printSection("eth={} — Ethernet layer:")
	printField("src", "source MAC address")
	printField("dst", "destination MAC (bypasses ARP lookup)")
	fmt.Println()
	printSection("l3={} — IPv4 layer:")
	printField("src", "source IP address")
	printField("dst", "destination IP address")
	printField("ttl", "time-to-live (0–255)")
	printField("tos", "type of service / DSCP byte (0–255)")
	fmt.Println()
	printSection("l4={} — TCP layer:")
	printField("src_port", "source TCP port")
	printField("dst_port", "destination TCP port")
	printField("window", "TCP receive window size")
	fmt.Println()
	printSection("Examples:")
	printCode(`adopt{ip="192.168.1.100"}`)
	printCode(`setmod{ip="192.168.1.100", l3={src="10.0.0.1", ttl=128}}`)
	printCode(`setmod{ip="192.168.1.100", eth={src="aa:bb:cc:dd:ee:ff"}, l4={src_port=4444}}`)
	printCode(`setmod{ip="192.168.1.100"}`)
}

func helpClear() {
	printSection("clear()")
	fmt.Println()
	fmt.Println("  Clears the terminal screen. Works on Linux, macOS, and Windows.")
	fmt.Println()
	printSection("Example:")
	printCode("clear()")
}

func helpSwap() {
	printSection(`swap{client="<ip>", server="<ip>", port=<port> [, i="<iface>"]}`)
	fmt.Println()
	fmt.Println("  Intercepts TCP traffic between a specific client and server port,")
	fmt.Println("  acting as a transparent MITM. Traffic retains its original 3-tuple")
	fmt.Println("  on the wire — the client sees the server's IP/port and vice versa.")
	fmt.Println()
	fmt.Println("  Kraken creates two internal TCP connections:")
	fmt.Println("    • one that accepts the client's connection (posing as the server)")
	fmt.Println("    • one that connects to the real server (posing as the client)")
	fmt.Println("  A bridge forwards data between them. Currently a plain mirror;")
	fmt.Println("  L5+ transforms can be hooked in without changing the architecture.")
	fmt.Println()
	fmt.Println("  Prerequisites:")
	fmt.Println("    • Kraken must already be in the traffic path (e.g. via ARP poisoning)")
	fmt.Println("    • IP forwarding enabled:  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
	fmt.Println("    • CAP_NET_ADMIN (run as root or with appropriate capabilities)")
	fmt.Println()
	printSection("Required:")
	printField("client", "IP address of the client to intercept")
	printField("server", "IP address of the server to intercept")
	printField("port", "TCP port on the server")
	fmt.Println()
	printSection("Options:")
	printField("i", "interface to use (default: first active interface)")
	fmt.Println()
	printSection("Note:")
	fmt.Println("  swap intercepts NEW connections only. TCP sessions established before")
	fmt.Println("  swap was run are not affected.")
	fmt.Println()
	printSection("Platform support:")
	fmt.Println("  Linux only. Windows requires WinDivert (not yet implemented).")
	fmt.Println()
	printSection("Example:")
	printCode(`swap{client="192.168.1.10", server="192.168.1.1", port=80}`)
	printCode(`swap{client="192.168.1.10", server="192.168.1.1", port=443, i="eth0"}`)
}


