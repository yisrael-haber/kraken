package main

import (
	"fmt"
	"os"

	rt "github.com/arnodel/golua/runtime"
)

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
	fmt.Printf("  %-10s  %s\n", cyan("ping"), "send an ICMP echo request and wait for a reply")
	fmt.Printf("  %-10s  %s\n", cyan("capture"), "capture packets on an interface")
	fmt.Printf("  %-10s  %s\n", cyan("script"), "run a Lua script file")
	fmt.Printf("  %-10s  %s\n", cyan("arpcache"), "show the ARP cache")
	fmt.Printf("  %-10s  %s\n", cyan("arpclear"), "clear ARP cache entries")
	fmt.Printf("  %-10s  %s\n", cyan("adopt"), "respond to ARP and ICMP for an IP not bound to the interface")
	fmt.Printf("  %-10s  %s\n", cyan("unadopt"), "stop responding for an adopted IP")
	fmt.Printf("  %-10s  %s\n", cyan("adopted"), "list currently adopted IP addresses")
	fmt.Printf("  %-10s  %s\n", cyan("clear"), "clear the terminal screen")
	fmt.Println()
	fmt.Println(dim(`Run help("command") for detailed usage of a specific command.`))
}

func printSection(title string) { fmt.Println(bold(yellow(title))) }
func printCode(s string)        { fmt.Println("    " + cyan(s)) }
func printField(name, desc string) {
	fmt.Printf("    %-14s %s\n", green(name), desc)
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
	"ping": func() {
		printSection(`ping{t="<ip>" [, options]}`)
		fmt.Println()
		fmt.Println("  Sends ICMP echo requests and waits for replies, printing RTT for each.")
		fmt.Println("  Resolves the destination MAC via ARP automatically.")
		fmt.Println()
		printSection("Required:")
		printField("t", "target IP address")
		fmt.Println()
		printSection("Top-level options:")
		printField("i", "interface to use (default: first active interface)")
		printField("count", "number of echo requests to send (default: 20)")
		fmt.Println()
		printSection("parameters={} — ICMP layer:")
		printField("type", "ICMP type   (default: 8 = echo request)")
		printField("code", "ICMP code   (default: 0)")
		printField("id", "identifier  (default: 1)")
		printField("seq", "sequence    (default: auto-increment from 1)")
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
		printField("dst", "dest MAC    (default: resolved via ARP)")
		fmt.Println()
		printSection("Examples:")
		printCode(`ping{t="192.168.1.1"}`)
		printCode(`ping{t="192.168.1.1", i="eth0"}`)
		printCode(`ping{t="192.168.1.1", count=5}`)
		printCode(`ping{t="192.168.1.1", parameters={id=42, seq=7}}`)
		printCode(`ping{t="192.168.1.1", parameters={data="hello"}}`)
		printCode(`ping{t="192.168.1.1", parameters={data="0xdeadbeef"}}`)
		printCode(`ping{t="192.168.1.1", parameters={type=8, code=0}}`)
		printCode(`ping{t="192.168.1.1", ip={src="10.0.0.5", ttl=128}}`)
		printCode(`ping{t="192.168.1.1", eth={src="aa:bb:cc:dd:ee:ff"}}`)
	},
	"capture": func() {
		printSection("capture([{options}])")
		fmt.Println()
		fmt.Println("  Captures and prints packets on a network interface.")
		fmt.Println("  Runs until interrupted (Ctrl+C).")
		fmt.Println()
		printSection("Options:")
		printField("i", "interface to capture on (default: first active interface)")
		fmt.Println()
		printSection("Examples:")
		printCode("capture()")
		printCode(`capture{i="eth0"}`)
	},
	"script": func() {
		printSection("script(\"<file.lua>\")  /  moto script <file.lua>")
		fmt.Println()
		fmt.Println("  Loads and runs a Lua script file.")
		fmt.Println("  All moto commands are available as globals inside the script.")
		fmt.Println("  Full Lua is supported — variables, loops, functions, and conditionals all work.")
		fmt.Println()
		fmt.Println("  When called from the interactive shell, the script shares the shell's runtime:")
		fmt.Println("  any globals it defines remain accessible after it finishes.")
		fmt.Println("  Scripts can also call script() themselves to load further files.")
		fmt.Println()
		printSection("Usage:")
		printCode(`script("path/to/script.lua")   -- from the shell`)
		printCode("moto script path/to/script.lua  -- from the CLI")
		fmt.Println()
		printSection("Example script:")
		printCode(`-- scan a subnet`)
		printCode(`for i = 1, 254 do`)
		printCode(`    arp{t="192.168.1." .. i}`)
		printCode(`end`)
	},
	"arpcache": func() {
		printSection("arpcache()")
		fmt.Println()
		fmt.Println("  Displays all entries in the ARP cache.")
		fmt.Println("  Entries expire after 5 minutes; a new ARP request is issued on next use.")
		fmt.Println("  The cache is populated automatically when sending packets (e.g. ping)")
		fmt.Println("  and persists for the lifetime of the process.")
		fmt.Println()
		printSection("Example:")
		printCode("arpcache()")
	},
	"arpclear": func() {
		printSection(`arpclear()  /  arpclear("<ip>")`)
		fmt.Println()
		fmt.Println("  Removes entries from the ARP cache.")
		fmt.Println("  Called with no arguments, clears the entire cache.")
		fmt.Println("  Called with an IP string, removes only that entry.")
		fmt.Println()
		printSection("Examples:")
		printCode("arpclear()")
		printCode(`arpclear("192.168.1.1")`)
	},
	"adopt": func() {
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
		fmt.Println()
		printSection("Examples:")
		printCode(`adopt{ip="192.168.1.100"}`)
		printCode(`adopt{ip="192.168.1.100", i="eth0"}`)
		printCode(`adopt{ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff"}`)
	},
	"unadopt": func() {
		printSection(`unadopt("<ip>")`)
		fmt.Println()
		fmt.Println("  Stops responding for the given adopted IP.")
		fmt.Println("  The interface listener shuts down automatically when no IPs remain on it.")
		fmt.Println()
		printSection("Example:")
		printCode(`unadopt("192.168.1.100")`)
	},
	"adopted": func() {
		printSection("adopted()")
		fmt.Println()
		fmt.Println("  Lists all currently adopted IP addresses, their advertised MAC, and interface.")
		fmt.Println()
		printSection("Example:")
		printCode("adopted()")
	},
	"clear": func() {
		printSection("clear()")
		fmt.Println()
		fmt.Println("  Clears the terminal screen. Works on Linux, macOS, and Windows.")
		fmt.Println()
		printSection("Example:")
		printCode("clear()")
	},
}
