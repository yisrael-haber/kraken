package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	rt "github.com/arnodel/golua/runtime"
)

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

// ── Lua command wrappers ─────────────────────────────────────────────────────

func luaClear(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
	return c.Next(), nil
}

func luaDevices(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if err := cmdDevices(nil); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaARPCache(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	entries := globalARPCache.snapshot()
	if len(entries) == 0 {
		fmt.Println(dim("ARP cache is empty"))
		return c.Next(), nil
	}
	now := time.Now()
	fmt.Printf("  %-18s  %-19s  %s\n", bold("IP"), bold("MAC"), bold("age"))
	for ip, e := range entries {
		age := now.Sub(e.updated).Round(time.Second)
		fmt.Printf("  %-18s  %-19s  %s\n", cyan(ip), green(e.mac.String()), dim(age.String()))
	}
	return c.Next(), nil
}

func luaARPClear(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() > 0 {
		ipStr, err := c.StringArg(0)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			return nil, fmt.Errorf("arpclear: invalid IP: %q", ipStr)
		}
		globalARPCache.delete(ip)
		fmt.Printf("cleared ARP cache entry for %s\n", ipStr)
	} else {
		globalARPCache.clear()
		fmt.Println("ARP cache cleared")
	}
	return c.Next(), nil
}

func luaAdopt(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("adopt: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("adopt: ip required")
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, fmt.Errorf("adopt: invalid IP: %q", ipStr)
	}

	iface, err := resolveIface(tableGetString(tbl, "i"))
	if err != nil {
		return nil, err
	}

	mac := iface.HardwareAddr
	if macStr := tableGetString(tbl, "mac"); macStr != "" {
		parsed, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("adopt: invalid MAC: %s", macStr)
		}
		mac = parsed
	}

	if err := globalAdoptions.add(ip, mac, iface); err != nil {
		return nil, err
	}
	fmt.Printf("adopting %s on %s (mac: %s)\n", ip, iface.Name, mac)
	return c.Next(), nil
}

func luaUnadopt(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	ipStr, err := c.StringArg(0)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, fmt.Errorf("unadopt: invalid IP: %q", ipStr)
	}
	if !globalAdoptions.remove(ip) {
		fmt.Printf("%s was not adopted\n", ip)
	} else {
		fmt.Printf("unadopted %s\n", ip)
	}
	return c.Next(), nil
}

func luaAdopted(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	entries := globalAdoptions.snapshot()
	if len(entries) == 0 {
		fmt.Println(dim("no adopted addresses"))
		return c.Next(), nil
	}
	fmt.Printf("  %-18s  %-19s  %s\n", bold("IP"), bold("MAC"), bold("interface"))
	for _, e := range entries {
		fmt.Printf("  %-18s  %-19s  %s\n", cyan(e.ip.String()), green(e.mac.String()), e.iface.Name)
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
	count := 20

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
		if v, ok := luaTableUint16(tbl, "count"); ok && v > 0 {
			count = int(v)
		}
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

	fmt.Printf("PING %s on %s\n", dstIP, iface.Name)
	var received int
	for i := 1; i <= count; i++ {
		loopICMP := icmp
		if !loopICMP.HasSeq {
			loopICMP.Seq = uint16(i)
			loopICMP.HasSeq = true
		}
		rtt, err := doPing(iface, dstIP, eth, ip4, loopICMP)
		if errors.Is(err, errPingTimeout) {
			fmt.Printf("Request timeout for icmp_seq=%d\n", loopICMP.Seq)
		} else if err != nil {
			return nil, err
		} else {
			received++
			fmt.Printf("reply from %s: icmp_seq=%d time=%s\n", dstIP, loopICMP.Seq, formatRTT(rtt))
		}
	}
	loss := (count - received) * 100 / count
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss\n", count, received, loss)
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
