package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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

// luaTableBool reads a boolean field from a table; returns (value, true) if present.
func luaTableBool(tbl *rt.Table, key string) (bool, bool) {
	v := tbl.Get(rt.StringValue(key))
	if v.IsNil() {
		return false, false
	}
	b, ok := v.TryBool()
	return b, ok
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

	// Capture file defaults to "session.pcap"; override with capture="name".
	captureName := tableGetString(tbl, "capture")
	if captureName == "" {
		captureName = "session.pcapng"
	}
	capturePath := timestampedPath(captureName)

	if err := globalAdoptions.add(ip, mac, iface, capturePath); err != nil {
		return nil, err
	}
	fmt.Printf("adopting %s on %s (mac: %s)\n", ip, iface.Name, mac)
	return c.Next(), nil
}

// timestampedPath inserts a timestamp before the file extension.
// e.g. "session.pcap" → "session_20260312_153045.pcap"
func timestampedPath(name string) string {
	ts := time.Now().Format("20060102_150405")
	dot := strings.LastIndex(name, ".")
	if dot < 0 {
		return name + "_" + ts
	}
	return name[:dot] + "_" + ts + name[dot:]
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
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("ping: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("ping: ip required (adopted source IP)")
	}
	srcIP := net.ParseIP(strings.TrimSpace(ipStr))
	if srcIP == nil {
		return nil, fmt.Errorf("ping: invalid ip: %q", ipStr)
	}

	targetStr := tableGetString(tbl, "t")
	if targetStr == "" {
		return nil, fmt.Errorf("ping: t required (target IP)")
	}
	dstIP := net.ParseIP(strings.TrimSpace(targetStr))
	if dstIP == nil {
		return nil, fmt.Errorf("ping: invalid target IP: %q", targetStr)
	}

	count := 20
	if v, ok := luaTableUint16(tbl, "count"); ok && v > 0 {
		count = int(v)
	}
	id := uint16(1)
	if v, ok := luaTableUint16(tbl, "id"); ok {
		id = v
	}

	entry, found := globalAdoptions.lookupByIP(srcIP)
	if !found {
		return nil, fmt.Errorf("ping: %s is not adopted", srcIP)
	}
	if entry.netstack == nil {
		return nil, fmt.Errorf("ping: no netstack available for %s", srcIP)
	}

	if err := entry.netstack.ping(context.Background(), dstIP, count, id); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaDial(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("dial: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("dial: ip required (adopted source IP)")
	}
	srcIP := net.ParseIP(strings.TrimSpace(ipStr))
	if srcIP == nil {
		return nil, fmt.Errorf("dial: invalid ip: %q", ipStr)
	}

	targetStr := tableGetString(tbl, "t")
	if targetStr == "" {
		return nil, fmt.Errorf("dial: t required (target IP)")
	}
	dstIP := net.ParseIP(strings.TrimSpace(targetStr))
	if dstIP == nil {
		return nil, fmt.Errorf("dial: invalid target IP: %q", targetStr)
	}

	port, ok := luaTableUint16(tbl, "port")
	if !ok || port == 0 {
		return nil, fmt.Errorf("dial: port required")
	}

	entry, found := globalAdoptions.lookupByIP(srcIP)
	if !found {
		return nil, fmt.Errorf("dial: %s is not adopted", srcIP)
	}
	if entry.netstack == nil {
		return nil, fmt.Errorf("dial: no netstack available for %s", srcIP)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("connecting %s → %s:%d\n", srcIP, dstIP, port)
	conn, err := entry.netstack.dial(ctx, dstIP, port)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	fmt.Printf("connected %s → %s\n", conn.LocalAddr(), conn.RemoteAddr())

	// Read up to 4096 bytes with a 3s deadline — banner grab.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		fmt.Printf("received %d bytes:\n%s\n", n, buf[:n])
	} else {
		fmt.Println("no data received")
	}
	return c.Next(), nil
}

func luaListen(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("listen: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("listen: ip required")
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, fmt.Errorf("listen: invalid IP: %q", ipStr)
	}

	port, ok := luaTableUint16(tbl, "port")
	if !ok || port == 0 {
		return nil, fmt.Errorf("listen: port required")
	}

	entry, found := globalAdoptions.lookupByIP(ip)
	if !found {
		return nil, fmt.Errorf("listen: %s is not adopted", ip)
	}
	if entry.netstack == nil {
		return nil, fmt.Errorf("listen: no netstack available for %s", ip)
	}

	echo, _ := luaTableBool(tbl, "echo")
	handler := func(conn net.Conn) {
		if echo {
			io.Copy(conn, conn)
		}
		conn.Close()
	}
	entry.netstack.listen(port, handler)
	fmt.Printf("listening on %s:%d", ip, port)
	if echo {
		fmt.Print(" (echo)")
	}
	fmt.Println()
	return c.Next(), nil
}

func luaCapture(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	var ifaceName, fileArg string
	if c.NArgs() > 0 {
		tbl, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		ifaceName = tableGetString(tbl, "i")
		fileArg = tableGetString(tbl, "file")
	}
	iface, err := resolveIface(ifaceName)
	if err != nil {
		return nil, err
	}
	if fileArg != "" {
		if err := doCaptureToFile(iface, timestampedPath(fileArg)); err != nil {
			return nil, err
		}
		return c.Next(), nil
	}
	fmt.Printf("capturing on %s\n", iface.Name)
	if err := doCapture(iface); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaSetMod(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("setmod: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("setmod: ip required (adopted IP)")
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil, fmt.Errorf("setmod: invalid IP: %q", ipStr)
	}

	entry, found := globalAdoptions.lookupByIP(ip)
	if !found {
		return nil, fmt.Errorf("setmod: %s is not adopted", ip)
	}
	if entry.netstack == nil {
		return nil, fmt.Errorf("setmod: no netstack available for %s", ip)
	}

	var mod packetMod

	if ethTbl := luaSubTable(tbl, "eth"); ethTbl != nil {
		mod.EthSrc = luaTableMAC(ethTbl, "src")
		mod.EthDst = luaTableMAC(ethTbl, "dst")
	}

	if l3Tbl := luaSubTable(tbl, "l3"); l3Tbl != nil {
		mod.IPSrc = luaTableIP(l3Tbl, "src")
		mod.IPDst = luaTableIP(l3Tbl, "dst")
		if v, ok := luaTableUint8(l3Tbl, "ttl"); ok {
			mod.TTL = &v
		}
		if v, ok := luaTableUint8(l3Tbl, "tos"); ok {
			mod.TOS = &v
		}
	}

	if l4Tbl := luaSubTable(tbl, "l4"); l4Tbl != nil {
		if v, ok := luaTableUint16(l4Tbl, "src_port"); ok {
			mod.TCPSrcPort = &v
		}
		if v, ok := luaTableUint16(l4Tbl, "dst_port"); ok {
			mod.TCPDstPort = &v
		}
		if v, ok := luaTableUint16(l4Tbl, "window"); ok {
			mod.Window = &v
		}
	}

	entry.netstack.setMod(mod)
	fmt.Printf("header mod set for %s\n", ip)
	return c.Next(), nil
}

func luaSwap(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("swap: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	clientStr := tableGetString(tbl, "client")
	if clientStr == "" {
		return nil, fmt.Errorf("swap: client required")
	}
	clientIP := net.ParseIP(strings.TrimSpace(clientStr))
	if clientIP == nil {
		return nil, fmt.Errorf("swap: invalid client IP: %q", clientStr)
	}

	serverStr := tableGetString(tbl, "server")
	if serverStr == "" {
		return nil, fmt.Errorf("swap: server required")
	}
	serverIP := net.ParseIP(strings.TrimSpace(serverStr))
	if serverIP == nil {
		return nil, fmt.Errorf("swap: invalid server IP: %q", serverStr)
	}

	port, ok := luaTableUint16(tbl, "port")
	if !ok || port == 0 {
		return nil, fmt.Errorf("swap: port required")
	}

	iface, err := resolveIface(tableGetString(tbl, "i"))
	if err != nil {
		return nil, err
	}

	s := &swapSession{
		client: clientIP.To4(),
		server: serverIP.To4(),
		port:   port,
		iface:  iface,
	}
	if err := startSwap(s); err != nil {
		return nil, err
	}
	globalSwaps.add(s)
	return c.Next(), nil
}

func luaConnLog(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	globalConnLog.Print()
	return c.Next(), nil
}

func luaConnLogClear(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	globalConnLog.Clear()
	fmt.Println("connection log cleared")
	return c.Next(), nil
}
