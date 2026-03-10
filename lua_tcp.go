package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	rt "github.com/arnodel/golua/runtime"
)

func luaTCPConnect(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("tcp_connect: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	dstStr := tableGetString(tbl, "dst")
	if dstStr == "" {
		return nil, fmt.Errorf("tcp_connect: dst required")
	}
	dstIP := net.ParseIP(strings.TrimSpace(dstStr))
	if dstIP == nil {
		return nil, fmt.Errorf("tcp_connect: invalid IP: %q", dstStr)
	}

	portVal, ok := luaTableUint16(tbl, "port")
	if !ok || portVal == 0 {
		return nil, fmt.Errorf("tcp_connect: port required")
	}

	iface, err := resolveIface(tableGetString(tbl, "i"))
	if err != nil {
		return nil, err
	}

	var srcPort uint16
	if v, ok := luaTableUint16(tbl, "src_port"); ok {
		srcPort = v
	}

	tcpParams := parseLuaTCPParams(tbl)

	fmt.Printf("connecting to %s:%d on %s\n", dstIP, portVal, iface.Name)
	sess, err := doTCPConnect(iface, dstIP, portVal, srcPort, tcpParams)
	if err != nil {
		return nil, err
	}
	fmt.Printf("connected (session %d: %s:%d → %s:%d)\n",
		sess.id, sess.srcIP, sess.srcPort, sess.dstIP, sess.dstPort)

	return c.PushingNext1(t.Runtime, rt.IntValue(int64(sess.id))), nil
}

func luaTCPListen(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("tcp_listen: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	portVal, ok := luaTableUint16(tbl, "port")
	if !ok || portVal == 0 {
		return nil, fmt.Errorf("tcp_listen: port required")
	}

	iface, err := resolveIface(tableGetString(tbl, "i"))
	if err != nil {
		return nil, err
	}

	// Optional adopted IP (and optionally its MAC).
	var srcIP net.IP
	var srcMAC net.HardwareAddr
	if ipStr := tableGetString(tbl, "ip"); ipStr != "" {
		srcIP = net.ParseIP(strings.TrimSpace(ipStr))
		if srcIP == nil {
			return nil, fmt.Errorf("tcp_listen: invalid ip: %q", ipStr)
		}
		srcIP = srcIP.To4()
		// If mac not explicitly given, look up the adoption table.
		if macStr := tableGetString(tbl, "mac"); macStr != "" {
			srcMAC, err = net.ParseMAC(strings.TrimSpace(macStr))
			if err != nil {
				return nil, fmt.Errorf("tcp_listen: invalid mac: %w", err)
			}
		} else if entry, found := globalAdoptions.lookupByIP(srcIP); found {
			srcMAC = entry.mac
		}
	}

	var timeout time.Duration
	if v, ok := luaTableUint16(tbl, "timeout"); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}

	tcpParams := parseLuaTCPParams(tbl)

	listenAddr := iface.Name
	if srcIP != nil {
		listenAddr = fmt.Sprintf("%s (%s)", iface.Name, srcIP)
	}
	fmt.Printf("listening on %s:%d\n", listenAddr, portVal)
	sess, err := doTCPListen(iface, srcIP, srcMAC, portVal, timeout, tcpParams)
	if err != nil {
		return nil, err
	}
	fmt.Printf("accepted connection (session %d: %s:%d ← %s:%d)\n",
		sess.id, sess.srcIP, sess.srcPort, sess.dstIP, sess.dstPort)

	return c.PushingNext1(t.Runtime, rt.IntValue(int64(sess.id))), nil
}

func luaTCPSend(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() < 2 {
		return nil, fmt.Errorf("tcp_send: expected (session_id, data)")
	}
	idVal := c.Arg(0)
	id, ok := idVal.TryInt()
	if !ok {
		return nil, fmt.Errorf("tcp_send: session_id must be an integer")
	}
	data, err := c.StringArg(1)
	if err != nil {
		return nil, err
	}

	sess, found := globalTCPSessions.get(int(id))
	if !found {
		return nil, fmt.Errorf("tcp_send: unknown session %d", id)
	}
	if err := tcpSend(sess, []byte(data)); err != nil {
		return nil, err
	}
	return c.Next(), nil
}

func luaTCPRecv(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("tcp_recv: expected session_id")
	}
	idVal := c.Arg(0)
	id, ok := idVal.TryInt()
	if !ok {
		return nil, fmt.Errorf("tcp_recv: session_id must be an integer")
	}

	timeout := defaultTCPRecvTimeout
	if c.NArgs() >= 2 {
		secsVal := c.Arg(1)
		secs, ok := secsVal.TryInt()
		if !ok {
			return nil, fmt.Errorf("tcp_recv: timeout must be an integer (seconds)")
		}
		timeout = time.Duration(secs) * time.Second
	}

	sess, found := globalTCPSessions.get(int(id))
	if !found {
		return nil, fmt.Errorf("tcp_recv: unknown session %d", id)
	}

	data, err := tcpRecv(sess, timeout)
	if err != nil {
		return nil, err
	}

	return c.PushingNext1(t.Runtime, rt.StringValue(string(data))), nil
}

func luaTCPClose(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("tcp_close: expected session_id")
	}
	idVal := c.Arg(0)
	id, ok := idVal.TryInt()
	if !ok {
		return nil, fmt.Errorf("tcp_close: session_id must be an integer")
	}

	sess, found := globalTCPSessions.get(int(id))
	if !found {
		return nil, fmt.Errorf("tcp_close: unknown session %d", id)
	}
	if err := tcpClose(sess); err != nil {
		return nil, err
	}
	fmt.Printf("session %d closed\n", id)
	return c.Next(), nil
}

func luaTCPSessions(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	sessions := globalTCPSessions.snapshot()
	if len(sessions) == 0 {
		fmt.Println(dim("no active TCP sessions"))
		return c.Next(), nil
	}
	fmt.Printf("  %-4s  %-22s  %-22s  %s\n",
		bold("ID"), bold("local"), bold("remote"), bold("state"))
	for _, s := range sessions {
		s.mu.Lock()
		local := fmt.Sprintf("%s:%d", s.srcIP, s.srcPort)
		remote := fmt.Sprintf("%s:%d", s.dstIP, s.dstPort)
		state := s.state
		s.mu.Unlock()
		fmt.Printf("  %-4d  %-22s  %-22s  %s\n",
			s.id, cyan(local), green(remote), state)
	}
	return c.Next(), nil
}
