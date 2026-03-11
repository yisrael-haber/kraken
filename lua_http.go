package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	rt "github.com/arnodel/golua/runtime"
)

func luaHTTPServe(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if c.NArgs() == 0 {
		return nil, fmt.Errorf("http_serve: expected table argument")
	}
	tbl, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}

	ipStr := tableGetString(tbl, "ip")
	if ipStr == "" {
		return nil, fmt.Errorf("http_serve: ip required")
	}
	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return nil, fmt.Errorf("http_serve: invalid IP: %q", ipStr)
	}
	srcIP := parsed.To4()
	if srcIP == nil {
		return nil, fmt.Errorf("http_serve: %q is not an IPv4 address", ipStr)
	}

	portVal, ok := luaTableUint16(tbl, "port")
	if !ok || portVal == 0 {
		return nil, fmt.Errorf("http_serve: port required")
	}

	iface, err := resolveIface(tableGetString(tbl, "i"))
	if err != nil {
		return nil, err
	}

	path := tableGetString(tbl, "path")
	if path == "" {
		path, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("http_serve: getting cwd: %w", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("http_serve: path %q: %w", path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("http_serve: path %q is not a directory", path)
	}

	// Ensure the IP is adopted so ARP requests from clients are answered.
	// If the caller already adopted it (possibly with a custom MAC), use that;
	// otherwise adopt it now with the interface's own MAC and unadopt on exit.
	var srcMAC net.HardwareAddr
	selfAdopted := false
	if entry, found := globalAdoptions.lookupByIP(srcIP); found {
		srcMAC = entry.mac
	} else {
		srcMAC = iface.HardwareAddr
		if err := globalAdoptions.add(srcIP, srcMAC, iface); err != nil {
			return nil, fmt.Errorf("http_serve: adopting %s: %w", srcIP, err)
		}
		selfAdopted = true
		fmt.Printf("adopted %s on %s (mac %s)\n", srcIP, iface.Name, srcMAC)
	}

	ln, err := NewTCPListener(iface, srcIP, srcMAC, portVal, TCPParams{})
	if err != nil {
		if selfAdopted {
			globalAdoptions.remove(srcIP)
		}
		return nil, fmt.Errorf("http_serve: %w", err)
	}
	// Defers run LIFO: signal cleanup → close listener → unadopt.
	defer func() {
		if selfAdopted {
			globalAdoptions.remove(srcIP)
		}
	}()
	defer ln.Close()

	// sigDone lets us stop the signal goroutine if Serve exits for any reason
	// other than Ctrl+C (unexpected error), preventing a goroutine leak.
	sigDone := make(chan struct{})
	defer close(sigDone)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-stop:
			signal.Stop(stop)
			ln.Close()
		case <-sigDone:
			signal.Stop(stop)
		}
	}()

	fmt.Printf("serving %s on http://%s:%d/  (Ctrl+C to stop)\n", path, srcIP, portVal)

	server := &http.Server{Handler: http.FileServer(http.Dir(path))}
	if err := server.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return nil, fmt.Errorf("http_serve: %w", err)
	}

	fmt.Println("http server stopped")
	return c.Next(), nil
}
