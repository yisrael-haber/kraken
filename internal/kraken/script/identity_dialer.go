package script

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IdentityDialer adapts an adopted identity's netstack to libraries that accept
// net.Dialer-shaped hooks. It preserves Kraken's source-identity routing.
type IdentityDialer struct {
	Identity SocketIdentity
	Options  SocketOptions
}

func (dialer IdentityDialer) Dial(network, address string) (net.Conn, error) {
	return dialer.DialContext(context.Background(), network, address)
}

func (dialer IdentityDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer.Identity == nil {
		return nil, fmt.Errorf("identity dialer requires an adopted identity")
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("address must be host:port: %w", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("address host must be an IPv4 address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("address port must be between 1 and 65535")
	}

	switch {
	case strings.HasPrefix(network, "tcp"):
		if ctx == nil {
			ctx = context.Background()
		}
		return dialer.Identity.DialScriptTCP(ctx, ip, port, dialer.Options)
	case strings.HasPrefix(network, "udp"):
		return dialer.Identity.DialScriptUDP(ip, port, dialer.Options)
	default:
		return nil, fmt.Errorf("unsupported identity dial network %q", network)
	}
}
