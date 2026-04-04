//go:build linux

package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveSwapMACCacheHit verifies that resolveSwapMAC returns the cached
// MAC without performing any ARP request when the IP is already in globalARPCache.
// This exercises the fast path without requiring root or network access.
func TestResolveSwapMACCacheHit(t *testing.T) {
	ip := net.ParseIP("192.0.2.1").To4() // TEST-NET, will never be ARPed
	want := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	globalARPCache.set(ip, want)
	t.Cleanup(func() { globalARPCache.delete(ip) })

	// iface is intentionally zero-value — if the cache miss path were taken,
	// ifaceIPv4 would fail immediately, causing the test to error rather than
	// silently pass with a wrong MAC.
	got, err := resolveSwapMAC("", net.Interface{}, ip)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
