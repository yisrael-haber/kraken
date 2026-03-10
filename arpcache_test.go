package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCache() *arpCache {
	return &arpCache{entries: make(map[string]arpEntry)}
}

// ── Basic set / lookup ────────────────────────────────────────────────────────

func TestARPCache_SetAndLookup(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	c.set(ip, mac)
	got, ok := c.lookup(ip)
	require.True(t, ok)
	assert.Equal(t, mac, got)
}

func TestARPCache_MissOnUnknownIP(t *testing.T) {
	c := newTestCache()
	_, ok := c.lookup(net.ParseIP("1.2.3.4"))
	assert.False(t, ok)
}

func TestARPCache_OverwriteUpdatesMAC(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	mac1 := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	mac2 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	c.set(ip, mac1)
	c.set(ip, mac2)
	got, ok := c.lookup(ip)
	require.True(t, ok)
	assert.Equal(t, mac2, got)
}

// ── TTL expiry ────────────────────────────────────────────────────────────────

func TestARPCache_ExpiredEntryReturnsMiss(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	mac := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	// Insert with a timestamp in the past that exceeds arpCacheTTL.
	c.mu.Lock()
	c.entries[ip.String()] = arpEntry{
		mac:     mac,
		updated: time.Now().Add(-(arpCacheTTL + time.Second)),
	}
	c.mu.Unlock()

	_, ok := c.lookup(ip)
	assert.False(t, ok, "expired entry should not be returned")
}

func TestARPCache_FreshEntryIsReturned(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.2")
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}

	c.mu.Lock()
	c.entries[ip.String()] = arpEntry{
		mac:     mac,
		updated: time.Now().Add(-(arpCacheTTL - time.Second)),
	}
	c.mu.Unlock()

	got, ok := c.lookup(ip)
	require.True(t, ok)
	assert.Equal(t, mac, got)
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestARPCache_Delete(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	c.set(ip, net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})

	c.delete(ip)
	_, ok := c.lookup(ip)
	assert.False(t, ok)
}

func TestARPCache_DeleteNonExistentIsNoop(t *testing.T) {
	c := newTestCache()
	assert.NotPanics(t, func() { c.delete(net.ParseIP("9.9.9.9")) })
}

// ── Clear ─────────────────────────────────────────────────────────────────────

func TestARPCache_Clear(t *testing.T) {
	c := newTestCache()
	c.set(net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	c.set(net.ParseIP("10.0.0.2"), net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})

	c.clear()

	_, ok1 := c.lookup(net.ParseIP("10.0.0.1"))
	_, ok2 := c.lookup(net.ParseIP("10.0.0.2"))
	assert.False(t, ok1)
	assert.False(t, ok2)
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

func TestARPCache_SnapshotIsACopy(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	mac := net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	c.set(ip, mac)

	snap := c.snapshot()
	require.Len(t, snap, 1)

	// Mutating the original cache must not affect the snapshot.
	c.clear()
	assert.Len(t, snap, 1, "snapshot must be independent of the live cache")
}

func TestARPCache_SnapshotEmpty(t *testing.T) {
	c := newTestCache()
	snap := c.snapshot()
	assert.Empty(t, snap)
}

// ── Concurrent safety ─────────────────────────────────────────────────────────

func TestARPCache_ConcurrentAccess(t *testing.T) {
	c := newTestCache()
	ip := net.ParseIP("10.0.0.1")
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func() { defer wg.Done(); c.set(ip, mac) }()
		go func() { defer wg.Done(); c.lookup(ip) }()
		go func() { defer wg.Done(); c.snapshot() }()
	}
	wg.Wait()
}
