package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ── formatRTT ─────────────────────────────────────────────────────────────────

func TestFormatRTT_Microseconds(t *testing.T) {
	s := formatRTT(500 * time.Microsecond)
	assert.Contains(t, s, "µs")
	assert.NotContains(t, s, "ms")
}

func TestFormatRTT_ExactlyOneMicrosecond(t *testing.T) {
	s := formatRTT(1 * time.Microsecond)
	assert.Contains(t, s, "µs")
}

func TestFormatRTT_ExactlyOneMillisecond(t *testing.T) {
	// d == time.Millisecond is NOT < time.Millisecond, so should use ms branch.
	s := formatRTT(time.Millisecond)
	assert.Contains(t, s, "ms")
}

func TestFormatRTT_Milliseconds(t *testing.T) {
	s := formatRTT(42500 * time.Microsecond) // 42.5 ms
	assert.Contains(t, s, "ms")
	assert.Contains(t, s, "42.500")
}

func TestFormatRTT_SubMicrosecondIsStillMicros(t *testing.T) {
	// Any duration below 1ms → µs branch.
	s := formatRTT(999 * time.Microsecond)
	assert.Contains(t, s, "µs")
}
