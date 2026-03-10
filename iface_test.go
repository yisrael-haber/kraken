package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── parsePayload ──────────────────────────────────────────────────────────────

func TestParsePayload_RawString(t *testing.T) {
	data, err := parsePayload("hello")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)
}

func TestParsePayload_EmptyString(t *testing.T) {
	data, err := parsePayload("")
	require.NoError(t, err)
	assert.Equal(t, []byte(""), data)
}

func TestParsePayload_HexLowerPrefix(t *testing.T) {
	data, err := parsePayload("0xdeadbeef")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, data)
}

func TestParsePayload_HexUpperPrefix(t *testing.T) {
	data, err := parsePayload("0XCAFE01")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xca, 0xfe, 0x01}, data)
}

func TestParsePayload_HexEmptyAfterPrefix(t *testing.T) {
	data, err := parsePayload("0x")
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestParsePayload_InvalidHex(t *testing.T) {
	_, err := parsePayload("0xZZZZ")
	assert.Error(t, err)
}

func TestParsePayload_OddLengthHex(t *testing.T) {
	// hex.DecodeString requires even length
	_, err := parsePayload("0xabc")
	assert.Error(t, err)
}

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
