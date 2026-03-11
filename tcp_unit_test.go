package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── tcpState.String() ─────────────────────────────────────────────────────────

func TestTCPStateString(t *testing.T) {
	cases := []struct {
		state tcpState
		want  string
	}{
		{tcpStateSynSent, "SYN_SENT"},
		{tcpStateEstablished, "ESTABLISHED"},
		{tcpStateFinWait1, "FIN_WAIT_1"},
		{tcpStateFinWait2, "FIN_WAIT_2"},
		{tcpStateCloseWait, "CLOSE_WAIT"},
		{tcpStateLastAck, "LAST_ACK"},
		{tcpStateClosed, "CLOSED"},
		{tcpState(99), "UNKNOWN"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.String(), "state %d", tc.state)
	}
}

// ── randomEphemeralPort ───────────────────────────────────────────────────────

func TestRandomEphemeralPort_InRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		p := randomEphemeralPort()
		assert.GreaterOrEqual(t, p, uint16(49152), "port %d below ephemeral range", p)
		assert.LessOrEqual(t, p, uint16(65534), "port %d above ephemeral range", p)
	}
}

func TestRandomEphemeralPort_NotAlwaysSame(t *testing.T) {
	seen := make(map[uint16]bool)
	for i := 0; i < 200; i++ {
		seen[randomEphemeralPort()] = true
	}
	assert.Greater(t, len(seen), 1, "should produce more than one distinct port")
}

// ── randomISN ────────────────────────────────────────────────────────────────

func TestRandomISN_ReturnsUint32(t *testing.T) {
	// Just verify it doesn't panic and returns a value (any uint32 is valid).
	_ = randomISN()
}

func TestRandomISN_NotAlwaysSame(t *testing.T) {
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		seen[randomISN()] = true
	}
	assert.Greater(t, len(seen), 1)
}

// ── tcpSessionTable ───────────────────────────────────────────────────────────

func newTestSession() *TCPSession {
	s := &TCPSession{}
	s.recvCond = sync.NewCond(&s.mu)
	return s
}

func TestSessionTable_AddAndGet(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	s := newTestSession()
	id := tbl.add(s)

	got, ok := tbl.get(id)
	require.True(t, ok)
	assert.Equal(t, s, got)
}

func TestSessionTable_GetMiss(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	_, ok := tbl.get(999)
	assert.False(t, ok)
}

func TestSessionTable_IDsAreMonotonicallyIncreasing(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	id1 := tbl.add(newTestSession())
	id2 := tbl.add(newTestSession())
	id3 := tbl.add(newTestSession())
	assert.Less(t, id1, id2)
	assert.Less(t, id2, id3)
}

func TestSessionTable_Remove(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	id := tbl.add(newTestSession())

	tbl.remove(id)
	_, ok := tbl.get(id)
	assert.False(t, ok)
}

func TestSessionTable_RemoveNonExistentIsNoop(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	assert.NotPanics(t, func() { tbl.remove(999) })
}

func TestSessionTable_Snapshot(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	s1 := newTestSession()
	s2 := newTestSession()
	tbl.add(s1)
	tbl.add(s2)

	snap := tbl.snapshot()
	assert.Len(t, snap, 2)
}

func TestSessionTable_SnapshotIsIndependent(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	id := tbl.add(newTestSession())
	snap := tbl.snapshot()
	require.Len(t, snap, 1)

	tbl.remove(id)
	assert.Len(t, snap, 1, "snapshot must be independent of the live table")
}

func TestSessionTable_ConcurrentAccess(t *testing.T) {
	tbl := &tcpSessionTable{entries: make(map[int]*TCPSession)}
	var wg sync.WaitGroup
	const n = 50

	ids := make([]int, n)
	for i := 0; i < n; i++ {
		ids[i] = tbl.add(newTestSession())
	}

	wg.Add(n * 3)
	for i := 0; i < n; i++ {
		id := ids[i]
		go func() { defer wg.Done(); tbl.get(id) }()
		go func() { defer wg.Done(); tbl.snapshot() }()
		go func() { defer wg.Done(); tbl.remove(id) }()
	}
	wg.Wait()
}

// ── tcpRecv timeout ───────────────────────────────────────────────────────────

func TestTCPRecv_TimeoutOnEmptyBuffer(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateEstablished

	start := time.Now()
	_, err := tcpRecv(s, 100*time.Millisecond)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	// Should return promptly after the timeout (allow 200ms slop for CI).
	assert.Less(t, elapsed, 500*time.Millisecond)
}

func TestTCPRecv_ReturnsDataInBuffer(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateEstablished
	s.recvBuf = []byte("hello")

	data, err := tcpRecv(s, time.Second)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)
	assert.Empty(t, s.recvBuf, "buffer should be drained after recv")
}

func TestTCPRecv_ErrorOnClosed(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateClosed

	_, err := tcpRecv(s, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestTCPRecv_WakesWhenDataArrives(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateEstablished

	go func() {
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		s.recvBuf = []byte("world")
		s.recvCond.Broadcast()
		s.mu.Unlock()
	}()

	data, err := tcpRecv(s, time.Second)
	require.NoError(t, err)
	assert.Equal(t, []byte("world"), data)
}

// ── tcpRecv with CLOSE_WAIT ───────────────────────────────────────────────────

// After the peer sends FIN the session transitions to CLOSE_WAIT.  Any data
// that arrived before the FIN must still be readable; the receiver should not
// see an error just because the peer closed its side.

func TestTCPRecv_DrainsBufInCloseWait(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateCloseWait
	s.recvBuf = []byte("last bytes")

	data, err := tcpRecv(s, time.Second)
	require.NoError(t, err)
	assert.Equal(t, []byte("last bytes"), data)
}

func TestTCPRecv_TimeoutInCloseWaitWhenEmpty(t *testing.T) {
	s := newTestSession()
	s.state = tcpStateCloseWait // peer FIN received, buf is empty

	_, err := tcpRecv(s, 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// ── tcpClose state check ──────────────────────────────────────────────────────

func TestTCPClose_RejectsInvalidStates(t *testing.T) {
	for _, state := range []tcpState{
		tcpStateSynSent,
		tcpStateFinWait1,
		tcpStateFinWait2,
		tcpStateLastAck,
	} {
		s := newTestSession()
		s.state = state
		err := tcpClose(s)
		assert.Error(t, err, "tcpClose on %s should return an error", state)
		assert.Contains(t, err.Error(), state.String())
	}
}

// ── tcpSend state check ───────────────────────────────────────────────────────

func TestTCPSend_RejectsNonEstablished(t *testing.T) {
	for _, state := range []tcpState{
		tcpStateSynSent,
		tcpStateFinWait1,
		tcpStateFinWait2,
		tcpStateLastAck,
		tcpStateClosed,
	} {
		s := newTestSession()
		s.state = state
		err := tcpSend(s, []byte("data"))
		assert.Error(t, err, "state %s should reject send", state)
		assert.Contains(t, err.Error(), state.String())
	}
}
