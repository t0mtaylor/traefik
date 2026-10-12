package wafqueue

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errValkeyDown = errors.New("valkey down")

// When the breaker is OPEN, flush must NOT dial valkey (safety: a dead valkey adds no work)
// and must BUFFER the job for replay instead of dropping it.
func TestRetry_BreakerOpen_BuffersNoDial(t *testing.T) {
	fs := &fakeStore{}
	m, _ := testMW(t, mwOpts{store: fs})
	m.breaker = newBreaker(1, time.Hour) // trips after one failure, long cooldown
	m.retry = newRetryRing(10)
	m.breaker.failure("down") // trip it OPEN
	if m.breaker.allow() {
		t.Fatal("breaker should be open")
	}
	fs.mu.Lock()
	before := fs.enqN
	fs.mu.Unlock()
	m.flush(context.Background(), enqueueJob{ip: "198.51.100.1"})
	fs.mu.Lock()
	after := fs.enqN
	fs.mu.Unlock()
	if after != before {
		t.Fatalf("Enqueue dialed while breaker open (enqN %d->%d) — must skip valkey", before, after)
	}
	if m.retry.length() != 1 {
		t.Fatalf("job not buffered while breaker open (held=%d want 1)", m.retry.length())
	}
}

// When Enqueue FAILS (valkey down but breaker still closed), flush buffers the job; once valkey
// recovers, replayOnce drains the ring back into valkey in FIFO order with no loss.
func TestRetry_BufferThenReplayOnReconnect(t *testing.T) {
	fs := &fakeStore{enqErr: errValkeyDown}
	m, _ := testMW(t, mwOpts{store: fs})
	m.breaker = newBreaker(1000, time.Hour) // high threshold: isolate the Enqueue-fail path
	m.retry = newRetryRing(100)
	for i := 0; i < 3; i++ {
		m.flush(context.Background(), enqueueJob{ip: "198.51.100.2"})
	}
	if m.retry.length() != 3 {
		t.Fatalf("buffered=%d want 3", m.retry.length())
	}
	// valkey recovers
	fs.mu.Lock()
	fs.enqErr = nil
	enqBefore := fs.enqN
	fs.mu.Unlock()
	m.replayOnce(context.Background())
	if h := m.retry.length(); h != 0 {
		t.Fatalf("held=%d after replay, want 0", h)
	}
	fs.mu.Lock()
	replayed := fs.enqN - enqBefore
	fs.mu.Unlock()
	if replayed != 3 {
		t.Fatalf("replayed Enqueue=%d want 3", replayed)
	}
	if _, _, rep, _ := m.retry.snapshot(); rep != 3 {
		t.Fatalf("ring replayed counter=%d want 3", rep)
	}
}

// replayOnce must STOP (and re-buffer) when valkey is still down, never hot-spin or lose the job.
func TestRetry_ReplayStopsWhenStillDown(t *testing.T) {
	fs := &fakeStore{enqErr: errValkeyDown}
	m, _ := testMW(t, mwOpts{store: fs})
	m.breaker = newBreaker(1000, time.Hour)
	m.retry = newRetryRing(10)
	m.retry.push(enqueueJob{ip: "203.0.113.9"})
	m.replayOnce(context.Background()) // valkey still failing
	if m.retry.length() != 1 {
		t.Fatalf("job lost on failed replay (held=%d want 1)", m.retry.length())
	}
}
