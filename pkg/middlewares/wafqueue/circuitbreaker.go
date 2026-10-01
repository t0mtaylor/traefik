package wafqueue

import (
	"sync"
	"time"
)

// breaker is a minimal circuit breaker guarding the background valkey I/O. When valkey is
// down/churning, consecutive failures trip it open; while open, callers skip the valkey dial
// entirely (allow() is a single mutex-guarded bool/time check, ~0 cost) so a dead valkey adds
// no work. After the cooldown it half-opens for one probe: a success closes it, a failure
// re-opens it. It never touches the request hot path — the hot path only does a non-blocking
// channel send — but it keeps the background drain from piling up behind a stalled valkey.
type breaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
	threshold int           // consecutive failures that trip the breaker open
	cooldown  time.Duration // how long it stays open before a half-open probe

	// Observability (read via snapshot(), published by the health heartbeat).
	openCount int64  // total number of times the breaker has tripped open
	lastOkMs  int64  // unix millis of the last successful call
	lastErrMs int64  // unix millis of the last failure
	lastErr   string // last failure message (auth already redacted by the caller)
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 2 * time.Second
	}
	return &breaker{threshold: threshold, cooldown: cooldown}
}

// breakerSnapshot is a point-in-time, lock-free-to-read copy of the breaker state for the
// health heartbeat and the /api/waf connection panel.
type breakerSnapshot struct {
	State     string // "closed" | "open" | "half-open"
	OpenCount int64
	LastOkMs  int64
	LastErrMs int64
	LastErr   string
}

// snapshot returns the current breaker state without changing it. Nil-safe.
func (b *breaker) snapshot() breakerSnapshot {
	if b == nil {
		return breakerSnapshot{State: "closed"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state := "closed"
	if !b.openUntil.IsZero() {
		if time.Now().Before(b.openUntil) {
			state = "open"
		} else {
			state = "half-open"
		}
	}
	return breakerSnapshot{
		State:     state,
		OpenCount: b.openCount,
		LastOkMs:  b.lastOkMs,
		LastErrMs: b.lastErrMs,
		LastErr:   b.lastErr,
	}
}

// allow reports whether a call may proceed. Closed ⇒ true. Open ⇒ false until the cooldown
// elapses, then it allows exactly one half-open probe (extending the window so concurrent
// callers do not all probe at once). Nil-safe: a nil breaker always allows.
func (b *breaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true // closed
	}
	if time.Now().Before(b.openUntil) {
		return false // open — skip valkey entirely
	}
	// Cooldown elapsed: half-open. Allow one probe and push the window out so only this caller
	// probes; success()/failure() will resolve the state.
	b.openUntil = time.Now().Add(b.cooldown)
	return true
}

// success records a successful call and closes the breaker.
func (b *breaker) success() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures = 0
	b.openUntil = time.Time{}
	b.lastOkMs = time.Now().UnixMilli()
	b.mu.Unlock()
}

// failure records a failed call and trips the breaker open once the threshold is reached.
// errMsg is stored for observability; the caller must redact any auth material first.
func (b *breaker) failure(errMsg string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures++
	b.lastErrMs = time.Now().UnixMilli()
	b.lastErr = errMsg
	if b.failures >= b.threshold && b.openUntil.IsZero() {
		b.openUntil = time.Now().Add(b.cooldown)
		b.openCount++
	} else if b.failures >= b.threshold {
		b.openUntil = time.Now().Add(b.cooldown)
	}
	b.mu.Unlock()
}

// open reports whether the breaker is currently open (for tests/metrics). Nil-safe.
func (b *breaker) open() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.openUntil.IsZero() && time.Now().Before(b.openUntil)
}
