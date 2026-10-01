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
	b.mu.Unlock()
}

// failure records a failed call and trips the breaker open once the threshold is reached.
func (b *breaker) failure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures++
	if b.failures >= b.threshold {
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
