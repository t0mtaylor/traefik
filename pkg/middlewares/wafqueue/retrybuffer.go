package wafqueue

import (
	"sync"
	"time"
)

// retryRingCap bounds the in-memory ring of inspection jobs held while valkey is
// unreachable (breaker open / Enqueue failing). A FIXED cap => bounded memory, never an
// OOM, even if valkey is down for a long time. On overflow the OLDEST entry is dropped
// (freshest attacker events are the ones worth replaying). The ring is drained back into
// valkey by retryLoop once the breaker closes. It is ONLY touched by the background
// drain/replay goroutines — never the request hot path — so it can never add request latency.
const retryRingCap = 100000

// retryReplayInterval is how often retryLoop attempts to drain the ring into valkey.
// maxReplayPerTick caps work per tick so replay stays incremental + ctx-responsive and never
// hot-spins or hogs a goroutine during a large backlog.
const (
	retryReplayInterval = time.Second
	maxReplayPerTick    = 2000
)

// retryRing is a bounded, mutex-guarded FIFO ring of enqueueJob awaiting replay. All methods
// are nil-safe: a nil ring degrades to the previous pure-drop fail-open behaviour. push never
// blocks and never grows past cap.
type retryRing struct {
	mu       sync.Mutex
	buf      []enqueueJob
	head     int
	size     int
	capacity int

	buffered int64 // cumulative jobs buffered (observability)
	dropped  int64 // cumulative jobs dropped on overflow (drop-oldest)
	replayed int64 // cumulative jobs successfully replayed to valkey
}

func newRetryRing(capacity int) *retryRing {
	if capacity <= 0 {
		capacity = retryRingCap
	}
	return &retryRing{buf: make([]enqueueJob, capacity), capacity: capacity}
}

// push appends a job; on overflow it overwrites the oldest (drop-oldest) and counts it.
// Constant time, never blocks, nil-safe.
func (r *retryRing) push(job enqueueJob) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.size == r.capacity {
		r.head = (r.head + 1) % r.capacity
		r.size--
		r.dropped++
	}
	r.buf[(r.head+r.size)%r.capacity] = job
	r.size++
	r.buffered++
	r.mu.Unlock()
}

// pop removes + returns the oldest job; ok=false when empty. Nil-safe.
func (r *retryRing) pop() (enqueueJob, bool) {
	if r == nil {
		return enqueueJob{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return enqueueJob{}, false
	}
	job := r.buf[r.head]
	r.buf[r.head] = enqueueJob{} // release reference for GC
	r.head = (r.head + 1) % r.capacity
	r.size--
	return job, true
}

// markReplayed bumps the replay counter after a successful Enqueue. Nil-safe.
func (r *retryRing) markReplayed() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.replayed++
	r.mu.Unlock()
}

// length is the current held count. Nil-safe.
func (r *retryRing) length() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// snapshot returns cumulative counters for observability. Nil-safe.
func (r *retryRing) snapshot() (buffered, dropped, replayed int64, held int) {
	if r == nil {
		return 0, 0, 0, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buffered, r.dropped, r.replayed, r.size
}
