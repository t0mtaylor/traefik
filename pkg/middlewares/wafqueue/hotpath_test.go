package wafqueue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// These tests prove the two-plane non-blocking guarantee of the async WAF (see DESIGN.md
// "Two-plane architecture"): the request hot path does ZERO network I/O, so a down/churning
// valkey adds no request latency. They back the production-outage fix where a blocking enqueue
// added valkey timeout latency to every request.

// statCount reads a live stat counter (same-package test access).
func statCount(m *wafQueue, field string) int64 {
	return m.stats.counts[field].Load()
}

func mkReq(method, path, xff, ua string) *http.Request {
	req, _ := http.NewRequest(method, "http://example.com"+path, nil)
	req.RemoteAddr = "203.0.113.5:1111"
	if xff != "" {
		req.Header.Set("X-Forwarded-Host", xff)
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return req
}

// Test 5 — the hot path is off the valkey path: next.ServeHTTP runs synchronously and the job
// is only buffered to the channel; store.Enqueue is NEVER called on the request goroutine.
func TestHotPath_EnqueueIsOffRequestPath(t *testing.T) {
	fs := &fakeStore{}
	m, called := testMW(t, mwOpts{store: fs})
	m.stats = newStatsCollector(fs, "waf:stats:", "n")

	rr := doReq(m, "203.0.113.5:1111", "/some/page", nil)

	if !*called || rr.Code != http.StatusOK {
		t.Fatalf("next must run synchronously and pass: called=%v code=%d", *called, rr.Code)
	}
	if fs.enqN != 0 {
		t.Fatalf("hot path must NOT call store.Enqueue synchronously (did %d times)", fs.enqN)
	}
	if len(m.jobs) != 1 {
		t.Fatalf("job should be buffered for the background worker, got %d buffered", len(m.jobs))
	}
	if got := statCount(m, statEnqueue); got != 1 {
		t.Fatalf("enqueue counter=%d want 1", got)
	}
}

// Test 1 — blackhole valkey adds ZERO hot-path latency. A real valkey client pointed at an
// unroutable address (192.0.2.1, TEST-NET-1) via New() with the real background workers
// running; every request must still pass fast.
func TestHotPath_ValkeyBlackhole_NoAddedLatency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tru := true
	next, called := okHandler()
	h, err := New(ctx, next, dynamic.WafQueue{ValkeyAddr: "192.0.2.1:6379", Shadow: &tru}, "blackhole")
	if err != nil {
		t.Fatal(err)
	}
	m := h.(*wafQueue)

	const n = 2000
	var maxD time.Duration
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/page", nil)
		req.RemoteAddr = "203.0.113.5:1111"
		rr := httptest.NewRecorder()
		t0 := time.Now()
		m.ServeHTTP(rr, req)
		if d := time.Since(t0); d > maxD {
			maxD = d
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d was blocked with a dead valkey: %d (shadow must always pass)", i, rr.Code)
		}
	}
	if !*called {
		t.Fatal("next handler was never called")
	}
	// The hot path only does a non-blocking channel send — never a valkey dial — so even with
	// an unroutable valkey the worst single request must be nowhere near the 50ms client dial
	// timeout. Generous bound to absorb CI GC pauses; real value is sub-millisecond.
	if maxD > 25*time.Millisecond {
		t.Fatalf("a dead valkey added hot-path latency: worst request %v (hot path must not touch valkey)", maxD)
	}
}

// Test 2 — when the bounded job channel is full the hot path DROPS and never blocks; the
// request still passes and the dropped counter climbs. testMW starts no drain, so the channel
// fills deterministically.
func TestHotPath_ChannelFull_DropsNeverBlocks(t *testing.T) {
	fs := &fakeStore{}
	m, _ := testMW(t, mwOpts{store: fs}) // jobs channel cap = 100, no background drain
	m.stats = newStatsCollector(fs, "waf:stats:", "n")

	const n = 300
	start := time.Now()
	for i := 0; i < n; i++ {
		rr := doReq(m, "203.0.113.5:1111", "/some/page", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d must still pass when the queue is full: %d", i, rr.Code)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("%d non-blocking sends should be near-instant, took %v (sends must never block)", n, elapsed)
	}
	if len(m.jobs) != 100 {
		t.Fatalf("buffered jobs=%d want 100 (channel capacity)", len(m.jobs))
	}
	if dropped := statCount(m, statDropped); dropped != int64(n-100) {
		t.Fatalf("dropped=%d want %d (every send past capacity drops)", dropped, n-100)
	}
}

// Test 3 — the circuit breaker opens after consecutive failures, skips the dial entirely while
// open (store.Enqueue not called), then half-opens after the cooldown and closes on success.
func TestFlush_CircuitBreaker_OpensSkipsDialHalfOpenCloses(t *testing.T) {
	fs := &fakeStore{enqErr: errors.New("dial tcp 192.0.2.1:6379: i/o timeout")}
	m, _ := testMW(t, mwOpts{store: fs})
	m.stats = newStatsCollector(fs, "waf:stats:", "n")
	m.breaker = newBreaker(3, 40*time.Millisecond)
	job := enqueueJob{ip: "198.51.100.9"}

	for i := 0; i < 3; i++ {
		m.flush(context.Background(), job)
	}
	if !m.breaker.open() {
		t.Fatal("breaker must be open after 3 consecutive failures")
	}
	dialsWhileClosed := fs.enqN

	// While open, flush must short-circuit without dialing.
	m.flush(context.Background(), job)
	m.flush(context.Background(), job)
	if fs.enqN != dialsWhileClosed {
		t.Fatalf("breaker open: store.Enqueue must not be called (was %d, now %d)", dialsWhileClosed, fs.enqN)
	}

	// After the cooldown, let valkey "recover" and allow one half-open probe to close it.
	time.Sleep(55 * time.Millisecond)
	fs.mu.Lock()
	fs.enqErr = nil
	fs.mu.Unlock()
	m.flush(context.Background(), job) // half-open probe → success → closed
	if m.breaker.open() {
		t.Fatal("breaker must close after a successful half-open probe")
	}
	if fs.enqN != dialsWhileClosed+1 {
		t.Fatalf("exactly one half-open probe should have dialed (was %d, now %d)", dialsWhileClosed, fs.enqN)
	}
}

// Test 4 — happy path: with valkey up the background flush XADDs the job and the event fields
// are correct (real IP, method, path, host, ts present).
func TestFlush_HappyPath_XADDsCorrectFields(t *testing.T) {
	fs := &fakeStore{}
	m, _ := testMW(t, mwOpts{store: fs})
	m.stats = newStatsCollector(fs, "waf:stats:", "n")
	m.breaker = newBreaker(3, time.Second)

	job := buildJob(mkReq(http.MethodPost, "/wp-login.php", "victim.example", "sqlmap/1.0"), mustAddr(t, "198.51.100.9"))
	m.flush(context.Background(), job)

	if fs.enqN != 1 {
		t.Fatalf("store.Enqueue calls=%d want 1", fs.enqN)
	}
	want := map[string]string{"ip": "198.51.100.9", "m": "POST", "p": "/wp-login.php", "h": "victim.example", "ua": "sqlmap/1.0"}
	for k, v := range want {
		if got, _ := fs.last[k].(string); got != v {
			t.Errorf("field %q=%q want %q", k, got, v)
		}
	}
	if ts, ok := fs.last["ts"].(int64); !ok || ts <= 0 {
		t.Errorf("ts field missing/invalid: %v", fs.last["ts"])
	}
	if m.breaker.open() {
		t.Fatal("breaker must stay closed on success")
	}
}

// Test 7 — each hot-path action increments exactly the right counter.
func TestCounters_PerActionPaths(t *testing.T) {
	newMW := func(o mwOpts) *wafQueue {
		m, _ := testMW(t, o)
		m.stats = newStatsCollector(&fakeStore{}, "waf:stats:", "n")
		return m
	}

	// pass + enqueue (clean request)
	m := newMW(mwOpts{store: &fakeStore{}})
	doReq(m, "203.0.113.5:1", "/page", nil)
	if statCount(m, statPass) != 1 || statCount(m, statEnqueue) != 1 {
		t.Fatalf("clean: pass=%d enqueue=%d want 1/1", statCount(m, statPass), statCount(m, statEnqueue))
	}

	// whitelist (never enqueued)
	m = newMW(mwOpts{store: &fakeStore{}, whitelist: []string{"203.0.113.0/24"}})
	doReq(m, "203.0.113.5:1", "/page", nil)
	if statCount(m, statWhitelist) != 1 || statCount(m, statPass) != 0 || len(m.jobs) != 0 {
		t.Fatalf("whitelist: whitelist=%d pass=%d jobs=%d want 1/0/0", statCount(m, statWhitelist), statCount(m, statPass), len(m.jobs))
	}

	// scoped (static path, no enqueue)
	m = newMW(mwOpts{store: &fakeStore{}})
	doReq(m, "203.0.113.5:1", "/app.js", nil)
	if statCount(m, statScoped) != 1 || len(m.jobs) != 0 {
		t.Fatalf("scoped: scoped=%d jobs=%d want 1/0", statCount(m, statScoped), len(m.jobs))
	}

	// would-block (shadow + blocklist hit)
	m = newMW(mwOpts{shadow: true, store: &fakeStore{}, blocklist: []string{"203.0.113.5/32"}})
	doReq(m, "203.0.113.5:1", "/page", nil)
	if statCount(m, statWouldBlock) != 1 || statCount(m, statBlock) != 0 {
		t.Fatalf("shadow blocklist: would_block=%d block=%d want 1/0", statCount(m, statWouldBlock), statCount(m, statBlock))
	}

	// block (enforce + blocklist hit)
	m = newMW(mwOpts{shadow: false, store: &fakeStore{}, blocklist: []string{"203.0.113.5/32"}})
	rr := doReq(m, "203.0.113.5:1", "/page", nil)
	if statCount(m, statBlock) != 1 || rr.Code != http.StatusForbidden {
		t.Fatalf("enforce blocklist: block=%d code=%d want 1/403", statCount(m, statBlock), rr.Code)
	}
}

// ---- Benchmarks: hot-path cost with valkey UP vs DOWN must be equal (proving zero I/O). ----

// benchMW builds a middleware with the real background drain running against the given store.
func benchMW(store Store) (*wafQueue, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	nop := zerolog.Nop()
	next, _ := okHandler()
	m := &wafQueue{
		next:         next,
		name:         "bench",
		shadow:       true,
		blockStatus:  403,
		streamKey:    "waf:stream",
		streamMaxLen: 1000000,
		bannedKey:    "waf:banned",
		resolver:     NewRealIPResolver(nil, nil),
		whitelist:    NewMatcher(),
		blocklist:    NewMatcher(),
		scopeSkip:    compileRegexes(DefaultScopeSkip, &nop),
		metrics:      NewMetrics(),
		breaker:      newBreaker(3, 2*time.Second),
		store:        store,
		jobs:         make(chan enqueueJob, 8192),
	}
	m.stats = newStatsCollector(store, "waf:stats:", "bench")
	for i := 0; i < 4; i++ {
		go m.enqueueLoop(ctx)
	}
	return m, cancel
}

func benchServe(b *testing.B, m *wafQueue) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/page", nil)
		req.RemoteAddr = "203.0.113.5:1111"
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
	}
}

// BenchmarkHotPath_ValkeyUp — background drain against an instant in-memory mock.
func BenchmarkHotPath_ValkeyUp(b *testing.B) {
	m, cancel := benchMW(&fakeStore{})
	defer cancel()
	benchServe(b, m)
}

// BenchmarkHotPath_ValkeyDown — background drain against an unroutable valkey. The hot-path
// ns/op must match ValkeyUp: the request goroutine never dials valkey.
func BenchmarkHotPath_ValkeyDown(b *testing.B) {
	m, cancel := benchMW(NewValkeyStore("192.0.2.1:6379", nil, "", "", 0))
	defer cancel()
	benchServe(b, m)
}
