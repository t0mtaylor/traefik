package wafqueue

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// ---- fakes ----

type fakeStore struct {
	mu        sync.Mutex
	enqErr    error
	memErr    error
	last      map[string]any
	enqN      int
	members   []string
	closed    bool
	flushIncr map[string]int64
	flushSet  map[string]int64
	flushErr  error

	healthKey string
	healthVal string
	healthErr error
}

func (f *fakeStore) SetHealth(_ context.Context, key, val string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthErr != nil {
		return f.healthErr
	}
	f.healthKey = key
	f.healthVal = val
	return nil
}

func (f *fakeStore) Enqueue(_ context.Context, _ string, _ int64, fields map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = fields
	f.enqN++
	return f.enqErr
}

func (f *fakeStore) Members(_ context.Context, _ []string) ([]string, error) {
	return f.members, f.memErr
}

func (f *fakeStore) QueueDepth(_ context.Context, _ string) (int64, error) { return 0, nil }

func (f *fakeStore) Close() error { f.closed = true; return nil }

func (f *fakeStore) FlushStats(_ context.Context, incr map[string]int64, set map[string]int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flushErr != nil {
		return f.flushErr
	}
	if f.flushIncr == nil {
		f.flushIncr = map[string]int64{}
	}
	for k, v := range incr {
		f.flushIncr[k] += v
	}
	f.flushSet = set
	return nil
}

// hijackableRecorder lets us exercise the 444/drop path.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
	conn     *fakeConn
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	h.conn = &fakeConn{}
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

type fakeConn struct {
	closed bool
	net.Conn
}

func (c *fakeConn) Close() error { c.closed = true; return nil }

// ---- helpers ----

func okHandler() (http.Handler, *bool) {
	called := new(bool)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}), called
}

type mwOpts struct {
	shadow    bool
	block     int
	trusted   []string
	headers   []string
	whitelist []string
	blocklist []string
	store     Store
}

func testMW(t *testing.T, o mwOpts) (*wafQueue, *bool) {
	t.Helper()
	nop := zerolog.Nop()
	next, called := okHandler()
	block := o.block
	if block == 0 {
		block = 403
	}
	m := &wafQueue{
		next:         next,
		name:         "test",
		shadow:       o.shadow,
		blockStatus:  block,
		streamKey:    "waf:stream",
		streamMaxLen: 1000,
		bannedKey:    "waf:banned",
		resolver:     NewRealIPResolver(o.headers, o.trusted),
		whitelist:    NewMatcher(),
		blocklist:    NewMatcher(),
		scopeSkip:    compileRegexes(DefaultScopeSkip, &nop),
		metrics:      NewMetrics(),
		store:        o.store,
		jobs:         make(chan enqueueJob, 100),
	}
	if len(o.whitelist) > 0 {
		m.whitelist.Swap(BuildTrie(o.whitelist))
	}
	if len(o.blocklist) > 0 {
		m.blocklist.Swap(BuildTrie(o.blocklist))
	}
	return m, called
}

func doReq(m *wafQueue, remoteAddr, path string, headers map[string]string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com"+path, nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	return rr
}

// ---- tests ----

func TestServeHTTP_CleanRequest_PassesAndEnqueues(t *testing.T) {
	fs := &fakeStore{}
	m, called := testMW(t, mwOpts{store: fs})
	rr := doReq(m, "203.0.113.5:1111", "/some/page", nil)
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("clean request should pass: code=%d called=%v", rr.Code, *called)
	}
	if len(m.jobs) != 1 {
		t.Fatalf("clean request should enqueue exactly one job, got %d", len(m.jobs))
	}
}

func TestEnqueueJobShape(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://x/wp-login.php?a=b", nil)
	req.Header.Set("X-Forwarded-Host", "victim.example")
	req.Header.Set("User-Agent", "sqlmap/1.0")
	req.Header.Set("X-Request-Id", "req-123")
	addr := mustAddr(t, "198.51.100.9")
	fields := jobFields(buildJob(req, addr))
	want := map[string]string{"ip": "198.51.100.9", "m": "POST", "p": "/wp-login.php", "h": "victim.example", "ua": "sqlmap/1.0", "rid": "req-123"}
	for k, v := range want {
		if got, _ := fields[k].(string); got != v {
			t.Errorf("field %q = %q, want %q", k, got, v)
		}
	}
	if _, ok := fields["ts"].(int64); !ok {
		t.Errorf("ts must be int64, got %T", fields["ts"])
	}
}

func TestFlush_FailOpenOnValkeyDown(t *testing.T) {
	fs := &fakeStore{enqErr: errors.New("connection refused")}
	m, _ := testMW(t, mwOpts{store: fs})
	m.flush(context.Background(), buildJob(httptest.NewRequest(http.MethodGet, "/", nil), mustAddr(t, "1.1.1.1")))
	if got := testutil.ToFloat64(m.metrics.FailOpen.WithLabelValues(ReasonValkey)); got != 1 {
		t.Fatalf("failopen(valkey) = %v, want 1", got)
	}
}

func TestFlush_NilStoreFailsOpen(t *testing.T) {
	m, _ := testMW(t, mwOpts{store: nil})
	m.flush(context.Background(), buildJob(httptest.NewRequest(http.MethodGet, "/", nil), mustAddr(t, "1.1.1.1")))
	if got := testutil.ToFloat64(m.metrics.FailOpen.WithLabelValues(ReasonValkey)); got != 1 {
		t.Fatalf("nil store should fail open, failopen(valkey)=%v", got)
	}
}

func TestServeHTTP_WhitelistBeatsBlocklist(t *testing.T) {
	// Same IP in both lists; whitelist must win even under enforcement.
	m, called := testMW(t, mwOpts{
		shadow:    false,
		whitelist: []string{"198.51.100.0/24"},
		blocklist: []string{"198.51.100.0/24"},
	})
	rr := doReq(m, "198.51.100.9:2222", "/admin", nil)
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("whitelist must beat blocklist: code=%d called=%v", rr.Code, *called)
	}
	if got := testutil.ToFloat64(m.metrics.Requests.WithLabelValues(ActionWhitelist)); got != 1 {
		t.Errorf("whitelist action not recorded: %v", got)
	}
}

func TestServeHTTP_BlocklistBlocks_Enforce(t *testing.T) {
	m, called := testMW(t, mwOpts{shadow: false, block: 403, blocklist: []string{"45.9.0.0/16"}})
	rr := doReq(m, "45.9.1.2:3333", "/", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("banned IP should get 403, got %d", rr.Code)
	}
	if *called {
		t.Fatal("next must NOT be called for a blocked request")
	}
}

func TestServeHTTP_Shadow_NeverBlocks(t *testing.T) {
	m, called := testMW(t, mwOpts{shadow: true, blocklist: []string{"45.9.0.0/16"}})
	rr := doReq(m, "45.9.1.2:3333", "/", nil)
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("shadow must never block: code=%d called=%v", rr.Code, *called)
	}
	if got := testutil.ToFloat64(m.metrics.Requests.WithLabelValues(ActionWouldBlock)); got != 1 {
		t.Errorf("would_block not recorded: %v", got)
	}
	if got := testutil.ToFloat64(m.metrics.Requests.WithLabelValues(ActionBlock)); got != 0 {
		t.Errorf("shadow must not record a real block: %v", got)
	}
}

func TestServeHTTP_Block444_Drop(t *testing.T) {
	m, called := testMW(t, mwOpts{shadow: false, block: 444, blocklist: []string{"45.9.0.0/16"}})
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "45.9.1.2:3333"
	rr := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	m.ServeHTTP(rr, req)
	if !rr.hijacked || rr.conn == nil || !rr.conn.closed {
		t.Fatalf("444 should hijack and close the connection: hijacked=%v", rr.hijacked)
	}
	if *called {
		t.Fatal("next must not be called on a 444 drop")
	}
}

func TestServeHTTP_Block444_FallbackWhenNoHijack(t *testing.T) {
	m, _ := testMW(t, mwOpts{shadow: false, block: 444, blocklist: []string{"45.9.0.0/16"}})
	rr := doReq(m, "45.9.1.2:3333", "/", nil) // plain recorder is not a Hijacker
	if rr.Code != http.StatusForbidden {
		t.Fatalf("444 without hijack should fall back to 403, got %d", rr.Code)
	}
}

func TestServeHTTP_ScopeSkip_NoEnqueue(t *testing.T) {
	fs := &fakeStore{}
	m, called := testMW(t, mwOpts{store: fs})
	for _, p := range []string{"/stream/seg123.ts", "/audio/x.aac", "/live/index.m3u8", "/.well-known/acme-challenge/x", "/autodiscover/autodiscover.xml", "/app.js"} {
		rr := doReq(m, "203.0.113.5:1111", p, nil)
		if rr.Code != http.StatusOK || !*called {
			t.Fatalf("scoped path %q should pass", p)
		}
		*called = false
	}
	if len(m.jobs) != 0 {
		t.Fatalf("scoped paths must NOT enqueue, got %d jobs", len(m.jobs))
	}
}

func TestServeHTTP_BlocklistBeforeScope(t *testing.T) {
	// A banned IP hitting a static/stream path is still blocked (blocklist precedes scope).
	m, called := testMW(t, mwOpts{shadow: false, block: 403, blocklist: []string{"45.9.0.0/16"}})
	rr := doReq(m, "45.9.1.2:3333", "/stream/seg.ts", nil)
	if rr.Code != http.StatusForbidden || *called {
		t.Fatalf("banned IP on a static path should still be blocked: code=%d called=%v", rr.Code, *called)
	}
}

// ---- regression guards (mirror the fleet FP fixes) ----

func TestRegression_CFEdgeNeverBlocked(t *testing.T) {
	// A Cloudflare edge CIDR in the whitelist must beat a blocklist hit.
	m, called := testMW(t, mwOpts{
		shadow:    false,
		whitelist: []string{"104.16.0.0/13"}, // Cloudflare
		blocklist: []string{"104.16.0.0/13"},
	})
	rr := doReq(m, "104.16.5.5:1234", "/", nil)
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("CF edge must never be blocked: code=%d", rr.Code)
	}
}

func TestRegression_MobileCGNATWhitelisted(t *testing.T) {
	m, called := testMW(t, mwOpts{
		shadow:    false,
		whitelist: []string{"100.64.0.0/10"}, // CGNAT
		blocklist: []string{"100.64.0.0/10"},
	})
	rr := doReq(m, "100.64.9.9:1234", "/", nil)
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("mobile/CGNAT must be whitelisted: code=%d", rr.Code)
	}
}

func TestRegression_BanOnRealIPNotEdge(t *testing.T) {
	// Request arrives via a trusted internal proxy; the real client (CF-Connecting-IP) is
	// banned. We must block the real client, keying on the real IP and not the proxy.
	m, called := testMW(t, mwOpts{
		shadow:    false,
		block:     403,
		trusted:   []string{"10.0.0.0/8"},
		blocklist: []string{"45.9.1.2/32"}, // the real client
	})
	rr := doReq(m, "10.106.0.33:5555", "/", map[string]string{"CF-Connecting-IP": "45.9.1.2"})
	if rr.Code != http.StatusForbidden || *called {
		t.Fatalf("should block the real client behind the proxy: code=%d", rr.Code)
	}
}

func TestRegression_EdgeIPInBlocklistDoesNotBlockClient(t *testing.T) {
	// The proxy/edge IP is (wrongly) in the blocklist, but the real client is clean — we must
	// NOT block, because we key on the real client IP, never the edge.
	m, called := testMW(t, mwOpts{
		shadow:    false,
		trusted:   []string{"10.0.0.0/8"},
		blocklist: []string{"10.106.0.33/32"}, // the proxy itself
	})
	rr := doReq(m, "10.106.0.33:5555", "/", map[string]string{"CF-Connecting-IP": "203.0.113.50"})
	if rr.Code != http.StatusOK || !*called {
		t.Fatalf("a banned edge IP must not block a clean client: code=%d", rr.Code)
	}
}

func TestIsShadowConfig(t *testing.T) {
	// Decoder-independent default: nil ⇒ shadow (safe). This is the Phase-1 safety guarantee.
	if !(&dynamic.WafQueue{Shadow: nil}).IsShadow() {
		t.Error("nil Shadow must read as shadow=true (safe default)")
	}
	tru, fal := true, false
	if !(&dynamic.WafQueue{Shadow: &tru}).IsShadow() {
		t.Error("*true must be shadow")
	}
	if (&dynamic.WafQueue{Shadow: &fal}).IsShadow() {
		t.Error("*false must be enforce")
	}
}

// TestRefreshOnce_ReportsTrueTrieSizes guards the dashboard trie-size fix: refreshOnce must
// publish the ACTUAL live trie lengths as the whitelist_size/blocklist_size gauges, even when
// no valkey whitelist/blocklist keys are configured and the whitelist is only the
// TrustedProxies seed. The old code only set the gauge inside `if len(fetched) > 0`, so a
// seeded-but-not-valkey-backed whitelist reported 0 — which read as an empty whitelist.
func TestRefreshOnce_ReportsTrueTrieSizes(t *testing.T) {
	fs := &fakeStore{} // Members returns empty: exercises the no-valkey-keys path.
	m, _ := testMW(t, mwOpts{shadow: true, store: fs})
	// Seed the whitelist exactly as New() does from TrustedProxies (the fleet whitelist).
	m.whitelist.Swap(BuildTrie([]string{"104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22"}))
	wantWL := int64(m.whitelist.Len())
	if wantWL == 0 {
		t.Fatal("precondition: seeded whitelist trie must be non-empty")
	}
	m.stats = newStatsCollector(fs, "waf:stats:", "mxtest")

	m.refreshOnce(context.Background())
	m.stats.flush(context.Background())

	if got := fs.flushSet["waf:stats:mxtest:whitelist_size"]; got != wantWL {
		t.Fatalf("whitelist_size=%d want %d (true trie size, not the fetched set size)", got, wantWL)
	}
	// Blocklist is legitimately empty in shadow until the worker ban-feed is loaded.
	if got := fs.flushSet["waf:stats:mxtest:blocklist_size"]; got != 0 {
		t.Fatalf("blocklist_size=%d want 0 (no feed loaded in shadow)", got)
	}
}
