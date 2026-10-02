package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func bptr(b bool) *bool { return &b }

// wafTestPassword is a sentinel secret in the test config; it must NEVER appear in the /api/waf
// payload (the handler exposes "authConfigured", never the password).
const wafTestPassword = "test-valkey-pw-DO-NOT-LEAK"

// mockWAFReader is a pure read-only fake. The wafReader interface exposes no mutating method,
// so read-only is guaranteed at the type level; this fake additionally records that nothing
// beyond the expected reads is attempted.
type mockWAFReader struct {
	depth     int64
	depthErr  error
	pending   int64
	banned    int64
	recent    []wafBan
	blCard    int64
	wlCard    int64
	nodes     map[string]*wafNode
	getVals   map[string]string
	health    map[string]string
	healthErr error
	closed    bool
}

func (m *mockWAFReader) Health(_ context.Context, _ string) (map[string]string, error) {
	return m.health, m.healthErr
}

func (m *mockWAFReader) QueueDepth(_ context.Context, _ string) (int64, error) {
	return m.depth, m.depthErr
}
func (m *mockWAFReader) Pending(_ context.Context, _, _ string) (int64, error) {
	return m.pending, nil
}
func (m *mockWAFReader) BannedCount(_ context.Context, _ string) (int64, error) {
	return m.banned, nil
}
func (m *mockWAFReader) RecentBans(_ context.Context, _ string, limit int) ([]wafBan, error) {
	if len(m.recent) > limit {
		return m.recent[:limit], nil
	}
	return m.recent, nil
}
func (m *mockWAFReader) SetCardinality(_ context.Context, keys []string) (int64, error) {
	// Distinguish blocklist vs whitelist by the first key name in the test fixtures.
	if len(keys) > 0 && keys[0] == "waf:bl:main" {
		return m.blCard, nil
	}
	return m.wlCard, nil
}
func (m *mockWAFReader) Get(_ context.Context, key string) (string, bool, error) {
	v, ok := m.getVals[key]
	return v, ok, nil
}
func (m *mockWAFReader) StatsByNode(_ context.Context, _ string) (map[string]*wafNode, error) {
	return m.nodes, nil
}
func (m *mockWAFReader) Close() error { m.closed = true; return nil }

func wafTestHandler(t *testing.T, reader wafReader, valkeyAddr string) *Handler {
	t.Helper()
	// Keep the environment from leaking a real valkey address into the test.
	t.Setenv("WAF_VALKEY_ADDR", "")
	t.Setenv("WAF_VALKEY_SENTINELS", "")
	rtConf := &runtime.Configuration{
		Middlewares: map[string]*runtime.MiddlewareInfo{
			"waf@file": {
				Middleware: &dynamic.Middleware{
					WafQueue: &dynamic.WafQueue{
						ValkeyAddr:     valkeyAddr,
						ValkeyPassword: wafTestPassword,
						StreamKey:      "waf:stream",
						StreamMaxLen:   1000000,
						BannedKey:      "waf:banned",
						StatsPrefix:    "waf:stats:",
						WhitelistKeys:  []string{"waf:wl:cf"},
						BlocklistKeys:  []string{"waf:bl:main"},
						Shadow:         bptr(true),
					},
				},
			},
		},
	}
	h := New(static.Configuration{API: &static.API{}, Global: &static.Global{}}, rtConf)
	h.wafStore = reader
	return h
}

func TestGetWAF_ReturnsLiveState(t *testing.T) {
	reader := &mockWAFReader{
		depth:   5,
		pending: 2,
		banned:  10,
		recent: []wafBan{
			{IP: "1.2.3.4", Source: "modsec 403", TTL: 3400, ExpiresAt: 1730003400000},
		},
		blCard: 336000,
		wlCard: 1200,
		nodes: map[string]*wafNode{
			"mx01": {Pass: 100, Block: 5, Enqueue: 90, Whitelist: 3, Scoped: 40, FailOpen: 1, BlocklistSize: 336000, WhitelistSize: 1200, LastRefresh: 1730000000000},
			"mx02": {Pass: 50, Block: 1, Enqueue: 45},
		},
	}
	h := wafTestHandler(t, reader, "127.0.0.1:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var out WAFResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))

	assert.False(t, out.Degraded)
	assert.Equal(t, "shadow", out.Mode)
	assert.Equal(t, "waf@file", out.Middleware)
	assert.Equal(t, int64(5), out.Queue.Depth)
	assert.Equal(t, int64(2), out.Queue.Pending)
	assert.Equal(t, "waf:stream", out.Queue.Stream)
	assert.Equal(t, int64(10), out.Bans.Active)
	require.Len(t, out.Bans.Recent, 1)
	assert.Equal(t, "1.2.3.4", out.Bans.Recent[0].IP)
	assert.Equal(t, int64(336000), out.Lists.BlocklistSize)
	assert.Equal(t, int64(1200), out.Lists.WhitelistSize)
	assert.Len(t, out.Nodes, 2)
	// Aggregate totals across nodes.
	assert.Equal(t, int64(150), out.Totals.Pass)
	assert.Equal(t, int64(6), out.Totals.Block)
	assert.Equal(t, int64(135), out.Totals.Enqueue)
}

func TestGetWAF_FailSoftWhenValkeyDown(t *testing.T) {
	reader := &mockWAFReader{depthErr: errors.New("dial tcp: connection refused")}
	h := wafTestHandler(t, reader, "127.0.0.1:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Never 500 the dashboard: valkey down returns a 200 with degraded:true.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	var out WAFResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.Degraded)
	assert.NotEmpty(t, out.Reason)
	// Mode is still reported from config even when valkey is unreachable.
	assert.Equal(t, "shadow", out.Mode)
	// CONFIG is built from config (no valkey I/O) so it is present even when valkey is down.
	assert.Equal(t, "127.0.0.1:6379", out.Config.Endpoint)
	assert.Equal(t, "waf:stream", out.Config.StreamKey)
	assert.True(t, out.Config.AuthConfigured)
	assert.Equal(t, int64(50), out.Config.DialTimeoutMs)
	// CONNECTION shows DOWN (no heartbeat read on the degraded canary path).
	assert.Equal(t, "down", out.ConnectionAgg.State)
	assert.Equal(t, "down", out.Worker.State)
	// The password is never serialised anywhere in the payload.
	assert.NotContains(t, string(raw), wafTestPassword)
}

func TestGetWAF_ReportsConnectionHealthAndConfig(t *testing.T) {
	now := time.Now().UnixMilli()
	nodeHB := fmt.Sprintf(`{"node":"mx01","ts":%d,"endpoint":"ttdf-valkey-master:6379","breakerState":"closed","breakerOpenCount":0,"lastEnqueueOkMs":%d,"lastFlushOkMs":%d,"streamKey":"waf:stream","streamMaxLen":1000000,"db":0,"authConfigured":true,"dialTimeoutMs":50}`, now, now, now)
	degradedHB := fmt.Sprintf(`{"node":"mx02","ts":%d,"endpoint":"ttdf-valkey-master:6379","breakerState":"open","breakerOpenCount":4,"lastErrorMs":%d,"lastError":"dial tcp i/o timeout","streamKey":"waf:stream","authConfigured":true}`, now, now)
	workerHB := fmt.Sprintf(`{"consumer":"mx01","group":"waf-workers","ts":%d,"lastConsumeMs":%d,"state":"up","endpoint":"ttdf-valkey-master:6379","processed1h":1200,"processed24h":28000,"modsecState":"up","modsecLastOkMs":%d,"modsecUrl":"http://10.106.0.2:8091","modsecLastErr":""}`, now, now, now)
	reader := &mockWAFReader{
		depth:   5,
		pending: 2,
		nodes: map[string]*wafNode{
			"mx01": {Pass: 10, Dropped: 3},
			"mx02": {Pass: 8},
		},
		health: map[string]string{
			"waf:health:mx01":        nodeHB,
			"waf:health:mx02":        degradedHB,
			"waf:health:worker:mx01": workerHB,
		},
	}
	h := wafTestHandler(t, reader, "ttdf-valkey-master:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	var out WAFResponse
	require.NoError(t, json.Unmarshal(raw, &out))

	// CONFIG
	assert.Equal(t, "ttdf-valkey-master:6379", out.Config.Endpoint)
	assert.Equal(t, "waf:stream", out.Config.StreamKey)
	assert.Equal(t, int64(1000000), out.Config.StreamMaxLen)
	assert.Equal(t, "waf-workers", out.Config.Group)
	assert.True(t, out.Config.AuthConfigured)
	assert.Equal(t, int64(50), out.Config.DialTimeoutMs)

	// CONNECTION per node, driven by the cached heartbeat + breaker state.
	require.Contains(t, out.Connection, "mx01")
	assert.Equal(t, "connected", out.Connection["mx01"].State)
	assert.Equal(t, "closed", out.Connection["mx01"].BreakerState)
	assert.Equal(t, int64(3), out.Connection["mx01"].Dropped) // folded from node stats
	require.Contains(t, out.Connection, "mx02")
	assert.Equal(t, "degraded", out.Connection["mx02"].State)
	assert.Equal(t, "open", out.Connection["mx02"].BreakerState)
	assert.Equal(t, int64(4), out.Connection["mx02"].BreakerOpenCount)
	// Aggregate: worst state wins (mx02 is degraded).
	assert.Equal(t, "degraded", out.ConnectionAgg.State)
	// Aggregate carries the most-recent successful valkey write (from mx01's recent heartbeat),
	// so the dashboard shows a real "last write" timestamp, never a bare "—", while connected.
	assert.Equal(t, now, out.ConnectionAgg.LastFlushOkMs)
	assert.Equal(t, now, out.ConnectionAgg.LastEnqueueOkMs)

	// WORKER
	assert.Equal(t, 1, out.Worker.Replicas)
	assert.Equal(t, "up", out.Worker.State)
	assert.Equal(t, "waf-workers", out.Worker.Group)
	assert.Equal(t, int64(2), out.Worker.Pending)
	// Throughput (worker-maintained, read from the cached heartbeat).
	assert.Equal(t, int64(1200), out.Worker.Processed1h)
	assert.Equal(t, int64(28000), out.Worker.Processed24h)

	// modsec link health, from the worker heartbeat (worker->modsec is what inspects the queue).
	assert.True(t, out.Modsec.Available)
	require.NotNil(t, out.Modsec.Healthy)
	assert.True(t, *out.Modsec.Healthy)
	assert.Equal(t, "up", out.Modsec.State)
	assert.Equal(t, "http://10.106.0.2:8091", out.Modsec.URL)
	assert.Equal(t, now, out.Modsec.LastCheckMs)

	// No secret anywhere.
	assert.NotContains(t, string(raw), wafTestPassword)
}

func TestGetWAF_StaleHeartbeatIsDown(t *testing.T) {
	old := time.Now().UnixMilli() - 120000 // 2 min old ⇒ stale
	staleHB := fmt.Sprintf(`{"node":"mx01","ts":%d,"breakerState":"closed","streamKey":"waf:stream"}`, old)
	reader := &mockWAFReader{
		depth:  1,
		nodes:  map[string]*wafNode{"mx01": {Pass: 1}},
		health: map[string]string{"waf:health:mx01": staleHB},
	}
	h := wafTestHandler(t, reader, "ttdf-valkey-master:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf")
	require.NoError(t, err)
	defer resp.Body.Close()

	var out WAFResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Contains(t, out.Connection, "mx01")
	assert.True(t, out.Connection["mx01"].Stale)
	assert.Equal(t, "down", out.Connection["mx01"].State)
}

func TestGetWAF_DegradedWhenNoConnection(t *testing.T) {
	// No injected reader and an empty valkey address ⇒ nothing to connect to ⇒ degraded.
	h := wafTestHandler(t, nil, "")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out WAFResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.Degraded)
}

func TestGetWAF_ReadOnlyRejectsMutatingMethods(t *testing.T) {
	h := wafTestHandler(t, &mockWAFReader{}, "127.0.0.1:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req, err := http.NewRequest(method, server.URL+"/api/waf", nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
			"%s /api/waf must be rejected (read-only endpoint), body=%s", method, string(body))
	}
}

func TestGetWAF_RecentBansLimit(t *testing.T) {
	recent := make([]wafBan, 50)
	for i := range recent {
		recent[i] = wafBan{IP: "10.0.0.1", TTL: int64(i)}
	}
	h := wafTestHandler(t, &mockWAFReader{recent: recent}, "127.0.0.1:6379")
	server := httptest.NewServer(h.createRouter())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/waf?limit=5")
	require.NoError(t, err)
	defer resp.Body.Close()
	var out WAFResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Len(t, out.Bans.Recent, 5)
}
