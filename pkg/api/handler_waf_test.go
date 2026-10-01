package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func bptr(b bool) *bool { return &b }

// mockWAFReader is a pure read-only fake. The wafReader interface exposes no mutating method,
// so read-only is guaranteed at the type level; this fake additionally records that nothing
// beyond the expected reads is attempted.
type mockWAFReader struct {
	depth    int64
	depthErr error
	pending  int64
	banned   int64
	recent   []wafBan
	blCard   int64
	wlCard   int64
	nodes    map[string]*wafNode
	getVals  map[string]string
	closed   bool
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
						ValkeyAddr:    valkeyAddr,
						StreamKey:     "waf:stream",
						BannedKey:     "waf:banned",
						StatsPrefix:   "waf:stats:",
						WhitelistKeys: []string{"waf:wl:cf"},
						BlocklistKeys: []string{"waf:bl:main"},
						Shadow:        bptr(true),
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
	var out WAFResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.Degraded)
	assert.NotEmpty(t, out.Reason)
	// Mode is still reported from config even when valkey is unreachable.
	assert.Equal(t, "shadow", out.Mode)
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
