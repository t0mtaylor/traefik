package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// This file implements the read-only /api/waf endpoint for the async WAF (Phase 2).
//
// It is served under the same API router as the rest of the dashboard API, so it inherits the
// dashboard's auth + host (tfmx…) and is never a new public route. It is strictly read-only:
// it issues only read commands against valkey (XLEN, XPENDING, SCARD, SSCAN, GET, PTTL, SCAN)
// and never mutates state. Every failure path is fail-soft: if valkey is unreachable or no WAF
// middleware is configured, it returns a 200 with {"degraded": true, ...} rather than a 500,
// so a valkey outage can never take the dashboard down.
//
// The live valkey state it exposes (all cheaply readable, swarm-wide because the backing store
// is shared):
//   - queue depth (XLEN waf:stream) + worker lag (XPENDING on the consumer group)
//   - active bans (SCARD waf:banned) + the N most recent bans (ip, source, ttl, expiry)
//   - blocklist/whitelist sizes (per-node gauges written by the middleware) + last refresh
//   - per-node + aggregate action counters (waf:stats:<node>:<action>, written by the
//     middleware stats flusher) so the dashboard has live pass/block/enqueue rates
//   - mode (shadow vs enforce) read from the live middleware config
//   - a reserved modsec-health block (optional key, not yet emitted by the Phase-1 worker)

// wafDefaultGroup is the consumer group the waf-worker uses (WAF_GROUP default).
const wafDefaultGroup = "waf-workers"

// wafRecentBansDefault / wafRecentBansMax bound the recent-bans list.
const (
	wafRecentBansDefault = 20
	wafRecentBansMax     = 100
	// wafBanScanCap bounds how many members of waf:banned we SSCAN for the recent list, so the
	// endpoint stays cheap even if the ban set is large.
	wafBanScanCap = 2000
)

// wafReader is the minimal read-only valkey surface /api/waf needs. It is an interface so the
// handler test can substitute a fake (and assert read-only + fail-soft) without a live valkey.
type wafReader interface {
	QueueDepth(ctx context.Context, stream string) (int64, error)
	Pending(ctx context.Context, stream, group string) (int64, error)
	BannedCount(ctx context.Context, bannedKey string) (int64, error)
	RecentBans(ctx context.Context, bannedKey string, limit int) ([]wafBan, error)
	SetCardinality(ctx context.Context, keys []string) (int64, error)
	Get(ctx context.Context, key string) (string, bool, error)
	StatsByNode(ctx context.Context, prefix string) (map[string]*wafNode, error)
	Close() error
}

// wafConn is the valkey connection + key config /api/waf uses, derived from the live WafQueue
// middleware config (or the environment as a fallback).
type wafConn struct {
	addr          string
	sentinels     []string
	master        string
	password      string
	db            int
	streamKey     string
	bannedKey     string
	statsPrefix   string
	group         string
	whitelistKeys []string
	blocklistKeys []string
	mode          string // "shadow" | "enforce" | "unknown"
	middleware    string // middleware name, for display
	found         bool   // a WafQueue middleware was found in the runtime config
}

// ---- JSON response shapes ----

type wafBan struct {
	IP        string `json:"ip"`
	Source    string `json:"source,omitempty"`
	TTL       int64  `json:"ttl"`       // seconds remaining
	ExpiresAt int64  `json:"expiresAt"` // unix millis
}

type wafNode struct {
	Pass          int64 `json:"pass"`
	Whitelist     int64 `json:"whitelist"`
	WouldBlock    int64 `json:"wouldBlock"`
	Block         int64 `json:"block"`
	Scoped        int64 `json:"scoped"`
	Enqueue       int64 `json:"enqueue"`
	FailOpen      int64 `json:"failOpen"`
	Dropped       int64 `json:"dropped"`
	BlocklistSize int64 `json:"blocklistSize"`
	WhitelistSize int64 `json:"whitelistSize"`
	LastRefresh   int64 `json:"lastRefresh,omitempty"` // unix millis
}

type wafQueueInfo struct {
	Depth   int64  `json:"depth"`
	Pending int64  `json:"pending"`
	Stream  string `json:"stream"`
	Group   string `json:"group"`
}

type wafBansInfo struct {
	Active int64    `json:"active"`
	Recent []wafBan `json:"recent"`
}

type wafListsInfo struct {
	BlocklistSize int64    `json:"blocklistSize"`
	WhitelistSize int64    `json:"whitelistSize"`
	BlocklistKeys []string `json:"blocklistKeys,omitempty"`
	WhitelistKeys []string `json:"whitelistKeys,omitempty"`
	LastRefresh   int64    `json:"lastRefresh,omitempty"` // unix millis, most recent across nodes
}

type wafModsecInfo struct {
	Available bool  `json:"available"`
	Healthy   *bool `json:"healthy"`
}

// WAFResponse is the /api/waf payload.
type WAFResponse struct {
	Degraded   bool                `json:"degraded"`
	Reason     string              `json:"reason,omitempty"`
	Timestamp  int64               `json:"timestamp"` // unix millis
	Mode       string              `json:"mode"`
	Middleware string              `json:"middleware,omitempty"`
	Queue      wafQueueInfo        `json:"queue"`
	Bans       wafBansInfo         `json:"bans"`
	Lists      wafListsInfo        `json:"lists"`
	Nodes      map[string]*wafNode `json:"nodes"`
	Totals     wafNode             `json:"totals"`
	Modsec     wafModsecInfo       `json:"modsec"`
}

// getWAF serves GET /api/waf. Read-only, auth-gated (inherits the API router middleware),
// fail-soft.
func (h *Handler) getWAF(rw http.ResponseWriter, request *http.Request) {
	rw.Header().Set("Content-Type", "application/json")

	limit := wafRecentBansDefault
	if v := request.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > wafRecentBansMax {
		limit = wafRecentBansMax
	}

	conn := h.wafConn()
	resp := WAFResponse{
		Timestamp:  time.Now().UnixMilli(),
		Mode:       conn.mode,
		Middleware: conn.middleware,
		Nodes:      map[string]*wafNode{},
		Queue:      wafQueueInfo{Stream: conn.streamKey, Group: conn.group},
		Lists:      wafListsInfo{BlocklistKeys: conn.blocklistKeys, WhitelistKeys: conn.whitelistKeys},
		Modsec:     wafModsecInfo{Available: false},
	}
	if resp.Mode == "" {
		resp.Mode = "unknown"
	}

	reader := h.wafResolveReader(conn)
	if reader == nil {
		resp.Degraded = true
		resp.Reason = "no valkey connection configured for the WAF (no wafQueue middleware and no WAF_VALKEY_ADDR)"
		writeWAF(rw, request, resp)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()

	// Queue depth is the canary read: if it errors, treat the whole store as down (degraded)
	// but still return a 200 so the dashboard renders gracefully.
	depth, err := reader.QueueDepth(ctx, conn.streamKey)
	if err != nil {
		resp.Degraded = true
		resp.Reason = "valkey unreachable: " + err.Error()
		writeWAF(rw, request, resp)
		return
	}
	resp.Queue.Depth = depth

	// Each of the remaining reads is best-effort: a single failure degrades only its own field.
	if pending, err := reader.Pending(ctx, conn.streamKey, conn.group); err == nil {
		resp.Queue.Pending = pending
	}

	if active, err := reader.BannedCount(ctx, conn.bannedKey); err == nil {
		resp.Bans.Active = active
	}
	if recent, err := reader.RecentBans(ctx, conn.bannedKey, limit); err == nil {
		resp.Bans.Recent = recent
	}
	if resp.Bans.Recent == nil {
		resp.Bans.Recent = []wafBan{}
	}

	if n, err := reader.SetCardinality(ctx, conn.blocklistKeys); err == nil {
		resp.Lists.BlocklistSize = n
	}
	if n, err := reader.SetCardinality(ctx, conn.whitelistKeys); err == nil {
		resp.Lists.WhitelistSize = n
	}

	// Per-node + aggregate action counters and gauges.
	if nodes, err := reader.StatsByNode(ctx, conn.statsPrefix); err == nil && nodes != nil {
		resp.Nodes = nodes
		for _, n := range nodes {
			resp.Totals.add(n)
			if n.BlocklistSize > resp.Lists.BlocklistSize {
				resp.Lists.BlocklistSize = n.BlocklistSize
			}
			if n.WhitelistSize > resp.Lists.WhitelistSize {
				resp.Lists.WhitelistSize = n.WhitelistSize
			}
			if n.LastRefresh > resp.Lists.LastRefresh {
				resp.Lists.LastRefresh = n.LastRefresh
			}
		}
	}

	// Optional modsec-health flag (reserved: not yet emitted by the Phase-1 worker).
	if v, ok, err := reader.Get(ctx, "waf:modsec:up"); err == nil && ok {
		resp.Modsec.Available = true
		healthy := v == "1" || strings.EqualFold(v, "true")
		resp.Modsec.Healthy = &healthy
	}

	writeWAF(rw, request, resp)
}

func (n *wafNode) add(o *wafNode) {
	n.Pass += o.Pass
	n.Whitelist += o.Whitelist
	n.WouldBlock += o.WouldBlock
	n.Block += o.Block
	n.Scoped += o.Scoped
	n.Enqueue += o.Enqueue
	n.FailOpen += o.FailOpen
	n.Dropped += o.Dropped
}

func writeWAF(rw http.ResponseWriter, request *http.Request, resp WAFResponse) {
	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		log.Ctx(request.Context()).Error().Err(err).Msg("failed to encode /api/waf response")
	}
}

// wafResolveReader returns the test-injected reader if present, else a lazily-built, cached
// valkey reader for conn. A connection with no address and no sentinels yields nil (degraded).
func (h *Handler) wafResolveReader(conn wafConn) wafReader {
	h.wafMu.Lock()
	defer h.wafMu.Unlock()
	if h.wafStore != nil {
		return h.wafStore
	}
	if conn.addr == "" && len(conn.sentinels) == 0 {
		return nil
	}
	h.wafStore = newValkeyWAFReader(conn)
	return h.wafStore
}

// wafConn derives the valkey + key config from the live WafQueue middleware config, falling
// back to the environment when no such middleware is present in the runtime config.
func (h *Handler) wafConn() wafConn {
	c := wafConn{
		streamKey:   dynamic.WafQueueDefaultStreamKey,
		bannedKey:   dynamic.WafQueueDefaultBannedKey,
		statsPrefix: dynamic.WafQueueDefaultStatsPrefix,
		group:       wafDefaultGroup,
		mode:        "unknown",
	}

	if h.runtimeConfiguration != nil {
		for name, mi := range h.runtimeConfiguration.Middlewares {
			if mi == nil || mi.Middleware == nil || mi.Middleware.WafQueue == nil {
				continue
			}
			w := mi.Middleware.WafQueue
			c.found = true
			c.middleware = name
			c.addr = w.ValkeyAddr
			c.sentinels = w.ValkeySentinels
			c.master = w.ValkeyMaster
			c.password = w.ValkeyPassword
			c.db = w.ValkeyDB
			if w.StreamKey != "" {
				c.streamKey = w.StreamKey
			}
			if w.BannedKey != "" {
				c.bannedKey = w.BannedKey
			}
			if w.StatsPrefix != "" {
				c.statsPrefix = w.StatsPrefix
			}
			c.whitelistKeys = w.WhitelistKeys
			c.blocklistKeys = w.BlocklistKeys
			if w.IsShadow() {
				c.mode = "shadow"
			} else {
				c.mode = "enforce"
			}
			break // first WafQueue middleware wins (external traefik has one)
		}
	}

	// Environment fallback / override for the API's own valkey connection and group. This lets
	// the dashboard reach valkey even on an instance that only proxies (no local middleware),
	// and lets the consumer-group name be set to match the worker.
	if v := os.Getenv("WAF_VALKEY_ADDR"); v != "" {
		c.addr = v
	}
	if v := os.Getenv("WAF_VALKEY_SENTINELS"); v != "" {
		c.sentinels = splitCSVEnv(v)
	}
	if v := os.Getenv("WAF_VALKEY_MASTER"); v != "" {
		c.master = v
	}
	if v := os.Getenv("WAF_VALKEY_PASSWORD"); v != "" {
		c.password = v
	}
	if v := os.Getenv("WAF_API_GROUP"); v != "" {
		c.group = v
	} else if v := os.Getenv("WAF_GROUP"); v != "" {
		c.group = v
	}
	return c
}

func splitCSVEnv(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- valkey-backed wafReader ----

type valkeyWAFReader struct {
	c redis.UniversalClient
}

func newValkeyWAFReader(conn wafConn) *valkeyWAFReader {
	opts := &redis.UniversalOptions{Password: conn.password, DB: conn.db}
	if len(conn.sentinels) > 0 {
		opts.Addrs = conn.sentinels
		opts.MasterName = conn.master
	} else {
		opts.Addrs = []string{conn.addr}
	}
	return &valkeyWAFReader{c: redis.NewUniversalClient(opts)}
}

func (r *valkeyWAFReader) QueueDepth(ctx context.Context, stream string) (int64, error) {
	n, err := r.c.XLen(ctx, stream).Result()
	if err == redis.Nil {
		return 0, nil
	}
	return n, err
}

func (r *valkeyWAFReader) Pending(ctx context.Context, stream, group string) (int64, error) {
	p, err := r.c.XPending(ctx, stream, group).Result()
	if err != nil {
		// NOGROUP (worker never started) / empty stream ⇒ no pending, not an error for the UI.
		if err == redis.Nil || strings.Contains(err.Error(), "NOGROUP") {
			return 0, nil
		}
		return 0, err
	}
	return p.Count, nil
}

func (r *valkeyWAFReader) BannedCount(ctx context.Context, bannedKey string) (int64, error) {
	n, err := r.c.SCard(ctx, bannedKey).Result()
	if err == redis.Nil {
		return 0, nil
	}
	return n, err
}

// RecentBans SSCANs up to wafBanScanCap members of the ban set, reads each one's reason (GET)
// and remaining TTL (PTTL) in a pipeline, and returns the N with the most TTL remaining — i.e.
// the most recently banned, since every ban shares the same TTL window.
func (r *valkeyWAFReader) RecentBans(ctx context.Context, bannedKey string, limit int) ([]wafBan, error) {
	var members []string
	var cursor uint64
	for len(members) < wafBanScanCap {
		keys, next, err := r.c.SScan(ctx, bannedKey, cursor, "", 512).Result()
		if err != nil {
			if err == redis.Nil {
				break
			}
			return nil, err
		}
		members = append(members, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if len(members) == 0 {
		return []wafBan{}, nil
	}

	pipe := r.c.Pipeline()
	ttlCmds := make([]*redis.DurationCmd, len(members))
	reasonCmds := make([]*redis.StringCmd, len(members))
	for i, ip := range members {
		ttlCmds[i] = pipe.PTTL(ctx, bannedKey+":"+ip)
		reasonCmds[i] = pipe.Get(ctx, bannedKey+":"+ip)
	}
	// Ignore the pipeline error: individual command results are checked below, and a missing
	// per-IP marker (redis.Nil) is expected for an expired/pruned ban.
	_, _ = pipe.Exec(ctx)

	now := time.Now().UnixMilli()
	bans := make([]wafBan, 0, len(members))
	for i, ip := range members {
		ttl, err := ttlCmds[i].Result()
		if err != nil || ttl <= 0 {
			continue // no live marker (expired) — skip
		}
		reason, _ := reasonCmds[i].Result()
		bans = append(bans, wafBan{
			IP:        ip,
			Source:    reason,
			TTL:       int64(ttl / time.Second),
			ExpiresAt: now + ttl.Milliseconds(),
		})
	}
	sort.Slice(bans, func(i, j int) bool { return bans[i].TTL > bans[j].TTL })
	if len(bans) > limit {
		bans = bans[:limit]
	}
	return bans, nil
}

func (r *valkeyWAFReader) SetCardinality(ctx context.Context, keys []string) (int64, error) {
	var total int64
	for _, k := range keys {
		n, err := r.c.SCard(ctx, k).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return total, err
		}
		total += n
	}
	return total, nil
}

func (r *valkeyWAFReader) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.c.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// StatsByNode SCANs <prefix>* and folds every waf:stats:<node>:<field> key into a per-node
// record. Values are read in a pipeline. Unknown fields are ignored.
func (r *valkeyWAFReader) StatsByNode(ctx context.Context, prefix string) (map[string]*wafNode, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := r.c.Scan(ctx, cursor, prefix+"*", 512).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if len(keys) == 0 {
		return map[string]*wafNode{}, nil
	}

	pipe := r.c.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.Get(ctx, k)
	}
	_, _ = pipe.Exec(ctx)

	nodes := map[string]*wafNode{}
	for i, k := range keys {
		suffix := strings.TrimPrefix(k, prefix)
		idx := strings.LastIndex(suffix, ":")
		if idx < 0 {
			continue // a global key like waf:stats:requests — not per-node, ignore
		}
		node, field := suffix[:idx], suffix[idx+1:]
		if node == "" {
			continue
		}
		val, err := cmds[i].Result()
		if err != nil {
			continue
		}
		v, _ := strconv.ParseInt(val, 10, 64)
		n := nodes[node]
		if n == nil {
			n = &wafNode{}
			nodes[node] = n
		}
		switch field {
		case "pass":
			n.Pass = v
		case "whitelist":
			n.Whitelist = v
		case "would_block":
			n.WouldBlock = v
		case "block":
			n.Block = v
		case "scoped":
			n.Scoped = v
		case "enqueue":
			n.Enqueue = v
		case "failopen":
			n.FailOpen = v
		case "dropped":
			n.Dropped = v
		case "blocklist_size":
			n.BlocklistSize = v
		case "whitelist_size":
			n.WhitelistSize = v
		case "refresh_ts":
			n.LastRefresh = v
		}
	}
	return nodes, nil
}

func (r *valkeyWAFReader) Close() error { return r.c.Close() }

// ensure the valkey reader satisfies the interface.
var _ wafReader = (*valkeyWAFReader)(nil)
