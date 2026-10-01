// Package wafqueue implements the async WAF hot-path middleware for the traefik fork.
//
// The middleware resolves the real client IP, checks an in-memory whitelist and blocklist
// CIDR trie, enqueues a compact inspection job onto a valkey stream, and passes the request to
// the backend immediately. Inspection happens out-of-band in the waf-worker service, keeping
// modsec off the request critical path.
//
// Every step fails OPEN: on any error (valkey down, resolver ambiguity, matcher unavailable)
// the request is passed to the backend, never blocked. The middleware defaults to shadow
// (observe-only) mode, in which it classifies, enqueues and logs "would-block" but never
// actually blocks — so even if deployed before enforcement is intended, it cannot take traffic
// down. See DESIGN.md at the repo root for the full architecture.
package wafqueue

import (
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
)

const typeName = "WafQueue"

// DefaultScopeSkip are the built-in path patterns whose requests are passed without enqueue
// (but still subject to the blocklist). These mirror the fleet FP fixes: static assets,
// HLS/stream segments, health probes, well-known, and mail-autodiscovery.
var DefaultScopeSkip = []string{
	`\.(?:ts|aac|m3u8|mp3|ogg|js|css|png|jpe?g|gif|svg|ico|woff2?|map)(?:$|\?)`,
	`^/(?:health|healthz|ping|status|metrics)/?$`,
	`^/\.well-known/`,
	`(?i)^/(?:autodiscover|autoconfig)`,
}

// enqueueJob is the compact job pushed to the stream.
type enqueueJob struct {
	ip     string
	method string
	path   string
	host   string
	ua     string
	ts     int64
	rid    string
}

type wafQueue struct {
	next http.Handler
	name string

	shadow      bool
	blockStatus int

	streamKey    string
	streamMaxLen int64
	bannedKey    string
	whitelistKey []string
	blocklistKey []string

	resolver  *RealIPResolver
	whitelist *Matcher
	blocklist *Matcher
	scopeSkip []*regexp.Regexp
	inline    []*regexp.Regexp

	store   Store
	metrics *Metrics
	stats   *statsCollector

	jobs chan enqueueJob
}

// New builds the async WAF middleware. It never returns an error for a recoverable
// misconfiguration (bad regex is skipped with a warning) — the middleware must be impossible
// to turn into an outage.
func New(ctx context.Context, next http.Handler, config dynamic.WafQueue, name string) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)

	blockStatus := config.BlockStatus
	if blockStatus == 0 {
		blockStatus = dynamic.WafQueueDefaultBlockStatus
	}
	streamKey := config.StreamKey
	if streamKey == "" {
		streamKey = dynamic.WafQueueDefaultStreamKey
	}
	bannedKey := config.BannedKey
	if bannedKey == "" {
		bannedKey = dynamic.WafQueueDefaultBannedKey
	}
	streamMaxLen := config.StreamMaxLen
	if streamMaxLen == 0 {
		streamMaxLen = dynamic.WafQueueDefaultStreamMaxLen
	}
	refresh := time.Duration(config.RefreshInterval)
	if refresh <= 0 {
		refresh = 60 * time.Second
	}

	scopeSrc := config.ScopeSkip
	if len(scopeSrc) == 0 {
		scopeSrc = DefaultScopeSkip
	}

	m := &wafQueue{
		next:         next,
		name:         name,
		shadow:       config.IsShadow(),
		blockStatus:  blockStatus,
		streamKey:    streamKey,
		streamMaxLen: streamMaxLen,
		bannedKey:    bannedKey,
		whitelistKey: config.WhitelistKeys,
		blocklistKey: config.BlocklistKeys,
		resolver:     NewRealIPResolver(config.RealIPHeaders, config.TrustedProxies),
		whitelist:    NewMatcher(),
		blocklist:    NewMatcher(),
		scopeSkip:    compileRegexes(scopeSrc, logger),
		inline:       compileRegexes(config.InlineRoutes, logger),
		metrics:      NewMetrics(),
		jobs:         make(chan enqueueJob, 8192),
	}

	// Seed the whitelist with the trusted proxies as a belt-and-suspenders guard: a CDN edge
	// or internal proxy must never be blocked, even if it somehow lands in the blocklist.
	if len(config.TrustedProxies) > 0 {
		m.whitelist.Swap(BuildTrie(config.TrustedProxies))
		m.metrics.WhitelistSize.Set(float64(m.whitelist.Len()))
	}

	// Build the valkey store. A construction that cannot reach valkey is fine — every read is
	// fail-open and the tries stay empty (empty ⇒ no match ⇒ pass).
	if config.ValkeyAddr != "" || len(config.ValkeySentinels) > 0 {
		m.store = NewValkeyStore(config.ValkeyAddr, config.ValkeySentinels, config.ValkeyMaster, config.ValkeyPassword, config.ValkeyDB)
	}

	// Per-node stats mirror for the read-only /api/waf dashboard. Lives off the request
	// path: the hot path only does an atomic add, a background flusher pipelines to valkey.
	m.stats = newStatsCollector(m.store, config.StatsPrefix, "")

	// Report the ACTUAL loaded trie sizes to the dashboard from the start, before the first
	// refresh tick. The whitelist is seeded above from TrustedProxies (the fleet CF/CloudFront/
	// owner/CGNAT whitelist), so its size is non-zero immediately even when no valkey whitelist
	// keys are configured — the dashboard used to show "0 CIDRs" here, which read as an empty
	// whitelist when the trie actually holds the full set. These gauges are the TRUE trie
	// lengths, never a hardcoded value.
	m.stats.setGauge(statWhitelistSize, int64(m.whitelist.Len()))
	m.stats.setGauge(statBlocklistSize, int64(m.blocklist.Len()))

	if m.shadow {
		logger.Info().Msg("WafQueue middleware in SHADOW mode (observe-only, will never block)")
	} else {
		logger.Warn().Int("blockStatus", blockStatus).Msg("WafQueue middleware in ENFORCE mode (blocking enabled)")
	}

	// Background workers: enqueue dispatchers + the trie refresher. They stop when ctx is
	// cancelled (traefik cancels the provider context on config reload).
	for i := 0; i < 4; i++ {
		go m.enqueueLoop(ctx)
	}
	go m.refreshLoop(ctx, refresh)
	go m.stats.flushLoop(ctx, 5*time.Second)

	return m, nil
}

func compileRegexes(src []string, logger *zerolog.Logger) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(src))
	for _, s := range src {
		re, err := regexp.Compile(s)
		if err != nil {
			logger.Warn().Str("pattern", s).Err(err).Msg("WafQueue: skipping invalid regex")
			continue
		}
		out = append(out, re)
	}
	return out
}

func (m *wafQueue) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()

	// 1. Resolve the real client IP (fail-open: on failure we get the peer or a zero addr).
	ip := m.resolver.Resolve(req)

	// 2. Whitelist — highest precedence, beats every blocklist. Never enqueue, never block.
	if ip.IsValid() && m.whitelist.Contains(ip) {
		m.metrics.action(ActionWhitelist)
		m.stats.incr(statWhitelist)
		m.metrics.observeHotPath(time.Since(start).Seconds())
		m.next.ServeHTTP(rw, req)
		return
	}

	// 3. Blocklist — match on the REAL IP (never the edge). Checked before scope so a known-bad
	// IP is blocked even on a static URL.
	if ip.IsValid() && m.blocklist.Contains(ip) {
		if m.shadow {
			m.metrics.action(ActionWouldBlock)
			m.stats.incr(statWouldBlock)
			m.metrics.block(SourceBlocklist)
			m.logWouldBlock(req, ip)
			m.metrics.observeHotPath(time.Since(start).Seconds())
			m.next.ServeHTTP(rw, req)
			return
		}
		m.metrics.action(ActionBlock)
		m.stats.incr(statBlock)
		m.metrics.block(SourceBlocklist)
		m.writeBlock(rw)
		m.metrics.observeHotPath(time.Since(start).Seconds())
		return
	}

	// 4. Scope gate — skip enqueue for benign high-volume paths.
	if m.scoped(req.URL.Path) {
		m.metrics.action(ActionSkip)
		m.stats.incr(statScoped)
		m.metrics.observeHotPath(time.Since(start).Seconds())
		m.next.ServeHTTP(rw, req)
		return
	}

	// 5. Enqueue (bounded, fire-and-forget) + pass immediately.
	m.enqueue(req, ip)
	m.metrics.action(ActionPass)
	m.stats.incr(statPass)
	m.metrics.observeHotPath(time.Since(start).Seconds())
	m.next.ServeHTTP(rw, req)
}

func (m *wafQueue) scoped(path string) bool {
	for _, re := range m.scopeSkip {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// IsInline reports whether a path matches an InlineRoutes pattern (Phase-5 sync-block path).
// Exposed for tests and the future enforcement phase; it does not change Phase-1 behaviour.
func (m *wafQueue) IsInline(path string) bool {
	for _, re := range m.inline {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// buildJob builds the compact inspection job from a request.
func buildJob(req *http.Request, ip netip.Addr) enqueueJob {
	return enqueueJob{
		ip:     ip.String(),
		method: req.Method,
		path:   req.URL.Path,
		host:   requestHost(req),
		ua:     truncate(req.UserAgent(), 256),
		ts:     time.Now().UnixMilli(),
		rid:    req.Header.Get("X-Request-Id"),
	}
}

// jobFields renders the stream field map (compact keys) sent via XADD.
func jobFields(job enqueueJob) map[string]any {
	return map[string]any{
		"ip":  job.ip,
		"m":   job.method,
		"p":   job.path,
		"h":   job.host,
		"ua":  job.ua,
		"ts":  job.ts,
		"rid": job.rid,
	}
}

func (m *wafQueue) enqueue(req *http.Request, ip netip.Addr) {
	job := buildJob(req, ip)
	select {
	case m.jobs <- job:
		m.metrics.action(ActionEnqueue)
		m.stats.incr(statEnqueue)
	default:
		// Bounded queue full — drop the inspection job but still pass the request.
		m.metrics.failOpen(ReasonEnqueue)
		m.stats.incr(statFailOpen)
	}
}

func (m *wafQueue) enqueueLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-m.jobs:
			m.flush(ctx, job)
		}
	}
}

func (m *wafQueue) flush(ctx context.Context, job enqueueJob) {
	if m.store == nil {
		m.metrics.failOpen(ReasonValkey)
		m.stats.incr(statFailOpen)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if err := m.store.Enqueue(cctx, m.streamKey, m.streamMaxLen, jobFields(job)); err != nil {
		m.metrics.failOpen(ReasonValkey)
		m.stats.incr(statFailOpen)
	}
}

// refreshLoop periodically rebuilds the whitelist and blocklist tries from valkey. On error it
// keeps the last-known tries (feed-stale) and never empties a populated trie on a transient
// failure.
func (m *wafQueue) refreshLoop(ctx context.Context, interval time.Duration) {
	m.refreshOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.refreshOnce(ctx)
		}
	}
}

func (m *wafQueue) refreshOnce(ctx context.Context) {
	if m.store == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Whitelist: configured sets + always the trusted proxies.
	if wl, err := m.store.Members(cctx, m.whitelistKey); err == nil {
		if len(wl) > 0 {
			t := BuildTrie(wl)
			// Keep the trusted-proxy seed as well.
			m.whitelist.Swap(t)
			m.metrics.WhitelistSize.Set(float64(t.Len()))
			m.stats.setGauge(statWhitelistSize, int64(t.Len()))
		}
	} else {
		m.metrics.failOpen(ReasonRefresh)
	}

	// Blocklist: configured sets + the worker-detected ban set.
	blKeys := append(append([]string{}, m.blocklistKey...), m.bannedKey)
	if bl, err := m.store.Members(cctx, blKeys); err == nil {
		if len(bl) > 0 {
			t := BuildTrie(bl)
			m.blocklist.Swap(t)
			m.metrics.BlocklistSize.Set(float64(t.Len()))
			m.stats.setGauge(statBlocklistSize, int64(t.Len()))
		}
	} else {
		m.metrics.failOpen(ReasonRefresh)
	}

	if d, err := m.store.QueueDepth(cctx, m.streamKey); err == nil {
		m.metrics.QueueDepth.Set(float64(d))
	}

	// Always report the ACTUAL live trie sizes (len of the loaded CIDR tries), not the size of
	// the sets just fetched from valkey. The whitelist keeps its TrustedProxies seed even when
	// no valkey whitelist keys are configured, so this is the true count the dashboard shows
	// (~233 whitelist CIDRs; blocklist legitimately 0 in shadow until the worker ban-feed is
	// loaded). Keeping it unconditional means a transient refresh error never resets the gauge.
	m.stats.setGauge(statWhitelistSize, int64(m.whitelist.Len()))
	m.stats.setGauge(statBlocklistSize, int64(m.blocklist.Len()))
	m.metrics.WhitelistSize.Set(float64(m.whitelist.Len()))
	m.metrics.BlocklistSize.Set(float64(m.blocklist.Len()))

	m.stats.setGauge(statRefreshTS, time.Now().UnixMilli())
}

func (m *wafQueue) logWouldBlock(req *http.Request, ip netip.Addr) {
	log.Info().
		Str("middleware", m.name).
		Str("waf", "would-block").
		Str("ip", ip.String()).
		Str("method", req.Method).
		Str("path", req.URL.Path).
		Str("host", requestHost(req)).
		Msg("WafQueue shadow: would block (blocklist hit)")
}

// writeBlock emits the block response. 444 drops the connection without a response (matching
// the nginx/CRS convention for known-bad scanners); any other status is written normally.
func (m *wafQueue) writeBlock(rw http.ResponseWriter) {
	if m.blockStatus == 444 {
		if hj, ok := rw.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		// Can't hijack (HTTP/2) — fall back to a 403 so we still deny.
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	rw.WriteHeader(m.blockStatus)
}

func requestHost(req *http.Request) string {
	if h := req.Header.Get("X-Forwarded-Host"); h != "" {
		return h
	}
	return req.Host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
