package wafqueue

import (
	"context"
	"os"
	"sync/atomic"
	"time"
)

// defaultStatsPrefix mirrors dynamic.WafQueueDefaultStatsPrefix; duplicated as a local const to
// keep this file free of a config dependency.
const defaultStatsPrefix = "waf:stats:"

// Stat action/field names. These are the suffixes of the per-node keys
// (waf:stats:<node>:<field>) that the read-only /api/waf endpoint reads back.
const (
	statPass       = "pass"
	statWhitelist  = "whitelist"
	statWouldBlock = "would_block"
	statBlock      = "block"
	statScoped     = "scoped"
	statEnqueue    = "enqueue"
	statFailOpen   = "failopen"
	// statDropped counts inspection jobs dropped on the hot path because the bounded job
	// channel was full (valkey slow/down and the background drain backed up). The request
	// still passed; only the out-of-band inspection was skipped.
	statDropped       = "dropped"
	statBlocklistSize = "blocklist_size"
	statWhitelistSize = "whitelist_size"
	statRefreshTS     = "refresh_ts"
)

// statCounterFields are the cumulative action counters (flushed as INCRBY deltas).
var statCounterFields = []string{
	statPass, statWhitelist, statWouldBlock, statBlock, statScoped, statEnqueue, statFailOpen, statDropped,
}

// statGaugeFields are absolute values (flushed as SET).
var statGaugeFields = []string{statBlocklistSize, statWhitelistSize, statRefreshTS}

// statsCollector mirrors the hot-path action counters into valkey as per-node keys so the
// read-only dashboard has live, swarm-wide rates without new middleware state on the request
// path. The hot path only does a lock-free atomic add; a background flusher pipelines the
// accumulated deltas to valkey periodically. It is fail-open: a flush error never touches the
// request path, and the deltas are simply retried on the next tick.
type statsCollector struct {
	store  Store
	prefix string
	node   string

	counts map[string]*atomic.Int64 // cumulative deltas, swapped to 0 on flush
	gauges map[string]*atomic.Int64 // absolute values, read on flush
}

// newStatsCollector builds a collector. prefix falls back to the default; node falls back to
// WAF_NODE then the hostname so each swarm node writes a distinct key namespace.
func newStatsCollector(store Store, prefix, node string) *statsCollector {
	if prefix == "" {
		prefix = defaultStatsPrefix
	}
	if node == "" {
		if n := os.Getenv("WAF_NODE"); n != "" {
			node = n
		} else {
			node, _ = os.Hostname()
		}
	}
	if node == "" {
		node = "unknown"
	}
	s := &statsCollector{
		store:  store,
		prefix: prefix,
		node:   node,
		counts: make(map[string]*atomic.Int64, len(statCounterFields)),
		gauges: make(map[string]*atomic.Int64, len(statGaugeFields)),
	}
	for _, f := range statCounterFields {
		s.counts[f] = &atomic.Int64{}
	}
	for _, f := range statGaugeFields {
		s.gauges[f] = &atomic.Int64{}
	}
	return s
}

// incr bumps an action counter. Lock-free and nil-safe; an unknown action is ignored.
func (s *statsCollector) incr(action string) {
	if s == nil {
		return
	}
	if c, ok := s.counts[action]; ok {
		c.Add(1)
	}
}

// setGauge records an absolute gauge value (e.g. a trie size). Nil-safe.
func (s *statsCollector) setGauge(field string, v int64) {
	if s == nil {
		return
	}
	if g, ok := s.gauges[field]; ok {
		g.Store(v)
	}
}

// key builds the full per-node valkey key for a field.
func (s *statsCollector) key(field string) string {
	return s.prefix + s.node + ":" + field
}

// flush pipelines the accumulated counter deltas (INCRBY) and current gauges (SET) to valkey.
// On error the counter deltas are added back so the next flush retries them (no lost counts on
// a transient valkey hiccup).
func (s *statsCollector) flush(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	incr := make(map[string]int64, len(s.counts))
	for field, c := range s.counts {
		if d := c.Swap(0); d != 0 {
			incr[s.key(field)] = d
		}
	}
	set := make(map[string]int64, len(s.gauges))
	for field, g := range s.gauges {
		set[s.key(field)] = g.Load()
	}
	if len(incr) == 0 && len(set) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.store.FlushStats(cctx, incr, set); err != nil {
		// Put the deltas back; they will be retried on the next tick.
		for field, d := range incr {
			// field is a full key; recover the suffix.
			suffix := field[len(s.prefix)+len(s.node)+1:]
			if c, ok := s.counts[suffix]; ok {
				c.Add(d)
			}
		}
	}
}

// flushLoop flushes on an interval until ctx is cancelled, with a final best-effort flush on
// shutdown.
func (s *statsCollector) flushLoop(ctx context.Context, interval time.Duration) {
	if s == nil || s.store == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush(context.Background())
			return
		case <-t.C:
			s.flush(ctx)
		}
	}
}
