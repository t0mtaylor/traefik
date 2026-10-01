package wafqueue

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the Prometheus collectors for the hot path. They are registered on a
// dedicated registry owned by the caller.
//
// TODO(waf): wire Registry into traefik's own observability metrics registry
// (pkg/metrics + the observability middleware) so these are exported on traefik's /metrics
// endpoint instead of a standalone registry. For Phase 1 (shadow) a self-contained registry
// is sufficient to validate detection parity.
type Metrics struct {
	Registry *prometheus.Registry

	Requests      *prometheus.CounterVec // waf_requests_total{action}
	Blocks        *prometheus.CounterVec // waf_block_total{source}
	FailOpen      *prometheus.CounterVec // waf_failopen_total{reason}
	QueueDepth    prometheus.Gauge       // waf_queue_depth
	HotPath       prometheus.Histogram   // waf_hotpath_latency_seconds
	BlocklistSize prometheus.Gauge       // waf_blocklist_size
	WhitelistSize prometheus.Gauge       // waf_whitelist_size
}

// Hot-path action labels.
const (
	ActionPass       = "pass"
	ActionWhitelist  = "whitelist"
	ActionWouldBlock = "would_block"
	ActionBlock      = "block"
	ActionSkip       = "skip"
	ActionEnqueue    = "enqueue"
)

// Block sources.
const (
	SourceBlocklist = "blocklist"
	SourceBanned    = "banned"
	SourceFeed      = "feed"
)

// Fail-open reasons.
const (
	ReasonValkey  = "valkey"
	ReasonRefresh = "refresh"
	ReasonEnqueue = "enqueue"
	ReasonResolve = "resolve"
	// ReasonDrop labels a hot-path enqueue dropped because the bounded job channel was full.
	ReasonDrop = "drop"
)

// NewMetrics builds the collectors and registers them on a fresh registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total requests seen by the async WAF, by hot-path action.",
		}, []string{"action"}),
		Blocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_block_total",
			Help: "Total requests blocked (or would-block in shadow), by source.",
		}, []string{"source"}),
		FailOpen: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_failopen_total",
			Help: "Total fail-open events (request passed on error), by reason.",
		}, []string{"reason"}),
		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_queue_depth",
			Help: "Approximate depth of the waf:stream job queue.",
		}),
		HotPath: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "waf_hotpath_latency_seconds",
			Help:    "Hot-path processing latency in seconds (target sub-millisecond).",
			Buckets: []float64{1e-6, 5e-6, 1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2},
		}),
		BlocklistSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_blocklist_size",
			Help: "Number of CIDRs in the live blocklist trie.",
		}),
		WhitelistSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_whitelist_size",
			Help: "Number of CIDRs in the live whitelist trie.",
		}),
	}
	reg.MustRegister(m.Requests, m.Blocks, m.FailOpen, m.QueueDepth, m.HotPath, m.BlocklistSize, m.WhitelistSize)
	return m
}

func (m *Metrics) action(a string) {
	if m != nil {
		m.Requests.WithLabelValues(a).Inc()
	}
}

func (m *Metrics) block(src string) {
	if m != nil {
		m.Blocks.WithLabelValues(src).Inc()
	}
}

func (m *Metrics) failOpen(reason string) {
	if m != nil {
		m.FailOpen.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) observeHotPath(seconds float64) {
	if m != nil {
		m.HotPath.Observe(seconds)
	}
}
