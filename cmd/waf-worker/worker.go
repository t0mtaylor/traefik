package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"
)

// Job is a single inspection job drained from the stream.
type Job struct {
	ID     string // stream entry id (for XACK)
	IP     string
	Method string
	Path   string
	Host   string
	UA     string
	TS     int64
	RID    string
}

// Verdict is the result of an out-of-band modsec inspection.
type Verdict struct {
	Bad    bool
	Reason string
}

// ModsecClient inspects a job out-of-band (POST to the modsec swarm VIP). Implementations
// must fail OPEN by returning an error (never a false "bad") when modsec is unreachable, so a
// modsec outage never produces spurious bans.
type ModsecClient interface {
	Inspect(ctx context.Context, job Job) (Verdict, error)
}

// StreamConsumer drains jobs from the valkey stream via a consumer group and acks them.
type StreamConsumer interface {
	Read(ctx context.Context, count int, block time.Duration) ([]Job, error)
	Ack(ctx context.Context, ids ...string) error
}

// BanStore persists a ban and answers whitelist membership.
type BanStore interface {
	Ban(ctx context.Context, ip string, ttl time.Duration, reason string) error
	IsWhitelisted(ctx context.Context, ip string) (bool, error)
}

// TTDFFeeder forwards a confirmed-bad IP into the TTDF ban pipeline so nginx + DO LB +
// fail2ban enforce it fleet-wide.
//
// TODO(waf): wire this to the real TTDF ban pipeline (dbwriter / ban-stream valkey). The
// skeleton implementation logs and optionally POSTs to a configurable webhook.
type TTDFFeeder interface {
	Feed(ctx context.Context, ip, reason string) error
}

// Config holds worker tunables.
type Config struct {
	BanTTL     time.Duration
	Batch      int
	BlockMin   time.Duration // read block timeout
	MaxRetries int
	Backoff    time.Duration // base backoff
	Logger     *slog.Logger
}

// Worker ties the consumer, modsec client, ban store and TTDF feeder together.
type Worker struct {
	cons   StreamConsumer
	modsec ModsecClient
	bans   BanStore
	ttdf   TTDFFeeder
	cfg    Config
	log    *slog.Logger

	lastConsumeMs  atomic.Int64 // unix millis of the last successful stream read (consume heartbeat)
	processedTotal atomic.Int64 // cumulative jobs acked (processed) since start; bucketed for throughput

	modsecOkMs  atomic.Int64 // unix millis of the last successful modsec inspection (real or probe)
	modsecErrMs atomic.Int64 // unix millis of the last modsec failure
	modsecErr   atomic.Value // last modsec error string (redaction not needed: a URL, no secret)
}

// recordModsec stamps the modsec link health from an inspection/probe result.
func (w *Worker) recordModsec(err error) {
	if err == nil {
		w.modsecOkMs.Store(time.Now().UnixMilli())
		return
	}
	w.modsecErrMs.Store(time.Now().UnixMilli())
	w.modsecErr.Store(err.Error())
}

// ModsecHealth returns the last modsec ok/err timestamps and the last error string. Nil-safe for
// the error (empty until a failure occurs).
func (w *Worker) ModsecHealth() (okMs, errMs int64, errStr string) {
	if v, ok := w.modsecErr.Load().(string); ok {
		errStr = v
	}
	return w.modsecOkMs.Load(), w.modsecErrMs.Load(), errStr
}

// ProbeModsec sends one synthetic benign inspection to modsec to confirm the link is up even
// when there is no live traffic. The verdict is ignored (nothing is enqueued, acked or banned);
// only the ok/err outcome is recorded. Off the consume path.
func (w *Worker) ProbeModsec(ctx context.Context) {
	_, err := w.modsec.Inspect(ctx, Job{
		ID:     "probe",
		IP:     "127.0.0.1",
		Method: "GET",
		Path:   "/",
		Host:   "waf-worker-healthcheck",
		UA:     "waf-worker-probe",
		TS:     time.Now().UnixMilli(),
	})
	w.recordModsec(err)
}

// LastConsumeMs reports when the worker last successfully read from the stream (0 if never).
// Used by the connection-health heartbeat so the dashboard can show worker liveness.
func (w *Worker) LastConsumeMs() int64 { return w.lastConsumeMs.Load() }

// ProcessedTotal reports the cumulative number of jobs acked (reached a terminal decision)
// since the worker started. The heartbeat buckets its delta into time windows for the
// dashboard's 1h/24h throughput.
func (w *Worker) ProcessedTotal() int64 { return w.processedTotal.Load() }

// NewWorker builds a Worker.
func NewWorker(cons StreamConsumer, modsec ModsecClient, bans BanStore, ttdf TTDFFeeder, cfg Config) *Worker {
	if cfg.Batch <= 0 {
		cfg.Batch = 64
	}
	if cfg.BlockMin <= 0 {
		cfg.BlockMin = 2 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 100 * time.Millisecond
	}
	if cfg.BanTTL <= 0 {
		cfg.BanTTL = time.Hour
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Worker{cons: cons, modsec: modsec, bans: bans, ttdf: ttdf, cfg: cfg, log: log}
}

// Run loops until ctx is cancelled, processing one batch per iteration.
func (w *Worker) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.ProcessBatch(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			// Read error (valkey hiccup) — back off and retry; never crash the worker.
			w.log.Warn("batch read failed", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.cfg.Backoff):
			}
		}
	}
}

// ProcessBatch reads one batch and processes every job. It acks a job once a decision is
// reached (ban written, clean, or whitelisted). A job whose modsec inspection keeps failing is
// NOT acked, so it is redelivered later — detection is delayed, never dropped silently, and
// the hot path is unaffected.
func (w *Worker) ProcessBatch(ctx context.Context) error {
	jobs, err := w.cons.Read(ctx, w.cfg.Batch, w.cfg.BlockMin)
	if err != nil {
		return err
	}
	// A successful read (even an empty one) means the worker→valkey link is alive; record it for
	// the connection-health heartbeat.
	w.lastConsumeMs.Store(time.Now().UnixMilli())
	var ackable []string
	for _, job := range jobs {
		if w.handle(ctx, job) {
			ackable = append(ackable, job.ID)
		}
	}
	if len(ackable) > 0 {
		if err := w.cons.Ack(ctx, ackable...); err != nil {
			w.log.Warn("ack failed", "err", err, "n", len(ackable))
		}
		// Count processed (acked) jobs for the 1h/24h throughput metric. In-memory add only;
		// the heartbeat buckets the delta into valkey off this path.
		w.processedTotal.Add(int64(len(ackable)))
	}
	return nil
}

// handle inspects one job. Returns true if the job reached a terminal decision and may be
// acked; false if it should be redelivered (modsec unreachable).
func (w *Worker) handle(ctx context.Context, job Job) bool {
	// Never ban a whitelisted IP (CDN edge / owner / mobile). Re-check here too — the
	// whitelist is authoritative at every tier.
	if wl, err := w.bans.IsWhitelisted(ctx, job.IP); err == nil && wl {
		return true
	}

	verdict, err := w.inspectWithRetry(ctx, job)
	if err != nil {
		// modsec down after retries: fail-open — leave unacked for redelivery, do not ban.
		w.log.Warn("modsec unavailable, deferring", "ip", job.IP, "err", err)
		return false
	}
	if !verdict.Bad {
		return true
	}

	// Defence in depth: never ban something that doesn't parse as an IP.
	if _, perr := netip.ParseAddr(job.IP); perr != nil {
		w.log.Warn("bad verdict but unparseable IP, skipping ban", "ip", job.IP)
		return true
	}

	if err := w.bans.Ban(ctx, job.IP, w.cfg.BanTTL, verdict.Reason); err != nil {
		w.log.Warn("ban write failed", "ip", job.IP, "err", err)
		return false // retry the ban later
	}
	w.log.Info("banned", "ip", job.IP, "reason", verdict.Reason, "ttl", w.cfg.BanTTL, "path", job.Path, "host", job.Host)

	if w.ttdf != nil {
		if err := w.ttdf.Feed(ctx, job.IP, verdict.Reason); err != nil {
			w.log.Warn("ttdf feed failed", "ip", job.IP, "err", err)
			// The local ban still stands; TTDF feed is best-effort.
		}
	}
	return true
}

// inspectWithRetry calls modsec with exponential backoff. A transport/5xx error is retried;
// after MaxRetries it returns the error (fail-open at the caller).
func (w *Worker) inspectWithRetry(ctx context.Context, job Job) (Verdict, error) {
	var lastErr error
	backoff := w.cfg.Backoff
	for attempt := 0; attempt <= w.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Verdict{}, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		v, err := w.modsec.Inspect(ctx, job)
		if err == nil {
			w.recordModsec(nil) // modsec link healthy (real inspection succeeded)
			return v, nil
		}
		lastErr = err
	}
	w.recordModsec(lastErr) // modsec link unhealthy after retries
	return Verdict{}, lastErr
}
