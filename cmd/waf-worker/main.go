// Command waf-worker drains the async WAF job stream (waf:stream), inspects each job via
// modsec out-of-band, and writes bans back to waf:banned (with a TTL) + feeds the TTDF ban
// pipeline. It is the out-of-band half of the async WAF: the traefik wafqueue middleware
// enqueues, this worker inspects. modsec is never on the request critical path.
//
// Config is via environment variables (see getenv* calls in loadConfig) or the matching flags.
// Fails open: a modsec outage delays detection (jobs are redelivered) but never bans
// spuriously and never affects live traffic.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/traefik/traefik/v3/pkg/middlewares/wafqueue"
)

type options struct {
	valkeyAddr      string
	valkeySentinels []string
	valkeyMaster    string
	valkeyPassword  string
	valkeyDB        int
	streamKey       string
	group           string
	consumer        string
	bannedKey       string
	whitelistKeys   []string
	modsecURL       string
	denyStatuses    []int
	banTTL          time.Duration
	batch           int
	maxRetries      int
	backoff         time.Duration
	refresh         time.Duration
	ttdfWebhook     string
	reqTimeout      time.Duration
}

func loadConfig() options {
	host, _ := os.Hostname()
	o := options{
		valkeyAddr:      getenv("WAF_VALKEY_ADDR", "127.0.0.1:6379"),
		valkeySentinels: splitCSV(getenv("WAF_VALKEY_SENTINELS", "")),
		valkeyMaster:    getenv("WAF_VALKEY_MASTER", ""),
		valkeyPassword:  getenv("WAF_VALKEY_PASSWORD", ""),
		valkeyDB:        getenvInt("WAF_VALKEY_DB", 0),
		streamKey:       getenv("WAF_STREAM", "waf:stream"),
		group:           getenv("WAF_GROUP", "waf-workers"),
		consumer:        getenv("WAF_CONSUMER", host),
		bannedKey:       getenv("WAF_BANNED_KEY", "waf:banned"),
		whitelistKeys:   splitCSV(getenv("WAF_WHITELIST_KEYS", "")),
		modsecURL:       getenv("WAF_MODSEC_URL", "http://modsec:8091"),
		denyStatuses:    parseInts(getenv("WAF_DENY_STATUSES", "403,406,444")),
		banTTL:          getenvDur("WAF_BAN_TTL", time.Hour),
		batch:           getenvInt("WAF_BATCH", 64),
		maxRetries:      getenvInt("WAF_MAX_RETRIES", 3),
		backoff:         getenvDur("WAF_BACKOFF", 100*time.Millisecond),
		refresh:         getenvDur("WAF_REFRESH", 60*time.Second),
		ttdfWebhook:     getenv("WAF_TTDF_WEBHOOK", ""),
		reqTimeout:      getenvDur("WAF_MODSEC_TIMEOUT", 2*time.Second),
	}

	flag.StringVar(&o.valkeyAddr, "valkey-addr", o.valkeyAddr, "valkey host:port (single node)")
	flag.StringVar(&o.valkeyMaster, "valkey-master", o.valkeyMaster, "sentinel master name")
	flag.StringVar(&o.streamKey, "stream", o.streamKey, "job stream key")
	flag.StringVar(&o.group, "group", o.group, "consumer group")
	flag.StringVar(&o.consumer, "consumer", o.consumer, "consumer name")
	flag.StringVar(&o.bannedKey, "banned-key", o.bannedKey, "ban set key")
	flag.StringVar(&o.modsecURL, "modsec-url", o.modsecURL, "modsec inspection endpoint (swarm VIP)")
	flag.DurationVar(&o.banTTL, "ban-ttl", o.banTTL, "ban TTL")
	flag.IntVar(&o.batch, "batch", o.batch, "read batch size")
	flag.Parse()
	return o
}

func main() {
	o := loadConfig()
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := newClient(o)
	defer func() { _ = rdb.Close() }()

	// Ensure the consumer group exists (MKSTREAM so first start works before any producer).
	if err := rdb.XGroupCreateMkStream(ctx, o.streamKey, o.group, "$").Err(); err != nil &&
		!strings.Contains(err.Error(), "BUSYGROUP") {
		log.Warn("create consumer group", "err", err)
	}

	cons := &valkeyConsumer{rdb: rdb, stream: o.streamKey, group: o.group, consumer: o.consumer}
	modsec := newModsecClient(o)
	bans := newValkeyBanStore(ctx, rdb, o, log)
	var ttdf TTDFFeeder = newTTDFFeeder(o)

	w := NewWorker(cons, modsec, bans, ttdf, Config{
		BanTTL:     o.banTTL,
		Batch:      o.batch,
		MaxRetries: o.maxRetries,
		Backoff:    o.backoff,
		Logger:     log,
	})

	log.Info("waf-worker starting",
		"stream", o.streamKey, "group", o.group, "consumer", o.consumer,
		"modsec", o.modsecURL, "banTTL", o.banTTL.String())

	// Connection-health heartbeat: publish worker liveness so the WAF dashboard can show
	// replicas / last-consume / worker->valkey link. Off the processing path; best-effort.
	go workerHeartbeat(ctx, rdb, o, w, log)

	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("worker exited", "err", err)
		os.Exit(1)
	}
	log.Info("waf-worker stopped")
}

// workerHealthKeyPrefix mirrors the handler's wafWorkerHealthPrefix.
const workerHealthKeyPrefix = "waf:health:worker:"

// workerHeartbeat writes waf:health:worker:<consumer> every 5s with a 30s TTL. If valkey is
// down the write fails and the key expires, so the dashboard shows the worker DOWN. The write
// uses a tiny timeout so it never piles up.
func workerHeartbeat(ctx context.Context, rdb redis.UniversalClient, o options, w *Worker, log *slog.Logger) {
	endpoint := o.valkeyAddr
	if len(o.valkeySentinels) > 0 {
		endpoint = "sentinel:" + o.valkeyMaster + "@" + strings.Join(o.valkeySentinels, ",")
	}
	key := workerHealthKeyPrefix + o.consumer
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	publish := func() {
		payload := map[string]any{
			"consumer":      o.consumer,
			"group":         o.group,
			"ts":            time.Now().UnixMilli(),
			"lastConsumeMs": w.LastConsumeMs(),
			"state":         "up",
			"endpoint":      endpoint,
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if err := rdb.Set(cctx, key, string(b), 30*time.Second).Err(); err != nil {
			log.Debug("worker heartbeat publish failed", "err", err)
		}
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			publish()
		}
	}
}

func newClient(o options) redis.UniversalClient {
	opts := &redis.UniversalOptions{
		Password: o.valkeyPassword,
		DB:       o.valkeyDB,
		// Fail-fast on a DOWN valkey (dial), but keep the default ReadTimeout so the blocking
		// XReadGroup consume (Block=BlockMin) is not cut short. MaxRetries off to avoid pileup.
		DialTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
		PoolTimeout:  250 * time.Millisecond,
		MaxRetries:   -1,
	}
	if len(o.valkeySentinels) > 0 {
		opts.Addrs = o.valkeySentinels
		opts.MasterName = o.valkeyMaster
	} else {
		opts.Addrs = []string{o.valkeyAddr}
	}
	return redis.NewUniversalClient(opts)
}

// ---- valkey stream consumer (consumer group) ----

type valkeyConsumer struct {
	rdb      redis.UniversalClient
	stream   string
	group    string
	consumer string
}

func (c *valkeyConsumer) Read(ctx context.Context, count int, block time.Duration) ([]Job, error) {
	res, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    c.group,
		Consumer: c.consumer,
		Streams:  []string{c.stream, ">"},
		Count:    int64(count),
		Block:    block,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // no new messages within block window
		}
		return nil, err
	}
	var jobs []Job
	for _, s := range res {
		for _, msg := range s.Messages {
			jobs = append(jobs, jobFromValues(msg.ID, msg.Values))
		}
	}
	return jobs, nil
}

func (c *valkeyConsumer) Ack(ctx context.Context, ids ...string) error {
	return c.rdb.XAck(ctx, c.stream, c.group, ids...).Err()
}

func jobFromValues(id string, v map[string]any) Job {
	ts, _ := strconv.ParseInt(str(v["ts"]), 10, 64)
	return Job{
		ID:     id,
		IP:     str(v["ip"]),
		Method: str(v["m"]),
		Path:   str(v["p"]),
		Host:   str(v["h"]),
		UA:     str(v["ua"]),
		TS:     ts,
		RID:    str(v["rid"]),
	}
}

// ---- modsec HTTP client ----

type modsecClient struct {
	url  string
	deny map[int]bool
	hc   *http.Client
}

func newModsecClient(o options) *modsecClient {
	deny := map[int]bool{}
	for _, s := range o.denyStatuses {
		deny[s] = true
	}
	return &modsecClient{
		url:  o.modsecURL,
		deny: deny,
		hc:   &http.Client{Timeout: o.reqTimeout},
	}
}

// Inspect replays the request metadata to modsec out-of-band. A deny status ⇒ bad; a clean
// status ⇒ not bad; a 5xx or transport error ⇒ error (retried / fail-open).
func (m *modsecClient) Inspect(ctx context.Context, job Job) (Verdict, error) {
	method := job.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, m.url+job.Path, bytes.NewReader(nil))
	if err != nil {
		return Verdict{}, err
	}
	if job.Host != "" {
		req.Header.Set("X-Forwarded-Host", job.Host)
	}
	if job.IP != "" {
		req.Header.Set("X-Real-Ip", job.IP)
		req.Header.Set("X-Forwarded-For", job.IP)
	}
	if job.UA != "" {
		req.Header.Set("User-Agent", job.UA)
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if m.deny[resp.StatusCode] {
		return Verdict{Bad: true, Reason: fmt.Sprintf("modsec %d", resp.StatusCode)}, nil
	}
	if resp.StatusCode >= 500 {
		return Verdict{}, fmt.Errorf("modsec upstream %d", resp.StatusCode)
	}
	return Verdict{Bad: false}, nil
}

// ---- valkey ban store with whitelist re-check ----

type valkeyBanStore struct {
	rdb       redis.UniversalClient
	bannedKey string
	wl        *wafqueue.Matcher
}

func newValkeyBanStore(ctx context.Context, rdb redis.UniversalClient, o options, log *slog.Logger) *valkeyBanStore {
	s := &valkeyBanStore{rdb: rdb, bannedKey: o.bannedKey, wl: wafqueue.NewMatcher()}
	s.refreshWhitelist(ctx, o.whitelistKeys, log)
	if len(o.whitelistKeys) > 0 {
		go func() {
			t := time.NewTicker(o.refresh)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.refreshWhitelist(ctx, o.whitelistKeys, log)
				}
			}
		}()
	}
	return s
}

func (s *valkeyBanStore) refreshWhitelist(ctx context.Context, keys []string, log *slog.Logger) {
	if len(keys) == 0 {
		return
	}
	var all []string
	for _, k := range keys {
		vals, err := s.rdb.SMembers(ctx, k).Result()
		if err != nil {
			log.Warn("whitelist refresh failed", "key", k, "err", err)
			return // keep last-known
		}
		all = append(all, vals...)
	}
	s.wl.Swap(wafqueue.BuildTrie(all))
}

func (s *valkeyBanStore) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil
	}
	return s.wl.Contains(addr.Unmap()), nil
}

func (s *valkeyBanStore) Ban(ctx context.Context, ip string, ttl time.Duration, reason string) error {
	pipe := s.rdb.TxPipeline()
	pipe.SAdd(ctx, s.bannedKey, ip)
	// Per-IP TTL marker so the ban auto-expires; the set membership is pruned by the worker's
	// own housekeeping / the orchestrator (the marker is the source of truth for expiry).
	pipe.Set(ctx, s.bannedKey+":"+ip, reason, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// ---- TTDF feeder (skeleton) ----

type ttdfFeeder struct {
	webhook string
	hc      *http.Client
}

func newTTDFFeeder(o options) *ttdfFeeder {
	return &ttdfFeeder{webhook: o.ttdfWebhook, hc: &http.Client{Timeout: o.reqTimeout}}
}

// Feed forwards a confirmed-bad IP to TTDF. TODO(waf): replace the webhook stub with the real
// TTDF ban-pipeline integration (dbwriter sole-writer / ban-stream valkey) so nginx + DO LB +
// fail2ban enforce fleet-wide. When no webhook is configured this is a no-op (logged by caller).
func (f *ttdfFeeder) Feed(ctx context.Context, ip, reason string) error {
	if f.webhook == "" {
		return nil
	}
	body := strings.NewReader(fmt.Sprintf(`{"ip":%q,"reason":%q,"source":"waf-worker"}`, ip, reason))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.webhook, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ttdf webhook status %d", resp.StatusCode)
	}
	return nil
}

// ---- env helpers ----

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getenvDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInts(s string) []int {
	var out []int
	for _, p := range splitCSV(s) {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
