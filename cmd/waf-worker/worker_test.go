package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// ---- fakes ----

type fakeConsumer struct {
	mu    sync.Mutex
	batch []Job
	acked []string
	reads int
}

func (f *fakeConsumer) Read(_ context.Context, _ int, _ time.Duration) ([]Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.reads > 1 {
		return nil, nil
	}
	return f.batch, nil
}

func (f *fakeConsumer) Ack(_ context.Context, ids ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, ids...)
	return nil
}

func (f *fakeConsumer) ackedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.acked...)
}

type fakeModsec struct {
	mu        sync.Mutex
	verdict   Verdict
	err       error
	failFirst int
	calls     int
}

func (f *fakeModsec) Inspect(_ context.Context, _ Job) (Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFirst {
		return Verdict{}, errors.New("modsec unreachable")
	}
	return f.verdict, f.err
}

type fakeBans struct {
	mu          sync.Mutex
	banned      map[string]string
	whitelisted map[string]bool
	banErr      error
}

func newFakeBans() *fakeBans {
	return &fakeBans{banned: map[string]string{}, whitelisted: map[string]bool{}}
}

func (f *fakeBans) Ban(_ context.Context, ip string, _ time.Duration, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.banErr != nil {
		return f.banErr
	}
	f.banned[ip] = reason
	return nil
}

func (f *fakeBans) IsWhitelisted(_ context.Context, ip string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.whitelisted[ip], nil
}

func (f *fakeBans) isBanned(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.banned[ip]
	return ok
}

type fakeTTDF struct {
	mu  sync.Mutex
	fed []string
}

func (f *fakeTTDF) Feed(_ context.Context, ip, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fed = append(f.fed, ip)
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fastCfg() Config {
	return Config{BanTTL: time.Hour, Batch: 10, MaxRetries: 3, Backoff: time.Millisecond, Logger: testLogger()}
}

// ---- tests ----

func TestWorker_BadVerdict_BansAndFeedsAndAcks(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "45.9.1.2", Method: "GET", Path: "/wp-login.php"}}}
	modsec := &fakeModsec{verdict: Verdict{Bad: true, Reason: "modsec 403"}}
	bans := newFakeBans()
	ttdf := &fakeTTDF{}
	w := NewWorker(cons, modsec, bans, ttdf, fastCfg())

	if err := w.ProcessBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bans.isBanned("45.9.1.2") {
		t.Error("bad verdict should write a ban")
	}
	if len(ttdf.fed) != 1 || ttdf.fed[0] != "45.9.1.2" {
		t.Errorf("ttdf feed = %v, want [45.9.1.2]", ttdf.fed)
	}
	if ids := cons.ackedIDs(); len(ids) != 1 || ids[0] != "1-0" {
		t.Errorf("acked = %v, want [1-0]", ids)
	}
}

func TestWorker_CleanVerdict_NoBan_Acks(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "203.0.113.5"}}}
	modsec := &fakeModsec{verdict: Verdict{Bad: false}}
	bans := newFakeBans()
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if bans.isBanned("203.0.113.5") {
		t.Error("clean verdict must not ban")
	}
	if len(cons.ackedIDs()) != 1 {
		t.Error("clean job should be acked")
	}
}

func TestWorker_Whitelisted_NeverBanned(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "104.16.5.5"}}}
	modsec := &fakeModsec{verdict: Verdict{Bad: true, Reason: "x"}}
	bans := newFakeBans()
	bans.whitelisted["104.16.5.5"] = true
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if bans.isBanned("104.16.5.5") {
		t.Error("whitelisted IP (CF edge) must never be banned")
	}
	if modsec.calls != 0 {
		t.Errorf("whitelisted IP should short-circuit before modsec, calls=%d", modsec.calls)
	}
	if len(cons.ackedIDs()) != 1 {
		t.Error("whitelisted job should be acked")
	}
}

func TestWorker_ModsecDown_Defers_NoBan_NoAck(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "45.9.1.2"}}}
	modsec := &fakeModsec{failFirst: 1000, err: errors.New("down")} // always fails
	bans := newFakeBans()
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if bans.isBanned("45.9.1.2") {
		t.Error("modsec-down must not produce a ban (fail-open)")
	}
	if len(cons.ackedIDs()) != 0 {
		t.Error("modsec-down job must NOT be acked (redelivered later)")
	}
	// Attempted MaxRetries+1 times.
	if modsec.calls != 4 {
		t.Errorf("expected 4 modsec attempts (1+3 retries), got %d", modsec.calls)
	}
}

func TestWorker_RetryThenSuccess_Bans(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "45.9.1.2"}}}
	modsec := &fakeModsec{failFirst: 2, verdict: Verdict{Bad: true, Reason: "modsec 403"}}
	bans := newFakeBans()
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if !bans.isBanned("45.9.1.2") {
		t.Error("should ban after retry succeeds")
	}
	if modsec.calls != 3 {
		t.Errorf("expected 3 attempts (2 fail + 1 ok), got %d", modsec.calls)
	}
}

func TestWorker_UnparseableIP_NoBan_ButAcks(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "not-an-ip"}}}
	modsec := &fakeModsec{verdict: Verdict{Bad: true, Reason: "x"}}
	bans := newFakeBans()
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if bans.isBanned("not-an-ip") {
		t.Error("must not ban an unparseable IP")
	}
	if len(cons.ackedIDs()) != 1 {
		t.Error("terminal (undefensible) job should still be acked")
	}
}

func TestWorker_BanWriteFails_NotAcked(t *testing.T) {
	cons := &fakeConsumer{batch: []Job{{ID: "1-0", IP: "45.9.1.2"}}}
	modsec := &fakeModsec{verdict: Verdict{Bad: true, Reason: "x"}}
	bans := newFakeBans()
	bans.banErr = errors.New("valkey write failed")
	w := NewWorker(cons, modsec, bans, &fakeTTDF{}, fastCfg())

	_ = w.ProcessBatch(context.Background())
	if len(cons.ackedIDs()) != 0 {
		t.Error("a failed ban write must leave the job unacked for retry")
	}
}

func TestJobFromValues(t *testing.T) {
	j := jobFromValues("9-0", map[string]any{"ip": "1.2.3.4", "m": "POST", "p": "/x", "h": "h", "ua": "u", "ts": "1700000000000", "rid": "r"})
	if j.ID != "9-0" || j.IP != "1.2.3.4" || j.Method != "POST" || j.Path != "/x" || j.TS != 1700000000000 {
		t.Errorf("jobFromValues mismatch: %+v", j)
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	cons := &fakeConsumer{}
	w := NewWorker(cons, &fakeModsec{}, newFakeBans(), &fakeTTDF{}, fastCfg())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Run should return context.Canceled, got %v", err)
	}
}
