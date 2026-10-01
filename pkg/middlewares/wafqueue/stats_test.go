package wafqueue

import (
	"context"
	"errors"
	"testing"
)

func TestStatsCollector_FlushPipelinesCountersAndGauges(t *testing.T) {
	fs := &fakeStore{}
	sc := newStatsCollector(fs, "waf:stats:", "mxtest")
	sc.incr(statPass)
	sc.incr(statPass)
	sc.incr(statBlock)
	sc.incr("unknown-action") // ignored, no counter registered
	sc.setGauge(statBlocklistSize, 42)

	sc.flush(context.Background())

	if got := fs.flushIncr["waf:stats:mxtest:pass"]; got != 2 {
		t.Fatalf("pass=%d want 2", got)
	}
	if got := fs.flushIncr["waf:stats:mxtest:block"]; got != 1 {
		t.Fatalf("block=%d want 1", got)
	}
	if _, ok := fs.flushIncr["waf:stats:mxtest:unknown-action"]; ok {
		t.Fatalf("unknown action must not be flushed")
	}
	if got := fs.flushSet["waf:stats:mxtest:blocklist_size"]; got != 42 {
		t.Fatalf("blocklist_size=%d want 42", got)
	}

	// Counters reset after a flush: a second flush writes no new deltas.
	fs.flushIncr = nil
	sc.flush(context.Background())
	if _, ok := fs.flushIncr["waf:stats:mxtest:pass"]; ok {
		t.Fatalf("counters should reset to zero after a flush")
	}
}

func TestStatsCollector_FailOpenReaddsDeltas(t *testing.T) {
	fs := &fakeStore{flushErr: errors.New("valkey down")}
	sc := newStatsCollector(fs, "waf:stats:", "mxtest")
	sc.incr(statEnqueue)
	sc.flush(context.Background()) // errors → delta re-added

	fs.flushErr = nil
	sc.flush(context.Background()) // retries the delta
	if got := fs.flushIncr["waf:stats:mxtest:enqueue"]; got != 1 {
		t.Fatalf("enqueue=%d want 1 (delta must be retried after a fail-open flush)", got)
	}
}

func TestStatsCollector_NilAndNilStoreAreNoops(t *testing.T) {
	var sc *statsCollector
	sc.incr(statPass) // must not panic
	sc.setGauge(statBlocklistSize, 1)
	sc.flush(context.Background())

	sc2 := newStatsCollector(nil, "", "mxtest")
	sc2.incr(statPass)
	sc2.flush(context.Background()) // nil store: no-op, no panic
}
