package main

import (
	"strconv"
	"testing"
	"time"
)

// TestBucketKeys verifies the throughput window key layout: index 0 is the current bucket, each
// subsequent key one step older, prefixed and deterministic (so the worker's incr target and the
// sum window line up exactly).
func TestBucketKeys(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)

	min := bucketKeys(tpMinutePrefix, now, 60, 60)
	if len(min) != 60 {
		t.Fatalf("minute keys=%d want 60", len(min))
	}
	base := now.Unix() / 60
	if min[0] != tpMinutePrefix+strconv.FormatInt(base, 10) {
		t.Fatalf("min[0]=%s want current bucket", min[0])
	}
	if min[59] != tpMinutePrefix+strconv.FormatInt(base-59, 10) {
		t.Fatalf("min[59]=%s want 59 buckets back", min[59])
	}

	hr := bucketKeys(tpHourPrefix, now, 3600, 24)
	if len(hr) != 24 {
		t.Fatalf("hour keys=%d want 24", len(hr))
	}
	hbase := now.Unix() / 3600
	if hr[0] != tpHourPrefix+strconv.FormatInt(hbase, 10) || hr[23] != tpHourPrefix+strconv.FormatInt(hbase-23, 10) {
		t.Fatalf("hour window wrong: %s .. %s", hr[0], hr[23])
	}

	// Keys must be unique (no accidental overlap that would double-count).
	seen := map[string]bool{}
	for _, k := range append(append([]string{}, min...), hr...) {
		if seen[k] {
			t.Fatalf("duplicate bucket key %s", k)
		}
		seen[k] = true
	}
}
