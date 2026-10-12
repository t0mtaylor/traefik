package wafqueue

import (
	"fmt"
	"testing"
)

func TestRetryRing_FIFOandBoundedDropOldest(t *testing.T) {
	r := newRetryRing(3)
	for i := 1; i <= 5; i++ { // push 5 into cap 3 -> oldest 1,2 dropped
		r.push(enqueueJob{ip: fmt.Sprintf("%d", i)})
	}
	if r.length() != 3 {
		t.Fatalf("length=%d want 3 (bounded)", r.length())
	}
	buf, drop, _, held := r.snapshot()
	if buf != 5 || drop != 2 || held != 3 {
		t.Fatalf("buffered=%d dropped=%d held=%d want 5/2/3", buf, drop, held)
	}
	for _, w := range []string{"3", "4", "5"} { // FIFO order of the survivors
		j, ok := r.pop()
		if !ok || j.ip != w {
			t.Fatalf("pop=%q ok=%v want %q", j.ip, ok, w)
		}
	}
	if _, ok := r.pop(); ok {
		t.Fatal("ring should be empty")
	}
}

func TestRetryRing_NilSafe(t *testing.T) {
	var r *retryRing
	r.push(enqueueJob{ip: "1.1.1.1"})
	if _, ok := r.pop(); ok {
		t.Fatal("nil ring pop should be empty")
	}
	if r.length() != 0 {
		t.Fatal("nil ring length should be 0")
	}
	r.markReplayed()
	if b, d, rep, h := r.snapshot(); b|d|rep != 0 || h != 0 {
		t.Fatal("nil ring snapshot should be zero")
	}
}
