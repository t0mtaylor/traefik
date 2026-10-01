package wafqueue

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func TestTrie_Contains_Basic(t *testing.T) {
	tr := NewCIDRTrie()
	tr.Add(mustPrefix(t, "10.0.0.0/8"))
	tr.Add(mustPrefix(t, "192.168.1.0/24"))
	tr.Add(mustPrefix(t, "2001:db8::/32"))

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"192.168.1.42", true},
		{"192.168.2.1", false},
		{"11.0.0.1", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
	}
	for _, c := range cases {
		if got := tr.Contains(mustAddr(t, c.ip)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestTrie_LongestPrefixMatch(t *testing.T) {
	tr := NewCIDRTrie()
	tr.Add(mustPrefix(t, "10.0.0.0/8"))
	tr.Add(mustPrefix(t, "10.1.0.0/16"))
	tr.Add(mustPrefix(t, "10.1.2.0/24"))

	// The deepest covering prefix must win.
	plen, ok := tr.LongestPrefix(mustAddr(t, "10.1.2.5"))
	if !ok || plen != 24 {
		t.Fatalf("LongestPrefix(10.1.2.5) = (%d,%v), want (24,true)", plen, ok)
	}
	plen, ok = tr.LongestPrefix(mustAddr(t, "10.1.9.9"))
	if !ok || plen != 16 {
		t.Fatalf("LongestPrefix(10.1.9.9) = (%d,%v), want (16,true)", plen, ok)
	}
	plen, ok = tr.LongestPrefix(mustAddr(t, "10.9.9.9"))
	if !ok || plen != 8 {
		t.Fatalf("LongestPrefix(10.9.9.9) = (%d,%v), want (8,true)", plen, ok)
	}
}

func TestTrie_DefaultRoute(t *testing.T) {
	tr := NewCIDRTrie()
	tr.Add(mustPrefix(t, "0.0.0.0/0"))
	if !tr.Contains(mustAddr(t, "8.8.8.8")) {
		t.Error("0.0.0.0/0 should match everything")
	}
}

func TestTrie_BareIPAndMappedV4(t *testing.T) {
	tr := BuildTrie([]string{"203.0.113.7", "::ffff:198.51.100.0/120"})
	if !tr.Contains(mustAddr(t, "203.0.113.7")) {
		t.Error("bare IP should become a host route")
	}
	if tr.Contains(mustAddr(t, "203.0.113.8")) {
		t.Error("host route must not over-match")
	}
	// A v4-mapped v6 prefix must match the plain v4 address (Unmap normalisation).
	if !tr.Contains(mustAddr(t, "198.51.100.5")) {
		t.Error("v4-mapped prefix should match the unmapped v4 address")
	}
}

func TestParseEntry_Garbage(t *testing.T) {
	for _, s := range []string{"", "not-an-ip", "10.0.0.0/999", "999.1.1.1"} {
		if _, ok := ParseEntry(s); ok {
			t.Errorf("ParseEntry(%q) unexpectedly ok", s)
		}
	}
}

func TestMatcher_AtomicSwap(t *testing.T) {
	m := NewMatcher()
	if m.Contains(mustAddr(t, "1.2.3.4")) {
		t.Error("empty matcher must not match (fail-open)")
	}
	m.Swap(BuildTrie([]string{"1.2.3.0/24"}))
	if !m.Contains(mustAddr(t, "1.2.3.4")) {
		t.Error("after swap, should match")
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
}

// gen300k builds ~300k pseudo-random /24s plus a handful of needles.
func gen300kCIDRs() ([]string, []netip.Addr) {
	r := rand.New(rand.NewSource(42))
	n := 300000
	entries := make([]string, 0, n)
	for i := 0; i < n; i++ {
		a := r.Intn(223) + 1
		b := r.Intn(256)
		c := r.Intn(256)
		entries = append(entries, fmt.Sprintf("%d.%d.%d.0/24", a, b, c))
	}
	// Needles guaranteed present and absent.
	entries = append(entries, "100.64.5.0/24")
	needles := []netip.Addr{
		netip.MustParseAddr("100.64.5.99"), // present
		netip.MustParseAddr("8.8.8.8"),     // (likely) absent
	}
	return entries, needles
}

func TestTrie_Large(t *testing.T) {
	entries, needles := gen300kCIDRs()
	tr := BuildTrie(entries)
	if tr.Len() < 200000 {
		t.Fatalf("expected a large trie, got Len=%d", tr.Len())
	}
	if !tr.Contains(needles[0]) {
		t.Error("known-present needle not found")
	}
}

func BenchmarkTrie_Build300k(b *testing.B) {
	entries, _ := gen300kCIDRs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildTrie(entries)
	}
}

func BenchmarkTrie_Lookup300k(b *testing.B) {
	entries, needles := gen300kCIDRs()
	tr := BuildTrie(entries)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tr.Contains(needles[i%len(needles)])
	}
}
