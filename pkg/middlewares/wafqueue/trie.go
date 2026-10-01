package wafqueue

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// CIDRTrie is a binary (per-bit) prefix trie supporting longest-prefix match over a large
// set of CIDRs (hundreds of thousands). IPv4 and IPv6 are kept in separate arenas so the
// walk depth is bounded by the address width (32 / 128 bits).
//
// Nodes live in a slice arena addressed by uint32 index; index 0 is the nil sentinel and
// index 1 is the root. This halves pointer memory versus *node and keeps children
// cache-local, which matters at ~300k+ entries.
//
// A CIDRTrie is immutable once built (Add is only called during construction). Concurrent
// readers call Contains without locking; the live trie is swapped atomically by Matcher.
type CIDRTrie struct {
	nodes4 []trieNode
	nodes6 []trieNode
	count  int
}

type trieNode struct {
	children [2]uint32 // 0 == nil
	plen     uint8     // prefix length of a terminal (valid only when terminal)
	terminal bool
}

const (
	nilIdx  uint32 = 0
	rootIdx uint32 = 1
)

// NewCIDRTrie returns an empty trie ready for Add.
func NewCIDRTrie() *CIDRTrie {
	return &CIDRTrie{
		// index 0 = nil sentinel, index 1 = root.
		nodes4: []trieNode{{}, {}},
		nodes6: []trieNode{{}, {}},
	}
}

// Len returns the number of prefixes inserted.
func (t *CIDRTrie) Len() int { return t.count }

func (t *CIDRTrie) arena(is4 bool) *[]trieNode {
	if is4 {
		return &t.nodes4
	}
	return &t.nodes6
}

// Add inserts a prefix. Invalid prefixes are ignored. Not safe for concurrent use.
func (t *CIDRTrie) Add(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	addr := p.Addr()
	bits := p.Bits()
	// Normalise a v4-mapped v6 prefix (e.g. ::ffff:a.b.c.0/120) to plain v4: the address drops
	// to 4 bytes, so the prefix length must drop the 96-bit mapping prefix too.
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
		if bits < 0 {
			bits = 0
		}
	}
	is4 := addr.Is4()
	nodes := t.arena(is4)

	var raw []byte
	if is4 {
		b := addr.As4()
		raw = b[:]
	} else {
		b := addr.As16()
		raw = b[:]
	}
	if max := len(raw) * 8; bits > max {
		bits = max
	}

	cur := rootIdx
	for i := 0; i < bits; i++ {
		bit := (raw[i>>3] >> (7 - uint(i&7))) & 1
		next := (*nodes)[cur].children[bit]
		if next == nilIdx {
			*nodes = append(*nodes, trieNode{})
			next = uint32(len(*nodes) - 1)
			(*nodes)[cur].children[bit] = next
		}
		cur = next
	}
	if !(*nodes)[cur].terminal {
		t.count++
	}
	(*nodes)[cur].terminal = true
	(*nodes)[cur].plen = uint8(bits)
}

// Contains reports whether addr is covered by any inserted prefix. Safe for concurrent use.
func (t *CIDRTrie) Contains(addr netip.Addr) bool {
	_, ok := t.LongestPrefix(addr)
	return ok
}

// LongestPrefix returns the longest matching prefix length and whether a match was found.
// Safe for concurrent use.
func (t *CIDRTrie) LongestPrefix(addr netip.Addr) (int, bool) {
	if !addr.IsValid() {
		return 0, false
	}
	addr = addr.Unmap()
	is4 := addr.Is4()
	nodes := t.nodes4
	if !is4 {
		nodes = t.nodes6
	}

	var raw []byte
	if is4 {
		b := addr.As4()
		raw = b[:]
	} else {
		b := addr.As16()
		raw = b[:]
	}

	bestLen := 0
	found := false
	cur := rootIdx
	// A /0 terminal at the root matches everything.
	if nodes[cur].terminal {
		bestLen, found = int(nodes[cur].plen), true
	}
	total := len(raw) * 8
	for i := 0; i < total; i++ {
		bit := (raw[i>>3] >> (7 - uint(i&7))) & 1
		next := nodes[cur].children[bit]
		if next == nilIdx {
			break
		}
		cur = next
		if nodes[cur].terminal {
			bestLen, found = int(nodes[cur].plen), true
		}
	}
	return bestLen, found
}

// Matcher holds a swappable CIDRTrie so the refresher can replace the whole set atomically
// while hot-path readers keep using the previous one (never a partially-built trie).
type Matcher struct {
	v atomic.Pointer[CIDRTrie]
	// buildMu serialises builders so two refreshers do not race to swap.
	buildMu sync.Mutex
}

// NewMatcher returns a Matcher backed by an empty trie (fail-open: empty ⇒ no match).
func NewMatcher() *Matcher {
	m := &Matcher{}
	m.v.Store(NewCIDRTrie())
	return m
}

// Swap atomically replaces the live trie.
func (m *Matcher) Swap(t *CIDRTrie) {
	if t == nil {
		return
	}
	m.v.Store(t)
}

// Contains reports membership against the live trie.
func (m *Matcher) Contains(addr netip.Addr) bool {
	return m.v.Load().Contains(addr)
}

// LongestPrefix returns the longest matching prefix length against the live trie.
func (m *Matcher) LongestPrefix(addr netip.Addr) (int, bool) {
	return m.v.Load().LongestPrefix(addr)
}

// Len returns the entry count of the live trie.
func (m *Matcher) Len() int { return m.v.Load().Len() }

// BuildLock serialises builders; the caller builds a fresh trie then Swaps it.
func (m *Matcher) BuildLock() func() {
	m.buildMu.Lock()
	return m.buildMu.Unlock
}

// BuildTrie builds a CIDRTrie from a list of CIDR / bare-IP strings. Unparseable entries are
// skipped. A bare IP is treated as a host route (/32 or /128).
func BuildTrie(entries []string) *CIDRTrie {
	t := NewCIDRTrie()
	for _, e := range entries {
		p, ok := ParseEntry(e)
		if ok {
			t.Add(p)
		}
	}
	return t
}

// ParseEntry parses a CIDR or a bare IP into a prefix. Reports ok=false on garbage.
func ParseEntry(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), true
	}
	return netip.Prefix{}, false
}
