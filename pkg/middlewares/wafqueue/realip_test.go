package wafqueue

import (
	"net/http"
	"testing"
)

func newReq(remoteAddr string, headers map[string]string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestRealIP_UntrustedPeer_IgnoresHeaders(t *testing.T) {
	// Peer is NOT a trusted proxy ⇒ headers must be ignored (anti-spoof).
	r := NewRealIPResolver(nil, []string{"10.0.0.0/8"})
	got := r.Resolve(newReq("203.0.113.9:4444", map[string]string{
		"CF-Connecting-IP": "1.2.3.4",
		"X-Forwarded-For":  "5.6.7.8",
	}))
	if got.String() != "203.0.113.9" {
		t.Fatalf("untrusted peer: got %s, want the peer 203.0.113.9", got)
	}
}

func TestRealIP_TrustedPeer_HeaderOrder(t *testing.T) {
	r := NewRealIPResolver(nil, []string{"10.0.0.0/8"})
	// Peer is a trusted internal proxy; CF-Connecting-IP has highest priority.
	got := r.Resolve(newReq("10.106.0.33:5555", map[string]string{
		"CF-Connecting-IP": "198.51.100.23",
		"X-Real-Ip":        "198.51.100.99",
		"X-Forwarded-For":  "198.51.100.77, 10.106.0.33",
	}))
	if got.String() != "198.51.100.23" {
		t.Fatalf("CF-Connecting-IP should win: got %s", got)
	}
}

func TestRealIP_TrustedPeer_FallThroughHeaders(t *testing.T) {
	r := NewRealIPResolver(nil, []string{"10.0.0.0/8"})
	// No CF header; falls through to X-Real-Ip.
	got := r.Resolve(newReq("10.106.0.33:5555", map[string]string{
		"X-Real-Ip":       "198.51.100.99",
		"X-Forwarded-For": "198.51.100.77",
	}))
	if got.String() != "198.51.100.99" {
		t.Fatalf("X-Real-Ip should be used: got %s", got)
	}
}

func TestRealIP_XFF_LeftMost(t *testing.T) {
	r := NewRealIPResolver([]string{"X-Forwarded-For"}, []string{"10.0.0.0/8"})
	got := r.Resolve(newReq("10.106.0.33:5555", map[string]string{
		"X-Forwarded-For": "198.51.100.5, 70.1.1.1, 10.106.0.33",
	}))
	if got.String() != "198.51.100.5" {
		t.Fatalf("XFF left-most should be the client: got %s", got)
	}
}

func TestRealIP_NoHeaders_UsesPeer(t *testing.T) {
	r := NewRealIPResolver(nil, []string{"10.0.0.0/8"})
	got := r.Resolve(newReq("10.106.0.33:5555", nil))
	if got.String() != "10.106.0.33" {
		t.Fatalf("no header: should fall back to peer, got %s", got)
	}
}

func TestRealIP_BareRemoteAddr(t *testing.T) {
	r := NewRealIPResolver(nil, nil)
	got := r.Resolve(newReq("203.0.113.5", nil))
	if got.String() != "203.0.113.5" {
		t.Fatalf("bare remoteaddr: got %s", got)
	}
}
