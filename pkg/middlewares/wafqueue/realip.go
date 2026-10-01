package wafqueue

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// DefaultRealIPHeaders is the ordered default list of headers consulted for the real client
// IP. CF-Connecting-IP is authoritative when the peer is a trusted Cloudflare edge.
var DefaultRealIPHeaders = []string{"CF-Connecting-IP", "X-Real-Ip", "X-Forwarded-For"}

// RealIPResolver resolves the real client IP from a request, honouring a trusted-proxy
// allowlist so an untrusted peer cannot spoof its identity via a header.
//
// This directly addresses project_modsec_waf_not_inspecting_real_client_ip: a WAF that keys
// on the proxy IP bans every client behind it. A header value is only trusted when the
// immediate peer (RemoteAddr) is a member of the trusted-proxy trie; otherwise the peer
// address itself is used.
type RealIPResolver struct {
	headers []string
	trusted *CIDRTrie
}

// NewRealIPResolver builds a resolver. Empty headers ⇒ DefaultRealIPHeaders.
func NewRealIPResolver(headers, trustedProxies []string) *RealIPResolver {
	hs := headers
	if len(hs) == 0 {
		hs = DefaultRealIPHeaders
	}
	return &RealIPResolver{
		headers: hs,
		trusted: BuildTrie(trustedProxies),
	}
}

// Resolve returns the real client IP for the request. It never errors: on any ambiguity it
// falls back to the peer address (fail-safe — we would rather inspect the proxy than block
// the wrong party).
func (r *RealIPResolver) Resolve(req *http.Request) netip.Addr {
	peer := peerAddr(req.RemoteAddr)

	// Only consult headers when the immediate peer is a trusted proxy.
	if peer.IsValid() && r.trusted.Contains(peer) {
		for _, h := range r.headers {
			v := req.Header.Get(h)
			if v == "" {
				continue
			}
			if addr, ok := firstTrustworthyIP(v); ok {
				return addr
			}
		}
	}
	return peer
}

// peerAddr extracts the IP from a RemoteAddr "ip:port" (or bare ip).
func peerAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	// Strip an IPv6 zone if present.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// firstTrustworthyIP returns the left-most parseable IP from a header value. For
// X-Forwarded-For the left-most entry is the originating client (traefik/CF prepend
// trustworthy left-most for the hops they control).
func firstTrustworthyIP(v string) (netip.Addr, bool) {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Some proxies include a port.
		if h, _, err := net.SplitHostPort(part); err == nil {
			part = h
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}
