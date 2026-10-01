package dynamic

import (
	"time"

	ptypes "github.com/traefik/paerser/types"
)

// Default values for the WafQueue middleware.
const (
	// WafQueueDefaultStreamKey is the default valkey stream key for enqueued jobs.
	WafQueueDefaultStreamKey = "waf:stream"
	// WafQueueDefaultBannedKey is the default valkey key holding worker-detected bans.
	WafQueueDefaultBannedKey = "waf:banned"
	// WafQueueDefaultStatsPrefix is the default prefix for the mirror stat counters.
	WafQueueDefaultStatsPrefix = "waf:stats:"
	// WafQueueDefaultStreamMaxLen is the default approximate bound on the job stream.
	WafQueueDefaultStreamMaxLen int64 = 1000000
	// WafQueueDefaultBlockStatus is the default HTTP status returned when (and only when)
	// enforcement is enabled and a request is blocked.
	WafQueueDefaultBlockStatus = 403
)

// WafQueue holds the async WAF middleware configuration.
//
// The middleware resolves the real client IP, checks an in-memory whitelist and blocklist
// CIDR trie, enqueues a compact inspection job to a valkey stream, and passes the request to
// the backend immediately. Out-of-band, the waf-worker drains the stream, calls modsec, and
// writes verdicts back to waf:banned. Every step fails OPEN: on any error the request is
// passed, never blocked.
//
// Shadow is a pointer on purpose: "default true" (observe-only, cannot block) must hold under
// every configuration provider, and the file/yaml provider does not invoke SetDefaults on
// nested dynamic structs — a plain bool would default to false (enforce) and break the
// Phase-1 safety guarantee. nil or absent ⇒ shadow (observe-only); only an explicit
// shadow: false can ever enable blocking.
//
// +k8s:deepcopy-gen=true
type WafQueue struct {
	// ValkeyAddr is a single-node valkey host:port, used when no sentinels are configured.
	ValkeyAddr string `json:"valkeyAddr,omitempty" toml:"valkeyAddr,omitempty" yaml:"valkeyAddr,omitempty"`
	// ValkeySentinels is the list of sentinel host:port endpoints for an HA deployment.
	ValkeySentinels []string `json:"valkeySentinels,omitempty" toml:"valkeySentinels,omitempty" yaml:"valkeySentinels,omitempty"`
	// ValkeyMaster is the sentinel master name (required when ValkeySentinels is set).
	ValkeyMaster string `json:"valkeyMaster,omitempty" toml:"valkeyMaster,omitempty" yaml:"valkeyMaster,omitempty"`
	// ValkeyPassword is the optional valkey auth password.
	ValkeyPassword string `json:"valkeyPassword,omitempty" toml:"valkeyPassword,omitempty" yaml:"valkeyPassword,omitempty" loggable:"false"`
	// ValkeyDB is the valkey database index.
	ValkeyDB int `json:"valkeyDB,omitempty" toml:"valkeyDB,omitempty" yaml:"valkeyDB,omitempty" export:"true"`

	// Shadow, when nil or true, keeps the middleware observe-only: it classifies, enqueues
	// and logs would-block but never actually blocks. Only an explicit false enables blocking.
	Shadow *bool `json:"shadow,omitempty" toml:"shadow,omitempty" yaml:"shadow,omitempty" export:"true"`

	// StreamKey is the valkey stream the hot path XADDs jobs to.
	StreamKey string `json:"streamKey,omitempty" toml:"streamKey,omitempty" yaml:"streamKey,omitempty" export:"true"`
	// StreamMaxLen approximately bounds the job stream (XADD MAXLEN ~).
	StreamMaxLen int64 `json:"streamMaxLen,omitempty" toml:"streamMaxLen,omitempty" yaml:"streamMaxLen,omitempty" export:"true"`
	// BannedKey is the valkey set of worker-detected bans folded into the blocklist trie.
	BannedKey string `json:"bannedKey,omitempty" toml:"bannedKey,omitempty" yaml:"bannedKey,omitempty" export:"true"`
	// StatsPrefix is the prefix for the mirror stat counters read by /api/waf.
	StatsPrefix string `json:"statsPrefix,omitempty" toml:"statsPrefix,omitempty" yaml:"statsPrefix,omitempty" export:"true"`

	// WhitelistKeys are valkey set keys unioned into the whitelist CIDR trie.
	WhitelistKeys []string `json:"whitelistKeys,omitempty" toml:"whitelistKeys,omitempty" yaml:"whitelistKeys,omitempty"`
	// BlocklistKeys are valkey set keys unioned into the blocklist CIDR trie.
	BlocklistKeys []string `json:"blocklistKeys,omitempty" toml:"blocklistKeys,omitempty" yaml:"blocklistKeys,omitempty"`

	// ScopeSkip are regexes matched against the request path; a match skips enqueue (but not
	// the blocklist check). When empty a built-in set is used (static/stream/health/
	// well-known/autodiscovery).
	ScopeSkip []string `json:"scopeSkip,omitempty" toml:"scopeSkip,omitempty" yaml:"scopeSkip,omitempty"`
	// RealIPHeaders is the ordered list of headers consulted for the real client IP (only
	// when the immediate peer is a TrustedProxies member).
	RealIPHeaders []string `json:"realIPHeaders,omitempty" toml:"realIPHeaders,omitempty" yaml:"realIPHeaders,omitempty"`
	// TrustedProxies are CIDRs whose immediate peer may set a real-IP header.
	TrustedProxies []string `json:"trustedProxies,omitempty" toml:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	// InlineRoutes are regexes reserved for the Phase-5 in-line synchronous block path. They
	// are parsed and exposed but do not change Phase-1 (async) behaviour.
	InlineRoutes []string `json:"inlineRoutes,omitempty" toml:"inlineRoutes,omitempty" yaml:"inlineRoutes,omitempty"`

	// BanTTL is the default ban lifetime written by the worker.
	BanTTL ptypes.Duration `json:"banTTL,omitempty" toml:"banTTL,omitempty" yaml:"banTTL,omitempty" export:"true"`
	// RefreshInterval is the trie refresh period.
	RefreshInterval ptypes.Duration `json:"refreshInterval,omitempty" toml:"refreshInterval,omitempty" yaml:"refreshInterval,omitempty" export:"true"`
	// BlockStatus is the HTTP status returned when enforcement is on and a request is blocked.
	// 444 drops the connection without a response.
	BlockStatus int `json:"blockStatus,omitempty" toml:"blockStatus,omitempty" yaml:"blockStatus,omitempty" export:"true"`
}

// SetDefaults sets the default values for a WafQueue middleware. This is honoured by the
// label/KV decoders; the file (yaml) provider does not call it, which is why Shadow is a
// pointer that reads as true when nil (see IsShadow).
func (w *WafQueue) SetDefaults() {
	shadow := true
	w.Shadow = &shadow
	w.StreamKey = WafQueueDefaultStreamKey
	w.BannedKey = WafQueueDefaultBannedKey
	w.StatsPrefix = WafQueueDefaultStatsPrefix
	w.StreamMaxLen = WafQueueDefaultStreamMaxLen
	w.BlockStatus = WafQueueDefaultBlockStatus
	w.BanTTL = ptypes.Duration(time.Hour)
	w.RefreshInterval = ptypes.Duration(60 * time.Second)
}

// IsShadow reports whether the middleware is in observe-only mode. A nil Shadow (absent from
// the config, e.g. via the file provider) reads as true, so blocking requires an explicit
// shadow: false.
func (w *WafQueue) IsShadow() bool {
	return w.Shadow == nil || *w.Shadow
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WafQueue) DeepCopyInto(out *WafQueue) {
	*out = *in
	if in.ValkeySentinels != nil {
		in, out := &in.ValkeySentinels, &out.ValkeySentinels
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Shadow != nil {
		in, out := &in.Shadow, &out.Shadow
		*out = new(bool)
		**out = **in
	}
	if in.WhitelistKeys != nil {
		in, out := &in.WhitelistKeys, &out.WhitelistKeys
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.BlocklistKeys != nil {
		in, out := &in.BlocklistKeys, &out.BlocklistKeys
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ScopeSkip != nil {
		in, out := &in.ScopeSkip, &out.ScopeSkip
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.RealIPHeaders != nil {
		in, out := &in.RealIPHeaders, &out.RealIPHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TrustedProxies != nil {
		in, out := &in.TrustedProxies, &out.TrustedProxies
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.InlineRoutes != nil {
		in, out := &in.InlineRoutes, &out.InlineRoutes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is a deepcopy function, copying the receiver, creating a new WafQueue.
func (in *WafQueue) DeepCopy() *WafQueue {
	if in == nil {
		return nil
	}
	out := new(WafQueue)
	in.DeepCopyInto(out)
	return out
}
