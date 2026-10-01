# wafqueue — async WAF middleware (traefik fork)

`wafqueue` is a native traefik middleware (compiled into the fork, **not** a Yaegi plugin)
that moves WAF inspection off the request critical path. On each request it resolves the real
client IP, checks an in-memory whitelist and blocklist CIDR trie, enqueues a compact
inspection job onto a valkey stream, and immediately calls the next handler. The out-of-band
[`waf-worker`](../../../cmd/waf-worker) drains the stream, inspects via modsec, and writes
bans back to `waf:banned`.

It **fails open at every layer** (any error → pass, never block) and defaults to **shadow**
(observe-only) mode, so it can never take traffic down. See [`DESIGN.md`](../../../DESIGN.md)
for the full architecture, valkey key schema, degradation matrix, and the shadow→enforce flip.

## Hot-path precedence

1. Resolve the real client IP (`RealIPHeaders`, trusted only when the peer is in `TrustedProxies`).
2. **Whitelist** (highest precedence — CF/CloudFront/owner/mobile beats any blocklist) → pass.
3. **Blocklist** (longest-prefix over 300k+ CIDRs) → block (shadow: log `would-block`, pass).
4. **Scope** skip (`ScopeSkip`: static/stream/health/well-known/autodiscovery) → pass, no enqueue.
5. **Enqueue** (bounded, fire-and-forget) + pass.

The blocklist is checked **before** scope, so a known-bad IP is blocked even on a static URL;
scope only suppresses *inspection* of benign high-volume paths.

## Configuration

Dynamic middleware config (file/yaml provider shown). `shadow` is a pointer: **absent ⇒ true**
(observe-only). Only an explicit `shadow: false` enables blocking.

```yaml
http:
  middlewares:
    my-waf:
      wafQueue:
        # --- valkey (HA via sentinel, or a single addr) ---
        valkeySentinels:
          - 10.0.7.11:26379
          - 10.0.7.12:26379
          - 10.0.7.13:26379
        valkeyMaster: ttdf-valkey
        # valkeyAddr: 127.0.0.1:6379   # alternative to sentinels
        valkeyPassword: ""
        valkeyDB: 0

        # --- mode (PHASE 1: keep true) ---
        shadow: true                    # observe-only; never blocks
        blockStatus: 403                # 444 => drop the connection (enforce only)

        # --- queue ---
        streamKey: waf:stream
        streamMaxLen: 1000000
        bannedKey: waf:banned

        # --- lists (valkey set keys unioned into the tries) ---
        whitelistKeys: [waf:wl:cloudflare, waf:wl:cloudfront, waf:wl:owner, waf:wl:mobile]
        blocklistKeys: [waf:bl:ttdf, waf:bl:spamhaus, waf:bl:firehol]
        refreshInterval: 60s

        # --- real IP (anti-spoof) ---
        realIPHeaders: [CF-Connecting-IP, X-Real-Ip, X-Forwarded-For]
        trustedProxies: [10.0.0.0/8, 172.16.0.0/12, 103.21.244.0/22, 104.16.0.0/13]

        # --- scope (defaults shown; omit to use built-ins) ---
        scopeSkip:
          - '\.(?:ts|aac|m3u8|mp3|js|css|png|jpe?g|svg|ico|woff2?)(?:$|\?)'
          - '^/\.well-known/'
          - '(?i)^/(?:autodiscover|autoconfig)'

        # --- reserved for Phase 5 (in-line sync block) ---
        inlineRoutes: ['^/admin', '^/wp-login\.php']
        banTTL: 1h
```

Attach per-router (the fork attaches the WAF chain per-router, never at the entrypoint — see
`project_modsec_waf_not_inspecting_real_client_ip`). Scope: the **external** traefik only.

## Fields

See the godoc on `dynamic.WafQueue` (`pkg/config/dynamic/wafqueue.go`) and the table in
`DESIGN.md` §4.

## Metrics

Prometheus collectors on a dedicated registry (`NewMetrics`): `waf_requests_total{action}`,
`waf_block_total{source}`, `waf_queue_depth`, `waf_hotpath_latency_seconds`,
`waf_failopen_total{reason}`, `waf_blocklist_size`, `waf_whitelist_size`. Wiring into traefik's
own `/metrics` registry is a TODO (see `metrics.go`).

## Safety invariants (tested)

- Whitelist beats blocklist (CF/CloudFront/owner/mobile never blocked).
- Bans key on the **real** client IP, never the proxy/edge.
- Shadow mode never blocks; every error path passes (fail-open).
- Static/stream/health/well-known/autodiscovery are scoped off (no enqueue).

Run the tests:

```sh
go test -race ./pkg/middlewares/wafqueue/... ./cmd/waf-worker/...
```
