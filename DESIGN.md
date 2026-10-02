# Async WAF for the Traefik fork — `feature/waf-queue` (Phase 1: shadow)

Status: **Phase 1 — SHADOW**. The middleware is compiled into the fork but defaults to
observe-only (`shadow: true`): it resolves, classifies, enqueues and emits metrics, but
**never blocks**. Enforcement (Phase 5) is a later, separately-gated flip.

This document is the source of truth for the valkey key schema, the middleware config, the
hot-path precedence, the degradation matrix, the metrics, and the shadow→enforce flip. It is
based on `project_traefik_waf_queue_async_2026_10_01` and must not drift from the code; if the
implementation diverges, update this file in the same change.

## 1. Why

The in-line modsec middleware (`waf-modsec`, `ModsecurityUrl`, `TimeoutMillis: 2000`,
`UnhealthyWafBackOffPeriodSecs: 30`) adds up to **2–3 s of pure latency** per request — the
engine is in `DetectionOnly` soak so the wait buys nothing but a log line. Under mx memory
thrash the modsec backend spikes to 1.6–5 s and traefik enters `marking modsec as unhealthy`
backoff loops.

The async WAF moves inspection **off** the request path: the hot path resolves the real
client IP, checks two in-memory CIDR tries (whitelist, blocklist), enqueues a compact job to
a valkey stream, and immediately calls the next handler. A separate `waf-worker` service
drains the stream, calls modsec out-of-band, and writes verdicts back to `waf:banned` (which
the next trie refresh folds into the blocklist). First flagged request passes; every
subsequent request from that IP is blocked — which kills scanners after request #1–2 without
putting modsec in anyone's critical path.

**Scope: the EXTERNAL traefik (`traefik_traefik`) only.** The internal traefik (`traefik-int`)
serves trusted VPC/service-to-service traffic where the real-IP/whitelist/blocklist model is
meaningless; it gets no WAF.

## 2. Hot path precedence (fail-open at every layer)

Order is fixed. Every step fails **open** (on any error → pass to the backend, never block).

1. **Resolve REAL client IP.** `RealIPHeaders` in order (default `CF-Connecting-IP`,
   `X-Real-Ip`, `X-Forwarded-For` left-most) — but a header is only trusted when the immediate
   peer (`RemoteAddr`) is in `TrustedProxies` (CF / CloudFront / internal LB / overlay). If the
   peer is not trusted, headers are ignored and `RemoteAddr` is used. Falls back to
   `RemoteAddr` when no header is present. This is the precondition tracked in
   `project_modsec_waf_not_inspecting_real_client_ip` — a WAF that bans the proxy IP bans
   everyone behind it.
2. **WHITELIST (highest precedence — beats every blocklist).** In-memory CIDR trie unioned
   from: CF edges, CloudFront edges, owner IPs + `EXCLUDE_IPS`, mobile/CGNAT ranges, and
   RFC1918/bogons. A whitelist hit → **pass immediately, never enqueued, never blocked.** This
   encodes the CLAUDE.md hard rule "never ban a CDN edge" and the mobile/CGNAT FP class.
3. **BLOCKLIST.** One in-memory CIDR trie (longest-prefix, 336k+ CIDRs) unioned from the TTDF
   shared blocklist + external feeds (Spamhaus DROP/EDROP, blocklist.de, AbuseIPDB, Firehol —
   already aggregated by the blocklist orchestrator) + `waf:banned` (worker detections). Match
   on the REAL IP → **block** (in shadow mode: log `would-block`, pass).
4. **SCOPE gate.** `ScopeSkip` regexes (static assets, stream `.ts/.aac/.m3u8`, health,
   `/.well-known/*`, mail-autodiscovery) → **pass, no enqueue.** Scope is checked *after* the
   blocklist so a known-bad IP is still blocked even on a static URL; scope only suppresses
   *inspection* of benign high-volume paths.
5. **ENQUEUE + PASS.** Hand the compact job to a **buffered channel** with a **non-blocking
   send** (`select { case jobs <- job: … default: drop }`), then `next.ServeHTTP` immediately.
   The request goroutine does **no valkey I/O** — it never dials, waits on, or times out
   against valkey. If the channel is full it **drops** the inspection job (`dropped`++) and
   passes anyway. The actual `XADD` happens on a separate background goroutine (see §2a).

`InlineRoutes` regexes (e.g. `/admin`, auth POSTs, mutating methods) are recorded for the
Phase-5 in-line sync-block path; in Phase 1 they are parsed and exposed but do not change hot
behaviour (everything is async).

## 2a. Two-plane architecture (the non-blocking guarantee)

The middleware is split into two planes that share **only** a bounded channel. This is the
core fix for the 2026-10-01 incident where a blocking enqueue added valkey's dial/write
timeout to **every** request while valkey was failing over — "fail-open after a timeout" still
pays the timeout, which is effectively blocking.

**Plane 1 — request hot path (the request goroutine).** Pure CPU + memory, **zero network
I/O**:
`resolve real IP → whitelist trie (atomic.Pointer, lock-free) → scope regex → blocklist trie
→ non-blocking channel send → next.ServeHTTP`. The tries are swapped atomically by the
refresher, so a reader never blocks on a rebuild. Nothing here can touch valkey, so nothing
here can wait on valkey.

**Plane 2 — background enqueuer (`enqueueLoop`, 4 goroutines).** Owns the valkey client,
drains the channel, and does the `XADD`. It is the *only* code that dials valkey on the
enqueue path. It is guarded by:

- **Buffered channel** (`jobs`, cap **8192**) with **drop-on-full**. The hot path's send is
  non-blocking; a full channel (valkey slow/down and the drain backed up) drops the job and
  increments `dropped`. The request still passes. This is the only backpressure the hot path
  can feel and it is a constant-time channel operation.
- **Circuit breaker** (`circuitbreaker.go`, threshold **3** consecutive failures, cooldown
  **2s**). On trip it **opens**: subsequent background flushes skip the valkey dial entirely
  (an `allow()` bool/time check, ~0 cost) so a dead valkey creates no dial storms and the
  channel drains instantly into drops. After the cooldown it **half-opens** for one probe — a
  success **closes** it, a failure **re-opens** it.
- **Tiny client timeouts** (`store.go`): dial/read/write = **50 ms**, pool = 100 ms,
  `MaxRetries = -1` (no command retries), `ContextTimeoutEnabled`. A background flush uses a
  100 ms context. So even a flush that does dial can never stall a worker for seconds.

**Guarantee (shadow AND enforce):** request latency is independent of valkey health. Proven by
`BenchmarkHotPath_ValkeyUp` vs `BenchmarkHotPath_ValkeyDown` (unroutable `192.0.2.1:6379`) —
equal ns/op — and by `TestHotPath_ValkeyBlackhole_NoAddedLatency` (worst request well under the
50 ms dial timeout with a dead valkey). In **enforce** mode a blocklist hit still blocks, but
that decision is a local in-memory trie lookup — never a valkey round-trip — so the
non-blocking property holds in both modes. The only thing a down valkey changes is that some
inspection jobs are dropped (counted), never that a request waits.

## 3. Valkey key schema

Backing store = the ttdf-valkey HA stack (master + replica + 3 sentinel) on mx. The client is
`github.com/redis/go-redis/v9` (sentinel `FailoverClient` when `ValkeySentinels`/`ValkeyMaster`
are set, otherwise a plain client on `ValkeyAddr`).

| Key | Type | Written by | Read by | Notes |
|-----|------|-----------|---------|-------|
| `waf:stream` | stream | middleware (`XADD`) | worker (`XREADGROUP`) | job queue; bounded `MAXLEN ~ StreamMaxLen` |
| `waf:banned` | set/hash of IP or CIDR → meta | worker | middleware (trie refresh) | each member carries a TTL; folded into the blocklist trie |
| `waf:banned:<ip>` | string w/ TTL | worker | — (TTL expiry) | per-IP TTL marker so bans auto-expire (`BanTTL`, default 1 h) |
| `waf:stats:requests` / `:blocks` / `:failopen` / `:enqueued` | counters | middleware + worker | dashboard / `/api/waf` | mirror of the Prometheus counters for the read-only API |
| `waf:wl:<name>` (`WhitelistKeys`) | set | blocklist orchestrator / CF+CloudFront refreshers | middleware | SMEMBERS → whitelist trie |
| `waf:bl:<name>` (`BlocklistKeys`) | set | blocklist orchestrator (reuse runtime.json/ipset pipeline) | middleware | SMEMBERS → blocklist trie |
| `waf:refresh` | pub/sub channel | orchestrator / worker | middleware | optional immediate-refresh signal (otherwise periodic `RefreshInterval`) |
| `waf:health:<node>` | string (JSON), TTL 30s | middleware (health heartbeat, every 5s) | dashboard / `/api/waf` | cached connection health: breaker state, last-ok timestamps, config echo. Absent/stale ⇒ node DOWN. Never the password |
| `waf:health:worker:<consumer>` | string (JSON), TTL 30s | worker (heartbeat, every 5s) | dashboard / `/api/waf` | worker liveness: last-consume, group, endpoint, throughput (1h/24h), modsec link health. Replica count = number of live keys |
| `waf:stats:worker:pm:<min>` / `:ph:<hour>` | counter, TTL 70m / 26h | worker (delta incr) | worker (rolling sum, published in heartbeat) | durable throughput buckets (processed 1h / 24h) |
| `waf:modsec:up` | string "1"/"0", TTL 45s | worker | dashboard / `/api/waf` | simple modsec-up bool mirror for the badge |

Stream job shape (one `XADD` field map, compact):

```
ip   = <real client IP>
m    = <HTTP method>
p    = <request path (no query)>
h    = <Host / X-Forwarded-Host>
ua   = <User-Agent, truncated>
ts   = <unix millis>
rid  = <request id, if present>
```

Whitelist precedence vs. every tier is maintained end-to-end exactly as
`feedback_whitelist_all_tiers`: a `whitelist:true` member must be honoured by the ipset
merger, the TTDF module, the DO LB applier **and** this trie. The worker never writes a
whitelisted IP to `waf:banned` (it re-checks the whitelist trie before banning).

## 4. Middleware config (`dynamic.WafQueue`)

Field (yaml) | Type | Default | Meaning
--- | --- | --- | ---
`valkeyAddr` | string | — | single-node valkey `host:port` (used when no sentinels)
`valkeySentinels` | []string | — | sentinel `host:port` list (HA)
`valkeyMaster` | string | — | sentinel master name
`valkeyPassword` | string | — | auth
`valkeyDB` | int | 0 | db index
`shadow` | *bool | **true** | observe-only; **nil/absent ⇒ true** (decoder-independent safe default). Only `shadow: false` can ever enable blocking.
`streamKey` | string | `waf:stream` | job stream
`streamMaxLen` | int64 | 1000000 | approx `MAXLEN` bound
`bannedKey` | string | `waf:banned` | ban set folded into blocklist
`whitelistKeys` | []string | — | valkey set keys → whitelist trie
`blocklistKeys` | []string | — | valkey set keys → blocklist trie
`statsPrefix` | string | `waf:stats:` | counter key prefix
`scopeSkip` | []string | built-in | regexes that skip enqueue (static/stream/health/well-known/autodiscovery)
`realIPHeaders` | []string | `CF-Connecting-IP,X-Real-Ip,X-Forwarded-For` | real-IP header order
`trustedProxies` | []string | — | CIDRs whose peer may set the real-IP header (CF/CloudFront/internal)
`inlineRoutes` | []string | — | regexes reserved for Phase-5 in-line sync block
`banTTL` | duration | 1h | default ban lifetime (worker)
`refreshInterval` | duration | 60s | trie refresh period
`blockStatus` | int | 403 | block response; `444` ⇒ drop the connection (no response)

`Shadow` is a pointer precisely so "default true" holds under **every** config provider —
the file (yaml) provider does not call `SetDefaults()` on nested dynamic structs, so a plain
`bool` would default to `false` (= enforce) and violate the Phase-1 safety guarantee. A
`SetDefaults()` is still provided for the label/KV path.

## 5. Degradation matrix

Every row's **effect on the request hot path is NONE** unless stated — the hot path does no
valkey I/O (§2a), so valkey/worker health cannot add request latency.

Condition | Hot-path effect | Behaviour
--- | --- | ---
valkey unreachable / enqueue error | **none** (background only) | background flush fails fast (≤100 ms ctx, 50 ms dial), `failopen{reason="valkey"}`++; after 3 failures the **circuit breaker opens** and subsequent flushes skip the dial entirely; tries keep last-known contents
job channel full | **none** (constant-time drop) | hot-path send is non-blocking; the job is **dropped** and `dropped`++; the request still passes. Caused by valkey slow/down backing up the drain
circuit breaker open | **none** | background flushes short-circuit without dialing for the 2 s cooldown, then one half-open probe; a dead valkey creates no dial storm
trie refresh fails | **none** (background) | keep **last-known** tries (feed-stale), `failopen{reason="refresh"}`; never empties a populated trie on a transient error
modsec down (worker) | **none** | worker **retries** with backoff; detection delayed; no ban written until a verdict is obtained
worker down entirely | **none** | stream grows to `StreamMaxLen` then trims oldest; bans simply stop being added
real-IP unresolvable | **none** | use `RemoteAddr`; a request is never blocked on an unverifiable identity (fail-open)
`shadow: true` (default) | **none** | full pipeline runs **except** the block — logs `would-block`, passes
block status misconfig (0) | — | treated as 403

The invariant: **no failure mode blocks legitimate traffic, and no failure mode adds request
latency.** Every error path is a pass, off the request goroutine.

## 6. Metrics (Prometheus)

Registered on a dedicated registry (see `metrics.go`); wiring into traefik's own
`/metrics` registry is a TODO (needs the observability middleware plumbing).

- `waf_requests_total{action}` — action ∈ {pass, whitelist, would_block, block, skip, enqueue}
- `waf_block_total{source}` — source ∈ {blocklist, banned, feed}
- `waf_queue_depth` — gauge, approx `XLEN waf:stream`
- `waf_hotpath_latency_seconds` — histogram of hot-path cost (target sub-ms)
- `waf_failopen_total{reason}` — reason ∈ {valkey, refresh, enqueue, resolve, **drop**} (`drop`
  = a hot-path enqueue dropped because the bounded channel was full)
- `waf_blocklist_size` / `waf_whitelist_size` — gauges, **true live trie entry counts** (the
  whitelist reports its full seeded size — ~233 CF/CloudFront/owner/CGNAT CIDRs — even when no
  valkey whitelist keys are configured; the blocklist is legitimately 0 in shadow)

**Per-node dashboard counters** (`waf:stats:<node>:<field>`, read by `/api/waf`): `pass`,
`whitelist`, `would_block`, `block`, `scoped`, `enqueue`, `failopen`, **`dropped`** (bounded-
channel drops), plus the `blocklist_size` / `whitelist_size` / `refresh_ts` gauges. These are
**cumulative hit counts since the task (re)started** — not list sizes — and differ between
nodes only by traffic volume (every node loads the same tries). The breaker's open/closed
state is observable via the `failopen{reason="valkey"}` rate when valkey is down.

Worker adds (see `cmd/waf-worker`): `waf_worker_processed_total`, `waf_worker_bad_total`,
`waf_worker_modsec_up`, `waf_worker_modsec_latency_seconds`, `waf_worker_retry_total`.

These flow vmagent → vmstorage → grafana for history/alerting (later phase).

## 7. waf-worker

Separate binary (`cmd/waf-worker`), a swarm service with replicas and a valkey consumer
group. Loop: `XREADGROUP` a batch from `waf:stream` → POST each job to the modsec endpoint
(the swarm VIP, configurable, with retries + exponential backoff + fail-open) → on a bad
verdict write `waf:banned` (+ per-IP TTL marker) and emit a structured log line + call the
TTDF ban-feed hook (TODO: wire to the real TTDF pipeline so nginx + DO LB + fail2ban enforce
fleet-wide). `XACK` after processing. Whitelisted IPs are re-checked and never banned.

Config via env/flags: `WAF_VALKEY_ADDR` / sentinels, `WAF_STREAM`, `WAF_GROUP`,
`WAF_CONSUMER`, `WAF_MODSEC_URL`, `WAF_BAN_TTL`, `WAF_BATCH`, `WAF_BLOCK_STATUS`.

## 8. Shadow → enforce flip (Phase 5, separately gated)

1. Phase 1 (this): compiled in, `shadow: true` everywhere. Validate detection parity vs the
   in-line modsec logs; confirm zero would-blocks on CF/CloudFront/mobile/owner.
2. Fix real-IP end-to-end first (the open precondition). A WAF that sees the proxy IP must
   never enforce.
3. Canary: roll ONE external-traefik replica with `shadow: false` on a test router behind a
   healthcheck-gated `--update-failure-action rollback`; verify routing + correct real-IP
   bans + CF/CloudFront/mobile never blocked.
4. Widen to all replicas; keep the previous image tag for instant
   `docker service rollback traefik_traefik`.
5. Fail-open means even an enforcement bug cannot black-hole traffic.

Nothing in Phase 1 deploys; the build is pushed to `localhost:5000` only.

## 9. Phase 2 — read-only `/api/waf` endpoint (native)

`feature/waf-queue` adds a native, **read-only** JSON endpoint that the dashboard WAF tab
(`feature/waf-dashboard`) consumes. It is registered on traefik's existing API router
(`pkg/api/handler.go` → `createRouter`), so it **inherits the dashboard/API router's auth and
host** (`tfmx.thetomtaylor.co.uk`) and is **never a new public route**. It is served only for
`GET`; any other method returns `405`.

### 9.1 Contract

`GET /api/waf[?limit=N]` → `200 application/json`. `limit` bounds the recent-bans list
(default 20, max 100). The endpoint is **fail-soft**: valkey unreachable or no WAF middleware
configured returns a `200` with `"degraded": true` and a `reason`, **never a `5xx`** — a valkey
outage can never take the dashboard down.

```jsonc
{
  "degraded": false,
  "reason": "",                 // set when degraded
  "timestamp": 1730000000000,
  "mode": "shadow",             // "shadow" | "enforce" | "unknown" (from the live middleware config)
  "middleware": "waf@file",
  "queue":  { "depth": 7, "pending": 3, "stream": "waf:stream", "group": "waf-workers" },
  "bans":   { "active": 12, "recent": [ { "ip": "1.2.3.4", "source": "modsec 403", "ttl": 3400, "expiresAt": 1730003400000 } ] },
  "lists":  { "blocklistSize": 336000, "whitelistSize": 1200, "blocklistKeys": ["waf:bl:main"], "whitelistKeys": ["waf:wl:cf"], "lastRefresh": 1730000000000 },
  "nodes":  { "mx01": { "pass": 100, "whitelist": 3, "wouldBlock": 2, "block": 5, "scoped": 40, "enqueue": 90, "failOpen": 1, "blocklistSize": 336000, "whitelistSize": 1200, "lastRefresh": 1730000000000 } },
  "totals": { "pass": 150, "block": 6, "enqueue": 135, "... (sum across nodes)": 0 },
  "modsec": { "available": false, "healthy": null }
}
```

### 9.2 Valkey reads (all cheap, read-only, swarm-wide because the store is shared)

| Field | valkey command(s) |
|-------|-------------------|
| `queue.depth` | `XLEN waf:stream` — the **retained stream length**, bounded by `streamMaxLen` and trimmed via `MAXLEN ~`. It does **not** shrink on `XACK` (only on trim), so a steady value is healthy, **not** a backlog. The dashboard labels it "Stream length (total events retained; trims at max-len)" |
| `queue.pending` (worker lag) | `XPENDING waf:stream waf-workers` (NOGROUP ⇒ 0) — the **real backlog**: jobs delivered to the consumer group but not yet `XACK`ed. 0–low = healthy. The dashboard presents this as the prominent health number |
| `bans.active` | `SCARD waf:banned` |
| `bans.recent` | `SSCAN waf:banned` (capped at 2000) → pipelined `PTTL`+`GET waf:banned:<ip>`, sorted by TTL remaining (most-recent first), top N |
| `lists.blocklistSize` / `whitelistSize` | `SCARD` over the middleware's `BlocklistKeys` / `WhitelistKeys` (and the per-node gauges, max) |
| `nodes.*`, `totals` | `SCAN waf:stats:*` → pipelined `GET` (see §9.3) |
| `modsec` | optional `GET waf:modsec:up` (reserved; the Phase-1 worker does not emit it yet) |

The valkey connection (addr / sentinels / master / password / db) and the key names are read
from the **live `WafQueue` middleware config** in the runtime configuration, so the endpoint
needs no separate wiring; `WAF_VALKEY_ADDR` / `WAF_VALKEY_SENTINELS` / `WAF_API_GROUP` env vars
override for an instance that only proxies. The reader is built lazily and cached; it is an
interface (`wafReader`) so the handler test substitutes a fake and asserts read-only + fail-soft
behaviour without a live valkey.

### 9.3 Per-node stats mirror (new)

Phase 1 wrote no stat counters (only a Prometheus registry). Phase 2 adds a tiny per-node
mirror so the dashboard has live rates without new request-path state:

- The hot path does only a **lock-free atomic increment** per action (`statsCollector.incr`).
- A background flusher (every 5 s, off the request path, fail-open) pipelines the accumulated
  deltas to valkey: **`INCRBY waf:stats:<node>:<action>`** for counters and **`SET`** for
  gauges, each with a sliding 1 h TTL so a departed node drops out of the aggregate.
- `<node>` = `WAF_NODE` env or the hostname. Actions: `pass`, `whitelist`, `would_block`,
  `block`, `scoped`, `enqueue`, `failopen`. Gauges: `blocklist_size`, `whitelist_size`,
  `refresh_ts`.

This supersedes the single-counter `waf:stats:requests`/`:blocks`/… row in §3 (those global
keys are ignored by the aggregator, which keys on `<node>:<field>`). The counters are a
best-effort dashboard mirror; Prometheus (§6) remains the source of truth for history/alerting.
The write path is behind the same fail-open guards as the rest of the middleware: a valkey
error during flush re-queues the deltas for the next tick and never touches live traffic.

### 9.4 Connection health + configuration (observability)

Added so valkey connection problems are visible at a glance (the gap during the 2026-10-01
outage). Two blocks in the `/api/waf` payload:

**`config`** — what the middleware is pointed at, built purely from the runtime config (**no
valkey I/O**, so it is present even when valkey is down). Never the password:
`endpoint`, `streamKey`, `streamMaxLen`, `db`, `authConfigured` (bool), `group`,
`dialTimeoutMs`/`readTimeoutMs`/`writeTimeoutMs` (50ms).

**`connection`** (per node) + **`connectionAgg`** (worst-state rollup) + **`worker`** — link
health. `state` ∈ {`connected` (green), `degraded` (amber, breaker open), `down` (red, stale/
absent heartbeat)}, plus `breakerState` (closed|open|half-open), `breakerOpenCount`,
`lastEnqueueOkMs`, `lastFlushOkMs`, `lastErrorMs`, `lastError` (redacted), `dropped`,
`heartbeatMs`, `stale`. `worker`: `group`, `replicas` (live heartbeats), `pending` (lag),
`lastConsumeMs`, `state`, `processed1h`/`processed24h` (throughput), and modsec link health
(`modsec.state` up/down/stale, `modsec.lastCheckMs`, `modsec.url`, `modsec.lastError`).

**Throughput (processed 1h/24h).** The worker counts acked jobs and, in its heartbeat (off the
consume path), buckets the delta into per-minute (`waf:stats:worker:pm:<min>`, 1h window) and
per-hour (`waf:stats:worker:ph:<hour>`, 24h window) valkey counters (durable across restarts via
TTL), then publishes the rolling sums in the heartbeat. `/api/waf` reads the cached sums — no
`XRANGE`/scan on the API path. A steady stream length with healthy throughput reads as WORKING.

**modsec link health.** The worker is the only component that talks to modsec. It records the
outcome of every real inspection and also sends a lightweight synthetic probe every ~30s
(fire-and-forget, bounded context — never blocks the consume loop), and publishes
`modsecState`/`lastCheckMs`/`url`/`lastError` in its heartbeat plus a `waf:modsec:up` bool.
`/api/waf` surfaces this as `modsec` (state/url/lastCheck/error) so the dashboard shows the
worker→modsec link is up and passing checks.

`lastEnqueueOkMs` = last successful background `XADD` (only advances when there is enqueue
traffic). `lastFlushOkMs` = last successful stats/health flush to valkey — written every ~5s
**whenever the link is up**, regardless of traffic. `connectionAgg` aggregates both as the
max across nodes, and the dashboard's **"Last valkey write"** uses the most recent of the two,
so a connected fleet always shows a fresh "Ns ago" (never a bare "—") even on idle nodes.

**The health mechanism is heartbeat-based, never a synchronous ping.** The handler must never
hang if valkey is down, so it does **not** issue a `PING`/`INFO`. Instead:

- The middleware's background plane publishes `waf:health:<node>` every 5s (`SET … EX 30`) with
  the **cached** circuit-breaker snapshot + last-success timestamps. The worker publishes
  `waf:health:worker:<consumer>` the same way. Both are off the request/consume path, bounded
  by the 50ms/200ms client timeouts.
- `/api/waf` reads those keys with its existing fail-soft bounded reads (the handler's own
  valkey client also uses fail-fast 100ms timeouts + `MaxRetries=-1`, so a blackholed valkey
  returns ~instantly as `degraded:true`). State is derived from the **cached** heartbeat:
  heartbeat older than 45s (TTL + headroom) or absent ⇒ `down`; `breakerState==open` ⇒
  `degraded`; else `connected`. If valkey is fully unreachable the canary read fails first and
  the whole response is `degraded:true` with `connectionAgg.state=down` — but `config` is still
  populated. The password is never serialised in any field.

## 10. Phase 2 — dashboard WAF tab (`feature/waf-dashboard`)

A read-only **WAF** tab is added to the existing traefik dashboard SPA (`webui/`, Faency +
TypeScript), modelled on the instance-name badge PR's component style. It is a permanent,
non-upstreamable fork branch carried through every rebase (same as the other `waf-*` branches).

- **Nav + route.** A `Security → WAF` entry is added to `webui/src/routes.tsx` (shield icon),
  which the existing `SideNavBar` renders automatically, plus a `/waf` route in
  `webui/src/App.tsx` and a `Waf` export from `webui/src/pages/index.ts`.
- **Data.** `webui/src/hooks/use-waf.ts` is an SWR hook that fetches `/waf` (→ `/api/waf` via
  the dashboard's `BASE_PATH`) and **polls every 5 s** (`WAF_POLL_INTERVAL`). Because the
  endpoint reads shared valkey, the tab is swarm-wide for free.
- **Page.** `webui/src/pages/waf/Waf.tsx` renders: a header with the SHADOW/ENFORCE mode badge
  + modsec-health badge; summary tiles (queue depth, worker lag, active bans, blocklist /
  whitelist sizes, last refresh); **per-node tiles** (pass / block / enqueue / whitelist /
  scoped / would-block / fail-open, with the mode + modsec badge and last-refresh); a
  **recent-bans table** (ip, source, ttl); and **top blocked CIDRs** (the recent bans grouped
  into `/24`s client-side). `degraded: true` shows a banner and still renders the partial
  state; a fetch error and the pre-data state render their own placeholders. This phase is
  strictly read-only — no unban / whitelist controls.
- **Tests.** `Waf.spec.tsx` (renders tiles / node card / recent bans, handles `degraded`, shows
  the loading state) and `use-waf.spec.ts` (fetches `/waf`, polls on `WAF_POLL_INTERVAL`).
  `tsc` + `eslint` clean.
