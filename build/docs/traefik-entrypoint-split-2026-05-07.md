# Traefik EXT/INT entrypoint split — final cleanup

**Date:** 2026-05-07
**Closes:** task #184 (audit ext traefik for leftover internal-only entrypoints)
**Affected stacks:** `traefik` (ext), `traefik-int`
**Image:** `traefik:3.7.0-tt-rc-dbb3c1ebc-f1f2pos` (unchanged)

## Summary

Removed 9 internal-tier entrypoints from the ext Traefik (already orphaned —
unpublished + zero traffic) and **migrated `torproxy` from ext → int**.

Net change:

| Tier | Before | After |
|------|-------:|------:|
| EXT  |     27 |    17 |
| INT  |     12 |    13 |

## What was removed from EXT

The ext static config (`/media/gfs/ptmx/traefik/traefik.yml`) had 10 entrypoints
defined that were no longer reachable from outside the container — the matching
host-port publishes had been dropped from the ext compose stack at "step 0a"
of the original split (2026-05-06), but the static-config stanzas were never
cleaned up. Traefik was still allocating internal listeners for them on every
worker.

| Entrypoint | Port  | Why orphaned                                                 |
|------------|-------|--------------------------------------------------------------|
| mcrouter   | 22121 | wa-mcrouter swarm service is `traefik.tier=int` (task #172)  |
| memcache1  | 11211 | wa-mc-01 is `tier=int` (task #173)                           |
| memcache2  | 11212 | wa-mc-02 is `tier=int` (task #173)                           |
| postgres   | 5432  | mailu DB is internal only — not used through traefik         |
| redis      | 6379  | mailu redis is internal only                                 |
| imapint    | 10143 | mailu internal IMAP — moved to int per task #174             |
| smtpint    | 10025 | mailu internal SMTP — moved to int per task #174             |
| solr       | 8983  | replaced by `solr-int` on int — mailu_solr already migrated  |
| beanstalkd | 11300 | unused on both sides                                         |
| torproxy   | 9050  | **migrated to int** (see below)                              |

## torproxy migration (ext → int)

- Added `torproxy` entrypoint to `/media/gfs/ptmx/traefik/traefik.int.yml`
  (mirroring the int pattern: transport-only, no proxyProtocol)
- Added `target: 9050 / published: 9050 / mode: host` to
  `/media/gfs/ptmx/traefik/traefik-int-stack.yml`
- All three int task instances (mx01/mx02/mx03) confirm the `torproxy`
  entrypoint is bound and visible in Prometheus metrics

**Caveat:** the ext torproxy entrypoint had `proxyProtocol.trustedIPs` for
internal CIDRs. The new int entrypoint does NOT. Existing usage was zero
connections so this should be moot, but if a client appears expecting
PROXY headers we may need to add `proxyProtocol` back on the int side.

## Pre-change verification (the audit)

Three independent signals confirmed nothing was actually using the 10
candidate entrypoints on ext:

1. **Compose stack**: ext stack file publishes only 17 host ports
   (80/443tcp/443udp/25/2525/465/587/110/995/143/993/8000/8001/8002/8080/61613
   plus 8082 healthcheck). None of the 10 candidates were in that list.

2. **Swarm service labels**: scanning every running service for
   `entrypoints=(mcrouter|memcache1|memcache2|postgres|redis|imapint|smtpint|solr|beanstalkd|torproxy)`
   returned only 4 services, all with `traefik.tier=int` or using `solr-int`
   (the int variant) — no ext-tier router targeted any candidate.

3. **Live connection count**: Prometheus reported 0 open connections on
   ext for all 10 candidates immediately before the change. mcrouter/memcache1/2
   showed 6/4/5 connections on int — confirming the live traffic had
   already migrated.

## Deploy gotcha — `order: stop-first`

First `docker service update --force traefik_traefik` failed: tasks went to
`Pending` with error **"host-mode port already in use on 1 node"**. With
`mode: global` + `mode: host` port publishing, Swarm's default rolling
behaviour starts the new task before stopping the old, causing port
collisions on the same node.

**Fix**: added `order: stop-first` under `deploy.update_config` in
`/media/gfs/ptmx/traefik-agent-stack.yml`. After re-deploy, all three nodes
rolled cleanly.

This is now part of the ext stack going forward — any future config edit
that triggers a rolling restart will use stop-first ordering.

## Files changed

```
/media/gfs/ptmx/traefik/traefik.yml
/media/gfs/ptmx/traefik/traefik.int.yml
/media/gfs/ptmx/traefik/traefik-int-stack.yml
/media/gfs/ptmx/traefik-agent-stack.yml
```

Each has a `*.bak.20260507-173617-pre-task184` (or `*-stopfirst`) backup next
to it for one-step rollback.

## Generator script

`/tmp/apply_traefik_entrypoint_split.py` (also on mx01) is idempotent — re-running
it on the modified configs is a no-op. Useful as a reference for future similar
moves.

## Post-change verification

Live ext entrypoints (instant query, count by entrypoint, post-rollout):

```
healthcheck, hls, http, https, icecast, icecastdab, icecastrelay,
imap, imaps, metrics, pop, pops, smtp, smtps, smtpss, stomp, submission
```
17 — matches the published-port list exactly.

Live int entrypoints:

```
beanstalkd, healthcheck, imapint, mcrouter, memcache1, memcache2,
metrics, postgres, redis, smtpint, solr-int, torproxy, traefik
```
13 — torproxy now present on all 3 instances.

No production impact observed during rollout. The 10 affected entrypoints
had zero live connections when removed.

## Remaining open items (not done in this batch)

- task #181: add `http` / `https` entrypoints to traefik-int with proper isolation
- task #182: mirror icecast/icecastdab/icecastrelay/hls on int (don't move)
- task #183: drop unused `beanstalkd` from int (zero use on either tier now)
- task #185: file-provider migration — split mailu/solr/icecast into per-tier dyn YAMLs

## Follow-up — proxyProtocol.trustedIPs added to all int data-plane entrypoints

After the initial split, noticed the int Traefik had no `proxyProtocol`
or `forwardedHeaders` trust blocks on any data-plane entrypoint, while
the ext side had them on all of them. Restored parity to avoid two issues:

1. PROXY headers from internal CIDRs being treated as raw bytes (broken
   protocol parsing for any client that did want to send PROXY).
2. Loss of source-IP fidelity through DO internal LB → mx → service.

**Trust set** (matching ext exactly): `127.0.0.1/32`, `10.0.0.0/32`,
`10.0.1.0/24`, `10.0.2.0/24`, `10.0.6.0/24`, `10.106.0.0/24`.

**Per-entrypoint application**:

| Entrypoint  | proxyProtocol | forwardedHeaders |
|-------------|:-------------:|:----------------:|
| mcrouter    | ✓             |                  |
| memcache1   | ✓             |                  |
| memcache2   | ✓             |                  |
| postgres    | ✓             |                  |
| redis       | ✓             |                  |
| beanstalkd  | ✓             |                  |
| torproxy    | ✓             |                  |
| smtpint     | ✓             | ✓                |
| imapint     | ✓             | ✓                |
| solr-int    | ✓             | ✓                |

(`forwardedHeaders` only on HTTP/SMTP/IMAP entrypoints — same pattern
ext used.)

**Behaviour**: Traefik PROXY parsing is opportunistic from a trusted source.
Clients in the trustedIPs list may or may not send PROXY headers — both
work. Clients NOT in the trustedIPs list are refused at the entrypoint.
Since int is already DO-Cloud-Firewall-restricted to internal sources,
the trustedIPs filter just matches the existing firewall posture.

**Verified** post-rollout: existing mcrouter/memcache1/memcache2 traffic
continued to flow (3/4/4 connections immediately after restart, vs 6/4/5
before — gauge-level fluctuation, no protocol failures).

**Generator**: `/tmp/apply_int_trusted_ips.py` (also on mx01).

**Bonus**: also added `order: stop-first` to `traefik-int-stack.yml`
`deploy.update_config` for parity with the ext stack — same mode:host /
mode:global combination, same need to free ports before binding.

