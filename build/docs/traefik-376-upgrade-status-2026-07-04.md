
## RESOLVED 2026-07-04 ~16:46 — 3.7.6 LIVE on ext
- **traefik_traefik 3/3 on 3.7.6, all health=healthy, version=3.7.6-tt-rc-7ddaf6ea9.** CVE fix live. mail 200 throughout every roll (auto-rollback + maintenance mode kept it up).
- **Two root causes fixed:**
  1. `dashboardNamePosition` removed from traefik.yml/traefik.int.yml (our review commit dropped the option).
  2. **Healthcheck binary-not-in-PATH**: my first image (simple Dockerfile) put the binary at `/traefik`, so the stack healthcheck `[CMD traefik healthcheck --ping]` → exit 127 'not found' → unhealthy → killed. The ping ENDPOINT worked fine (`wget :8082/ping`=200). Fixed by rebuilding with binary at `/usr/local/bin/traefik` (in PATH) + `/traefik` symlink. Stack healthcheck currently uses `/traefik` absolute (robust).
- **Version string**: was raw SHA because Makefile VERSION falls back to $(SHA) with no git tag + no explicit VERSION. Rebuilt with `VERSION=3.7.6-tt-rc-7ddaf6ea9`. New image digest sha256:fb4ad349...
- **Deploy process that worked**: maintenance-mode.sh on → `docker service update --image <digest> --update-order stop-first --update-parallelism 1 --update-monitor 90s --health-start-period 40s --update-failure-action rollback --detach=true` → monitor to 'completed' → maintenance-mode.sh off. Issue ONCE, never re-issue (overlapping updates thrash). host-mode ports REQUIRE stop-first.
- **maintenance-mode**: /media/gfs/ptmx/maintenance-mode.sh {on|off|status}; flag /media/gfs/ptmx/MAINTENANCE gates DNA + failover-rebalance-enforcer + swarm-rebalance-cron + swarm-rebalance (skip healing if flag <3h old; auto-expires 3h).
- **INTERNAL traefik**: NOT deployed (no traefik-int stack/service/container). Was 3/3 at session start, gone since (removal predates 6h event window, not from this session's changes which only touched traefik_traefik/traefik_modsec). Nothing to upgrade — needs owner clarification if it should be running.
