# Traefik custom fork — rebuild playbook (mx01)

This fork is the **production Traefik for the mx01/mx02/mx03 Docker Swarm**, carrying
internal + external **WAF + dashboard** patches. The deployed image is
`localhost:5000/traefik:<version>-waf-dash-<short-sha>` (e.g. `3.7.13-waf-dash-bc0609107`).

**Branch:** `build/waf-dash-shadow`  ·  **Fork:** `git@github.com:t0mtaylor/traefik.git`
**Upstream:** `https://github.com/traefik/traefik.git` (remote `origin`)

## Patches carried (do NOT lose on an upgrade)
- `pkg/middlewares/wafqueue/` — the WAF queue middleware (Valkey-backed, bounded retry
  ring + replay-on-reconnect so no IP loss on a Valkey outage).
- custom dashboard build + entrypoint split (see docs/).

## Rebuild on a NEW Traefik security release (the remediation vcheck points at)
1. `cd /root/traefik-fork`
2. Fetch + merge/rebase the upstream SECURITY tag onto this branch, preserving our patches:
   `git fetch origin && git rebase <upstream-fix-tag>  # resolve, keep wafqueue + dashboard`
3. Update the version ldflags in `build/build-traefik.sh` (the `-X ...version.Version=` value).
4. Build the binary (webui + go in a golang:1.25 container):
   `bash build/build-traefik.sh`
5. Build + tag + push the image (Dockerfile.tt copies the built binary onto alpine):
   `SHA=$(git rev-parse --short HEAD); VER=<new-version>`
   `docker build -f Dockerfile.tt -t localhost:5000/traefik:${VER}-waf-dash-${SHA} .`
   `docker push localhost:5000/traefik:${VER}-waf-dash-${SHA}`
6. Deploy (digest-pin — :latest does NOT repull):
   `docker service update --image localhost:5000/traefik@sha256:<digest> --with-registry-auth traefik_traefik`
7. Verify Traefik is routing + the WAF/dashboard patches are live; confirm version.
8. **Commit everything to the fork** (`t0mtaylor/traefik`) so the playbook survives an mx01 rebuild.

## Files
- `build-traefik.sh` — builds the linux/amd64 binary in a golang container.
- `../Dockerfile.tt` — assembles the `-waf-dash-` image from the built binary (alpine).
- `docs/` — upgrade status + entrypoint-split + presubmission-test notes.
