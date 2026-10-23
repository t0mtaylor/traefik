# Traefik fork pre-submission test runs

**Date:** 2026-05-08
**Run on:** mx01 (inside `golang:1.25` Docker container — Go isn't installed on mx01 itself)
**Repo:** `/root/traefik-fork` → fork at `git@github.com:t0mtaylor/traefik.git`
**Required by:** `docs/content/contributing/submitting-pull-requests.md` "Run Local Verifications"

This file is a snapshot for re-reference. CI on the upstream PRs will re-run
these targets server-side; local runs just save us from a "PR opens, CI fails,
re-push" round-trip.

## Branches tested

| Branch | Tip | Diff vs master |
|---|---|---|
| `feature/router-constraint` | `6a105974f` | 7 files, +476/-6 |
| `feature/dashboard-instance-name` | `137431439` | 13 files, +332/-22 |

## Runner command (re-runnable verbatim)

```sh
cd /root/traefik-fork
git checkout feature/router-constraint   # or feature/dashboard-instance-name
docker run --rm \
  -v /root/traefik-fork:/src \
  -v /root/.cache/go-build:/root/.cache/go-build \
  -v /root/go:/go \
  -w /src \
  golang:1.25 sh -c "go vet ./... && go build ./cmd/... && go test ./pkg/..."
```

## F1 — `feature/router-constraint`

Touched packages: `pkg/provider/docker/{config,config_test,shared}.go`,
plus 4 docs files.

### `go vet ./pkg/provider/docker/...`
```
VET_EXIT=0    ✅ clean
```

### Unit tests (focused — feature)
```
=== RUN   TestStripRouterConstraintLabels
=== RUN   TestStripRouterConstraintLabels/empty_input_returns_empty_output
=== RUN   TestStripRouterConstraintLabels/no_constraint_labels:_input_passed_through_unchanged
=== RUN   TestStripRouterConstraintLabels/strips_http/tcp/udp_router_constraint_labels
=== RUN   TestStripRouterConstraintLabels/preserves_other_labels_containing_the_word_constraint
--- PASS: TestStripRouterConstraintLabels (0.00s)
=== RUN   TestIsRouterConstraintLabel
=== RUN   TestIsRouterConstraintLabel/traefik.http.middlewares.m1.constraint
=== RUN   TestIsRouterConstraintLabel/random
=== RUN   TestIsRouterConstraintLabel/traefik.http.routers.r1.rule
=== RUN   TestIsRouterConstraintLabel/traefik.constraint-label
=== RUN   TestIsRouterConstraintLabel/#00
=== RUN   TestIsRouterConstraintLabel/traefik.http.routers.r1.constraint.extra
=== RUN   TestIsRouterConstraintLabel/traefik.http.routers.r1.constraint
=== RUN   TestIsRouterConstraintLabel/traefik.tcp.routers.t1.constraint
=== RUN   TestIsRouterConstraintLabel/traefik.udp.routers.u1.constraint
--- PASS: TestIsRouterConstraintLabel (0.00s)
PASS
ok  	github.com/traefik/traefik/v3/pkg/provider/docker	0.021s
```
**Result:** ✅ 13 sub-tests PASS, package ok

### Full `pkg/provider/docker` package
```
ok  	github.com/traefik/traefik/v3/pkg/provider/docker	0.037s
```
✅

### `go vet ./...` (whole tree)
```
VET_EXIT=0    ✅ clean
```

### `go build ./cmd/...`
```
BUILD_OK      ✅
```

### Summary
- ✅ vet (focused + whole-tree)
- ✅ feature unit tests (13 sub-tests)
- ✅ full `pkg/provider/docker` package tests
- ✅ build

## F2 — `feature/dashboard-instance-name`

Touched packages: `pkg/version/`, `pkg/config/static/`, `cmd/traefik/`, plus
webui frontend files (not Go).

### `go vet` (focused)
```
VET_EXIT=0    ✅ clean
```

### Unit tests — `pkg/version`
```
=== RUN   TestVersionHandler_DashboardName
=== RUN   TestVersionHandler_DashboardName/all_empty_defaults:_both_keys_absent_(omitempty)
=== RUN   TestVersionHandler_DashboardName/name_only,_no_position
=== RUN   TestVersionHandler_DashboardName/name_+_side_position
=== RUN   TestVersionHandler_DashboardName/name_+_below_position
--- PASS: TestVersionHandler_DashboardName (0.00s)
=== RUN   TestVersionHandler_ConcurrentReads
--- PASS: TestVersionHandler_ConcurrentReads (0.00s)
PASS
ok  	github.com/traefik/traefik/v3/pkg/version	0.007s
```
**Result:** ✅ 5 sub-tests PASS, package ok

### `go vet ./...` (whole tree)
```
VET_EXIT=0    ✅ clean
```

### `go build ./cmd/...`
```
BUILD_OK      ✅
```

### Summary
- ✅ vet (focused + whole-tree)
- ✅ feature unit tests (5 sub-tests, including concurrent-read)
- ✅ build

## What was NOT run locally (CI will handle these)

| Target | Why skipped | CI risk |
|---|---|---|
| `make generate` (`go generate`) | No code-gen in either feature; would only regenerate unrelated stuff | low |
| `make generate-crd` | K8s CRD generation; touches no files we changed | low |
| `make lint` (golangci-lint) | Not in `golang:1.25` image by default; `go vet` covered the basics | medium — golangci-lint may flag style issues |
| `make test-ui-unit` (npm/jest) | F2 has frontend specs that need `npm install` — heavy, skipped | medium — frontend tests are part of F2 (covered in soak) |
| `make test-integration` | Needs docker-in-docker + multiple test images; long | low — neither feature touches integration paths |
| `make test-gateway-api-conformance` | K8s gateway API; unrelated | low |
| `make pull-images` | Just pulls images for integration tests | low |

If CI flags any of these, fix locally + push; cycle is normal.

## Tooling notes

- mx01 doesn't have Go installed (`which go` returns nothing). Always run via
  the `golang:1.25` container as above.
- Cache mounts (`/root/.cache/go-build`, `/root/go`) speed up re-runs after
  the first `go: downloading ...` storm.
- `golang:1.25` is the version specified in `go.mod` (`go 1.25.0`).
