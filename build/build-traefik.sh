#!/bin/bash
set -e
cd /root/traefik-fork
echo BUILD_START $(date)
echo '--- webui ---'
make generate-webui
echo WEBUI_DONE
echo '--- go binary (in golang:1.25 container) ---'
docker run --rm -v /root/traefik-fork:/w -v /root/.gocache-traefik:/gocache -w /w   -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 -e GOCACHE=/gocache -e GOMODCACHE=/gocache/mod   golang:1.25   go build -ldflags '-s -w -X github.com/traefik/traefik/v3/pkg/version.Version=v3.7.6-7-g7ddaf6ea9 -X github.com/traefik/traefik/v3/pkg/version.Codename=cheddar -X github.com/traefik/traefik/v3/pkg/version.BuildDate=2026-07-04'   -o dist/linux/amd64/traefik ./cmd/traefik
echo BINARY_DONE
ls -la dist/linux/amd64/traefik
file dist/linux/amd64/traefik
