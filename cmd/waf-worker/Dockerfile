# waf-worker image. Thin stage consistent with Dockerfile.tt: the binary is built out-of-band
# in the golang container (reusing the shared gocache) and copied into a minimal alpine.
#
#   docker run --rm -v $PWD:/w -v /root/.gocache-traefik:/gocache -w /w \
#     -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
#     -e GOCACHE=/gocache -e GOMODCACHE=/gocache/mod golang:1.26 \
#     go build -ldflags '-s -w' -o dist/linux/amd64/waf-worker ./cmd/waf-worker
#   docker build -f cmd/waf-worker/Dockerfile -t localhost:5000/waf-worker:<sha> .
FROM alpine:3.23
RUN apk add --no-cache --no-progress ca-certificates tzdata
COPY ./dist/linux/amd64/waf-worker /usr/local/bin/waf-worker
USER nobody
ENTRYPOINT ["/usr/local/bin/waf-worker"]
