# syntax=docker/dockerfile:1

# ── Stage 1: build all binaries ───────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY cmd/      cmd/
COPY internal/ internal/
COPY modules/  modules/

# Build the custom Caddy binary (imports apigeecompat modules).
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/caddy \
    ./cmd/caddy/

# Build the transpiler CLI.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/caddygee-cli \
    ./cmd/caddygee/

# Build the deploy endpoint server.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/caddygee-server \
    ./cmd/caddygee-server/


# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

# Drop privileges — Cloud Run supports non-root containers.
RUN addgroup -S caddy && adduser -S caddy -G caddy

COPY --from=builder /build/caddy           /usr/bin/caddy
COPY --from=builder /build/caddygee-cli    /usr/bin/caddygee-cli
COPY --from=builder /build/caddygee-server /usr/bin/caddygee-server
COPY entrypoint.sh                          /entrypoint.sh

# Cloud Run injects $PORT (default 8080).
# caddygee-server deploy endpoint listens on DEPLOY_PORT (default 9090).
EXPOSE 8080 9090

USER caddy

ENTRYPOINT ["/entrypoint.sh"]
