.PHONY: build-cli build-caddy test test-race test-v lint clean docker-build docker-run cloud-build

# ── Local development ─────────────────────────────────────────────────────────

# Build the transpiler CLI binary
build-cli:
	go build -o caddygee-cli ./cmd/caddygee/

# Build a custom Caddy binary with the apigeecompat modules baked in (local)
build-caddy:
	go build -o ./caddy ./cmd/caddy/

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	go test ./...

test-race:
	go test -race ./...

test-v:
	go test -v ./...

# ── Lint ──────────────────────────────────────────────────────────────────────

lint:
	golangci-lint run ./...

# ── Docker ────────────────────────────────────────────────────────────────────

IMAGE ?= caddygee:dev

docker-build:
	docker build --tag $(IMAGE) .

# Run the container locally; mirrors the Cloud Run environment.
# Mounts gcloud ADC credentials for Google ID Token auth.
docker-run: docker-build
	docker run --rm \
		--publish 8080:8080 \
		--env PORT=8080 \
		--env ENVIRONMENT_NAME=preview \
		--volume $(HOME)/.config/gcloud:/home/caddy/.config/gcloud:ro \
		$(IMAGE)

# ── Cloud Build ───────────────────────────────────────────────────────────────

# Trigger a build locally (requires gcloud + Cloud Build API enabled).
# Usage: make cloud-build PROJECT_ID=my-project
cloud-build:
	gcloud builds submit \
		--config cloudbuild.yaml \
		--substitutions SHORT_SHA=$$(git rev-parse --short HEAD),PROJECT_ID=$(PROJECT_ID) \
		.

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	rm -f caddygee-cli caddy
