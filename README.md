# caddygee

A Caddy-based API gateway that replaces Apigee for services running on Google Cloud Run. Transpiles Apigee proxy bundles into Caddyfile configuration and serves multiple services from a single instance with hot-reload support.

## Overview

caddygee consists of three binaries:

| Binary | Path | Purpose |
|--------|------|---------|
| `caddy` | `cmd/caddy/` | Custom Caddy build with apigeecompat modules baked in |
| `caddygee-cli` | `cmd/caddygee/` | Transpiler CLI: converts Apigee proxy bundles to Caddyfile fragments |
| `caddygee-server` | `cmd/caddygee-server/` | Deploy endpoint: receives fragments, stores in GCS, hot-reloads Caddy |

## How It Works

```
[User project Cloud Build]
  caddygee-cli transpile --fragment → POST /deploy with OIDC token

[caddygee-server /deploy handler]
  1. Validate OIDC token
  2. Validate fragment (caddy adapt)
  3. Validate merged full config (caddy adapt)
  4. POST localhost:2019/load (Caddy hot reload)
  5. Write fragment to GCS

[Cold start / restart]
  Fetch all fragments from GCS → merge → start Caddy
```

Each service pushes its own Caddyfile fragment independently. A broken fragment from one service cannot affect other services — validation gates catch syntax errors and provisioning failures before any reload happens.

## Quick Start

### Build

```bash
make build-cli    # builds caddygee-cli
make build-caddy  # builds caddy (custom with apigeecompat modules)
make build        # builds all three binaries
```

### Transpile a proxy bundle

```bash
# Fragment mode (for pushing to /deploy endpoint)
caddygee-cli transpile \
  --input ./services/my-api/proxy/apiproxy \
  --fragment \
  --output my-api.caddyfile

# Full Caddyfile mode (for standalone Cloud Run use)
caddygee-cli transpile \
  --input ./services/my-api/proxy/apiproxy \
  --cloud-run \
  --output Caddyfile
```

### Merge fragments locally

```bash
# Merge all *.caddyfile files from a directory into a single Caddyfile
caddygee-cli merge \
  --input ./fragments/ \
  --cloud-run \
  --output Caddyfile

# Validate the result
caddy adapt --config Caddyfile --adapter caddyfile > /dev/null
```

### Run locally

```bash
export ENVIRONMENT_NAME=preview
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Transpile and merge all proxy bundles first
for svc in services/*/proxy/apiproxy; do
  name=$(basename $(dirname $(dirname $svc)))
  caddygee-cli transpile --input $svc --fragment --output /tmp/frags/$name.caddyfile
done
caddygee-cli merge --input /tmp/frags --cloud-run --output /tmp/Caddyfile

./caddy run --config /tmp/Caddyfile --adapter caddyfile
```

### Test

```bash
make test        # go test ./...
make test-race   # go test -race ./...
```

## CLI Reference

### `caddygee-cli transpile`

Converts an Apigee `apiproxy/` bundle to Caddyfile.

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | required | Path to the `apiproxy/` directory |
| `--output` | stdout | Output file path |
| `--format` | `caddyfile` | Output format: `caddyfile` or `json` |
| `--fragment` | false | Emit bare route content only (no server block); use for `/deploy` |
| `--cloud-run` | false | Emit Cloud Run global options block and server directives |

### `caddygee-cli merge`

Merges a directory of Caddyfile fragments into a complete Caddyfile.

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | required | Directory containing `*.caddyfile` fragment files |
| `--output` | stdout | Output file path |
| `--cloud-run` | false | Wrap with Cloud Run global options block |

## Deploy Endpoint

Services push fragments to caddygee using an OIDC-authenticated HTTP POST:

```bash
TOKEN=$(gcloud auth print-identity-token --audiences=$CADDYGEE_URL)

curl -sf -X POST $CADDYGEE_URL/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Service-Name: my-api" \
  --data-binary @my-api.caddyfile
```

The caller's service account must have `roles/run.invoker` on the caddygee Cloud Run service. The project ID is extracted from the token's `email` claim to namespace fragments in GCS: `gs://$CONFIG_BUCKET/$project_id/my-api.caddyfile`.

### Environment variables (caddygee-server)

| Variable | Description |
|----------|-------------|
| `CONFIG_BUCKET` | GCS bucket name for fragment storage (required) |
| `PORT` | HTTP port for the deploy server (default: `8080`) |
| `ENVIRONMENT_NAME` | Apigee environment name (`preview`, `preprod`, `prod`) |

## Supported Apigee Policies

See [`docs/policies.md`](docs/policies.md) for full reference.

| Module | Apigee equivalent | Status |
|--------|------------------|--------|
| `apigee_state` | Flow initialisation | Implemented |
| `apigee_conditional` | Step-level `<Condition>` | Implemented |
| `apigee_assign_message` | `AssignMessage` | Implemented |
| `apigee_raise_fault` | `RaiseFault` | Implemented |
| `apigee_google_auth` | `<Authentication><GoogleIDToken>` | Implemented |
| `apigee_verify_jwt` | `VerifyJWT` | Implemented |
| `apigee_javascript_callout` | `Javascript` | Implemented |
| `apigee_service_callout` | `ServiceCallout` | Implemented |
| `apigee_spike_arrest` | `SpikeArrest` | Implemented |
| `apigee_cors` | `CORS` | Implemented |
| `apigee_verify_api_key` | `VerifyAPIKey` | Passthrough (not enforced) |
| — | `ExtractVariables` | Not implemented |
| — | `Quota` | Not implemented |
| — | `KeyValueMapOperations` | Not implemented |

## Architecture Notes

- **Route blocks** are used instead of `handle` blocks because apigeecompat directives are not registered in Caddy's directive ordering system.
- **Matcher names** are prefixed with a slug derived from the proxy base path (e.g. `/profile-api/v2` → `profile_api_v2_`) to avoid collisions when merging multiple proxy bundles.
- **`environment.name`** is seeded from the `ENVIRONMENT_NAME` environment variable by `apigee_state` at provision time, allowing `apigee_conditional` to route to environment-specific Cloud Run targets at request time.
- **`apigee_google_auth`** uses Application Default Credentials to fetch a Google OIDC ID Token for the target Cloud Run service URL. This requires a service account — it will fail with user credentials locally.

## Directory Structure

```
caddygee/
├── cmd/
│   ├── caddy/            # Custom Caddy binary entrypoint
│   ├── caddygee/         # Transpiler CLI (transpile, merge commands)
│   └── caddygee-server/  # Deploy endpoint server
├── docs/
│   ├── policies.md       # Policy module reference
│   └── missing-policies.md
├── internal/
│   ├── condition/        # Apigee condition parser and Caddy matcher translator
│   └/transpiler/         # Apigee XML → CaddyConfig mapper and emitters
├── modules/
│   └── apigeecompat/     # Caddy handler modules (one per Apigee policy type)
├── Dockerfile
├── entrypoint.sh
├── Makefile
└── go.mod
```

## Docker

```bash
make docker-build   # builds gcr.io/PROJECT_ID/caddygee:latest
make docker-run     # runs locally on port 8080 with ENVIRONMENT_NAME=preview
make cloud-build    # submits to Cloud Build
```

The Docker image is a three-stage build that produces all three binaries. The entrypoint fetches GCS fragments, merges them into a Caddyfile, starts Caddy, and starts the deploy server.
