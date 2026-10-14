# caddygee

A Caddy-based API gateway that replaces Apigee for services running on Google Cloud Run. Transpiles Apigee proxy bundles into Caddyfile configuration and serves multiple services from a single instance with hot-reload support.

[![CI](https://github.com/SilverCory/caddygee/actions/workflows/ci.yml/badge.svg)](https://github.com/SilverCory/caddygee/actions/workflows/ci.yml)
[![Release](https://github.com/SilverCory/caddygee/actions/workflows/release.yml/badge.svg)](https://github.com/SilverCory/caddygee/actions/workflows/release.yml)

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

Each service pushes its own Caddyfile fragment independently. A broken fragment from one service cannot affect other services — three validation gates catch syntax errors and provisioning failures before any reload happens.

## Quick Start

### Build

```bash
make build-cli    # builds caddygee-cli
make build-caddy  # builds caddy (custom with apigeecompat modules)
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
| `DEBUG_TOKEN` | If set, requests with `X-Apigee-Debug: <token>` or `?_debug=<token>` get verbose handler logging |

## Supported Apigee Policies

See [`docs/policies.md`](docs/policies.md) for full reference.

| Directive | Apigee equivalent | Status |
|-----------|------------------|--------|
| `flow_state` | Flow initialisation | Implemented |
| `when` | Step-level `<Condition>` | Implemented |
| `assign_message` | `AssignMessage` | Implemented |
| `raise_fault` | `RaiseFault` | Implemented |
| `google_auth` | `<Authentication><GoogleIDToken>` | Implemented |
| `verify_jwt` | `VerifyJWT` | Implemented |
| `js_callout` | `Javascript` | Implemented |
| `service_callout` | `ServiceCallout` | Implemented |
| `spike_arrest` | `SpikeArrest` | Implemented |
| `cors` | `CORS` | Implemented |
| `verify_api_key` | `VerifyAPIKey` | Enforced via Firestore; passthrough without Firestore |
| `extract_vars` | `ExtractVariables` | Implemented |
| `quota` | `Quota` | Distributed via Firestore; in-memory fallback |
| `kvm` | `KeyValueMapOperations` | Live Firestore reads with TTL cache; static fallback |

## Firestore Integration

Several modules use Cloud Firestore for distributed state. Enable by adding the `firestore_app` directive to your Caddyfile global options block:

```caddyfile
{
    firestore_app {
        project_id my-gcp-project
    }
}
```

| Module | Without Firestore | With Firestore |
|--------|------------------|----------------|
| `verify_api_key` | Passthrough (logs warning) | Enforces — looks up key in `api_keys` collection |
| `quota` | In-memory per-process counter | Distributed atomic counter in `quotas` collection |
| `kvm` | Static baked-in values | Live values fetched from `kvm` collection (TTL from `<ExpiryTimeInSecs>`) |

### Required Firestore collections

**`api_keys/{sha256(key)}`**
```json
{ "enabled": true, "app_id": "my-service", "quota_limit": 200, "quota_interval": 1, "quota_timeunit": "minute" }
```

**`kvm/{map_name}`** — field names must match `Get.assignTo` values from the Apigee XML:
```json
{ "getAuthApiBaseUrl": "auth.example.com" }
```

**`quotas/`** — auto-created by the quota module; no manual setup needed.

The caddygee Cloud Run service account needs `roles/datastore.user` on the GCP project.

## Debug Logging

Set `DEBUG_TOKEN` to a secret value. Any request that includes a matching `X-Apigee-Debug` header or `?_debug=` query parameter will emit verbose per-handler logs for that request only. If `DEBUG_TOKEN` is unset, debug logging is always disabled.

## Architecture Notes

- **`route` blocks** are used instead of `handle` blocks because apigeecompat directives are not registered in Caddy's directive ordering system.
- **Matcher names** are prefixed with a slug derived from the proxy base path (e.g. `/profile-api/v2` → `profile_api_v2_`) to avoid collisions when merging multiple proxy bundles.
- **`environment.name`** is seeded from `ENVIRONMENT_NAME` at provision time by `flow_state`, allowing `when` to route to environment-specific Cloud Run targets at request time.
- **`google_auth`** uses Application Default Credentials to fetch a Google OIDC ID Token. This requires a service account — it will fail with user credentials locally.
- **KVM live mode**: Firestore document fields must use the `Get.assignTo` variable names (e.g. `getAuthApiBaseUrl`), not the KVM key names (e.g. `authApiBaseUrl`).

## Docker

```bash
make docker-build   # builds caddygee:dev
make docker-run     # runs locally on port 8080 with ENVIRONMENT_NAME=preview
make cloud-build    # submits to Cloud Build (requires PROJECT_ID=...)
```

The Docker image is a multi-stage build that produces all three binaries. The entrypoint fetches GCS fragments on cold start, merges them into a Caddyfile, and starts Caddy. The deploy server runs alongside, handling hot-reload requests.

Images are also published automatically to `ghcr.io/silvercory/caddygee` on every push to `master` — see [Releases](https://github.com/SilverCory/caddygee/releases).

## Directory Structure

```
caddygee/
├── cmd/
│   ├── caddy/            # Custom Caddy binary entrypoint
│   ├── caddygee/         # Transpiler CLI (transpile, merge commands)
│   └── caddygee-server/  # Deploy endpoint server
├── docs/
│   └── policies.md       # Policy module reference
├── internal/
│   ├── apigee/           # Apigee XML parser and type definitions
│   ├── condition/        # Apigee condition parser and Caddy matcher translator
│   └── transpiler/       # Apigee XML → CaddyConfig mapper and emitters
├── modules/
│   └── apigeecompat/     # Caddy handler modules (one per Apigee policy type)
├── .github/workflows/    # CI and release workflows
├── Dockerfile
├── entrypoint.sh
├── Makefile
└── go.mod
```
