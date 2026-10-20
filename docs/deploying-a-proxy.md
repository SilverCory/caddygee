# Deploying a Proxy to caddygee

This guide walks through deploying an Apigee proxy bundle to a running caddygee instance. The same steps apply to any service.

## Prerequisites

- `caddygee` CLI built and on your `$PATH` (see [Building](#building-the-cli))
- A GCP service account in the **caller project** with `roles/run.invoker` on the caddygee Cloud Run service (see [Service account permissions](#service-account-permissions))
- `gcloud` authenticated as (or able to impersonate) that service account

## Overview

```
apiproxy/  ──transpile──►  my-api.caddyfile  ──POST /deploy──►  caddygee
                              (fragment)                              │
                                                               validate + merge
                                                                      │
                                                               GCS + Caddy reload
```

The deploy endpoint authenticates callers via Google OIDC ID tokens. It extracts the **GCP project ID** from the service account email and namespaces the fragment under `<project-id>/my-api.caddyfile` in GCS.

## 1. Build the CLI

```bash
go build -o caddygee ./cmd/caddygee
```

Or install to `$GOPATH/bin`:

```bash
go install ./cmd/caddygee
```

## 2. Transpile the proxy bundle

Run from the root of your API proxy repository:

```bash
caddygee transpile \
  --input  services/my-api/proxy/apiproxy \
  --output my-api.caddyfile \
  --fragment
```

`--fragment` emits bare route content only (no server block). This is the format the `/deploy` endpoint expects.

Verify the output looks reasonable:

```bash
cat my-api.caddyfile
```

## 3. Obtain an OIDC ID token

The deploy endpoint validates the token audience against the value of `CADDYGEE_AUDIENCE` on the running caddygee instance (e.g. `https://gateway.example.com`).

```bash
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://gateway.example.com" \
  --impersonate-service-account=<your-sa>@<your-project>.iam.gserviceaccount.com)
```

If your `gcloud` session is already running as the service account:

```bash
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://gateway.example.com")
```

> **Note:** The token audience must exactly match the `CADDYGEE_AUDIENCE` env var on the Cloud Run service — including scheme and no trailing slash.

## 4. POST the fragment

```bash
curl -sS -X POST https://gateway.example.com/deploy \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Service-Name: my-api" \
  --data-binary @my-api.caddyfile
```

A `200 OK` response means the fragment passed all three validation gates and Caddy has hot-reloaded with the new config.

### Validation gates

| Gate | What it checks |
|------|---------------|
| 1 | Fragment is valid Caddyfile syntax in isolation |
| 2 | Merged config (all stored fragments + this one) is valid |
| 3 | Caddy accepts the merged config via its admin API (auto-rolls back on failure) |

Only after all three pass is the fragment written to GCS.

### Error responses

| Status | Meaning |
|--------|---------|
| `400` | Invalid `X-Service-Name` header, empty body, or fragment syntax error |
| `401` | Missing or invalid OIDC token |
| `422` | Fragment is valid on its own but breaks the merged config |
| `503` | Caddy rejected the reload (config was rolled back automatically) |

## 5. Verify the deployment

Check the Cloud Run logs:

```bash
gcloud run services logs read caddygee \
  --region=<region> \
  --project=<caddygee-project> \
  --limit=50
```

You should see a line like:

```
deployed <your-project>/my-api successfully
```

To confirm the route is live:

```bash
curl -I https://gateway.example.com/<base-path>/
```

## Fragment storage

Fragments are stored in GCS at:

```
gs://<config-bucket>/<project-id>/my-api.caddyfile
```

On the next container cold start, caddygee fetches all fragments from GCS and rebuilds the Caddyfile automatically — no re-deploy needed.

## Environments

The `ENVIRONMENT_NAME` env var on the Cloud Run service controls which conditional target endpoints are active (e.g. `preview`, `preprod`, `prod`).

The proxy bundle's conditional logic (e.g. `when environment.name = "preprod"`) selects the correct backend URL automatically — no changes to the fragment are needed when deploying to a different environment. Just deploy to the caddygee instance that has the matching `ENVIRONMENT_NAME`.

## Service account permissions

### Caller project (one-time setup per project)

Each project deploying a proxy needs a service account granted `roles/run.invoker` on the caddygee Cloud Run service. This allows it to call `/deploy` and mint OIDC ID tokens with the correct audience. The deploy endpoint extracts the **project ID** from the SA email to namespace fragments in GCS (`<project-id>/my-api.caddyfile`).

```bash
gcloud run services add-iam-policy-binding caddygee \
  --region=<region> \
  --project=<caddygee-project> \
  --member="serviceAccount:<caller-sa>@<caller-project>.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

### caddygee service account (already provisioned)

The caddygee service account is provisioned by Terraform with everything it needs:

| Role | Resource | Purpose |
|------|----------|---------|
| `roles/storage.objectAdmin` | config bucket | Read/write Caddyfile fragments |
| `roles/datastore.user` | project | Firestore access |

No action needed here unless caddygee needs access to additional GCP resources.

## Fragment encoding notes

### PEM public keys and JavaScript source

When the transpiler emits `verify_jwt` with a `public_key` or `js_callout` with a `source` block, it uses Caddyfile backtick quoting so multi-line content is preserved literally. If you hand-edit a fragment or write one without the CLI, make sure these fields use backtick-quoted strings with **real newlines** — not JSON `\n` escape sequences.

**Correct:**
```caddyfile
verify_jwt {
    public_key `-----BEGIN PUBLIC KEY-----
MIIBIjAN...
-----END PUBLIC KEY-----`
}
```

**Wrong (will fail at Caddy provision time):**
```caddyfile
verify_jwt {
    public_key "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
}
```

The same applies to `js_callout source`.

## Updating or removing a proxy

**Update:** repeat steps 2–4 with the revised bundle. The new fragment overwrites the previous one in GCS and Caddy hot-reloads immediately.

**Remove:** delete the fragment from GCS and trigger a reload by posting any other fragment, or restart the Cloud Run service:

```bash
gcloud storage rm \
  gs://<config-bucket>/<project-id>/my-api.caddyfile
```
