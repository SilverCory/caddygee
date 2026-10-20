# caddygee Infrastructure

This document describes the GCP infrastructure for a caddygee deployment and how to manage it.

## Deployed resources

A full caddygee deployment provisions the following resources (all defined in `terraform/`):

| Resource | Notes |
|----------|-------|
| Cloud Run service | Serves the public gateway URL |
| GCS bucket | Caddyfile fragment store (`<project-id>-caddygee-config`) |
| Firestore database | Quota, KVM, and API key state |
| Service account | Cloud Run identity (`caddygee-sa@<project>.iam.gserviceaccount.com`) |
| Global LB IP | Static external IP — DNS A record target |
| Managed SSL certificate | Provisioned for the configured domain |
| Serverless NEG + backend | Wires Cloud Run to the load balancer |

## Architecture

```
Internet
    │
    ▼
Global HTTP(S) Load Balancer (static IP)
    │ :80  → HTTP→HTTPS redirect
    │ :443 → HTTPS
    ▼
Managed SSL certificate (your domain)
    ▼
URL map → Backend service (HTTPS)
    ▼
Serverless NEG
    ▼
Cloud Run: caddygee
    ├── :8080  Caddy (proxy routes + /health + /deploy forwarded to :9090)
    └── :9090  caddygee-server (deploy endpoint, internal only)
```

## Environment variables (Cloud Run)

| Variable | Default | Purpose |
|----------|---------|---------|
| `DEPLOY_PORT` | `9090` | Port for the deploy server (Caddy proxies `/deploy` here) |
| `CONFIG_BUCKET` | — | GCS bucket name for fragment storage |
| `ENVIRONMENT_NAME` | — | Active Apigee environment — controls `when` routing (`preview`, `preprod`, `prod`) |
| `CADDYGEE_AUDIENCE` | — | OIDC token audience for `/deploy` auth — must match the public service URL |
| `LISTEN_ADDRESS` | `:8080` | Caddy bind address |
| `TRUSTED_PROXIES` | GCP LB ranges | Space-separated CIDRs written into the global options block |

> `PORT` is injected automatically by Cloud Run and must not be set manually.

## Terraform

All infrastructure is defined in `terraform/`. Variables are in `terraform/terraform.tfvars`.

```bash
# Plan
NIXPKGS_ALLOW_UNFREE=1 nix-shell -p terraform --impure --run \
  "terraform -chdir=terraform plan"

# Apply
NIXPKGS_ALLOW_UNFREE=1 nix-shell -p terraform --impure --run \
  "terraform -chdir=terraform apply -auto-approve"
```

### Key variables (`terraform/terraform.tfvars`)

| Variable | Description |
|----------|-------------|
| `project_id` | GCP project to deploy into |
| `region` | GCP region (e.g. `europe-west2`) |
| `image` | Docker image to run (e.g. `ghcr.io/silvercory/caddygee:latest`) |
| `domain` | Public domain for the load balancer and `CADDYGEE_AUDIENCE` |
| `environment_name` | Value of `ENVIRONMENT_NAME` injected into the container |

### Changing the Cloud Run image

Update `image` in `terraform.tfvars` and apply. Cloud Run creates a new revision and shifts traffic automatically.

### Changing the active environment

Update `environment_name` in `terraform.tfvars` and apply. All `when environment.name = "..."` conditions in loaded fragments will route accordingly on the next request.

## GCS fragment store

Fragments are stored at `gs://<bucket>/<project-id>/<service-name>.caddyfile`.

```bash
# List all stored fragments
gcloud storage ls -r gs://<config-bucket>/

# View a specific fragment
gcloud storage cat gs://<config-bucket>/<project-id>/my-api.caddyfile

# Delete a fragment
gcloud storage rm gs://<config-bucket>/<project-id>/my-api.caddyfile
```

On cold start, caddygee fetches all fragments and rebuilds the Caddyfile. To force a rebuild without a code change, trigger a new revision:

```bash
gcloud run services update caddygee \
  --region=<region> \
  --project=<caddygee-project> \
  --update-env-vars=_RESTART=$(date +%s)
```

## Checking service health

```bash
# HTTP health check
curl -sS https://<your-domain>/health

# Cloud Run service status
gcloud run services describe caddygee \
  --region=<region> \
  --project=<caddygee-project> \
  --format='value(status.conditions[0].type,status.conditions[0].status)'

# Recent logs
gcloud run services logs read caddygee \
  --region=<region> \
  --project=<caddygee-project> \
  --limit=50

# SSL cert status (PROVISIONING → ACTIVE)
gcloud compute ssl-certificates describe caddygee-cert \
  --global \
  --format='value(managed.status,managed.domainStatus)'
```

## DNS

The load balancer IP is output by Terraform as `load_balancer_ip`. Create a DNS A record pointing your domain to this IP. It is managed outside Terraform.

The managed SSL cert will not activate until DNS resolves correctly to the load balancer IP. Provisioning typically takes 10–30 minutes after DNS propagates.

## Scaling

Cloud Run is configured with:
- **Min instances:** 0 (scales to zero when idle)
- **Max instances:** 10
- **CPU:** 1 vCPU, allocated only during requests (`cpu_idle = true`)
- **Memory:** 512 MiB
- **Startup CPU boost:** enabled

To change limits, update the `resources` block in `terraform/main.tf` and apply.
