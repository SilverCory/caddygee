# Transpiler Pipeline

The transpiler converts an Apigee API proxy bundle (a directory tree) into either a fragment Caddyfile (for hot-reload deploys) or a complete Caddyfile (for standalone use). This document describes each stage of the pipeline and the key design decisions.

## Bundle Layout

An Apigee proxy bundle has this structure:

```
apiproxy/
├── <ProxyName>.xml          # Root descriptor: lists proxy/target endpoints
├── proxies/
│   └── default.xml          # ProxyEndpoint: base path, flows, route rules
├── targets/
│   └── default.xml          # TargetEndpoint: upstream URL, auth
└── policies/
    ├── AssignHeader.xml
    ├── ExtractToken.xml
    └── ...
```

The parser reads the root XML to locate endpoints and policies, then cross-references them by name.

## Pipeline Stages

### 1. Parse (`internal/apigee/parser.go`)

`apigee.Parse(dir string)` walks the `apiproxy/` directory and returns a `*apigee.Bundle`:

- Reads `apiproxy/*.xml` for the root descriptor
- Reads each proxy endpoint XML into `ProxyEndpoint` structs
- Reads each target endpoint XML into `TargetEndpoint` structs
- Reads each policy XML by element name (e.g. `<AssignMessage>`) into the matching struct field on `Policy`
- Policies are stored in `Bundle.Policies` keyed by their `name` attribute

**Adding support for a new policy XML element:** add a struct to `types.go` and a case in the `parsePolicy` switch in `parser.go`.

### 2. Transpile (`internal/transpiler/mapper.go`)

`transpiler.Transpile(bundle, opts)` maps a `Bundle` to a `CaddyConfig`:

1. For each `ProxyEndpoint`, calls `mapProxyEndpointRoutes`
2. For each flow (PreFlow → named flows → PostFlow), calls `mapFlow`
3. `mapFlow` produces a `Route` with:
   - A `CaddyMatcher` translated from the flow's `<Condition>` (via `internal/condition/`)
   - A `FlowStateHandler` as the first handler (always)
   - Request-phase handlers from `flow.Request.Steps`
   - Response-phase handlers (from `flow.Response.Steps`) placed **before** the terminal handlers
   - Target handlers (google_auth + reverse_proxy) as the terminal handlers

**Route ordering note:** Caddy executes handlers in the order they appear in a `route` block. Response-phase handlers must be placed before `reverse_proxy` because `reverse_proxy` is terminal — execution doesn't return from it. A response-phase `assign_message` handler wraps the `ResponseWriter` and intercepts the response as it flows back.

**Matcher prefix:** when merging multiple bundles (e.g. `profile-api-v2` and `discount-api`), all named matchers receive a prefix derived from the bundle's base path (e.g. `profile_api_v2_`). This prevents matcher name collisions in the merged Caddyfile.

### 3. Emit (`internal/transpiler/emitter_caddyfile.go`)

`transpiler.EmitCaddyfile(cfg, opts)` serialises a `CaddyConfig` to a Caddyfile string. The `Options.Fragment` flag controls the output format:

**Fragment mode** (`--fragment`):
- Emits only named matchers + `route` blocks
- No global options block, no server block wrapper
- Used by the deploy endpoint when uploading a fragment to GCS

**Full Caddyfile** (`--cloud-run`):
- Prepends the Cloud Run global options block (`admin`, `auto_https off`, `trusted_proxies`, structured logging)
- Wraps routes in a server block (e.g. `:8080 { ... }`)
- Includes standard directives: `/health` endpoint, `/deploy` reverse proxy

The emitter uses `route` blocks (not `handle` blocks) for all routes. This preserves handler order exactly as specified — Caddy's `handle` blocks are subject to automatic ordering by the directive registration system, which doesn't apply to custom apigeecompat directives.

### 4. Merge (`internal/transpiler/merger.go`)

`transpiler.MergeFragments(dir, opts)` combines multiple fragment files into a single Caddyfile:

1. Lists all `*.caddyfile` files in the directory
2. Concatenates their content (each fragment is already indented for inclusion inside a server block)
3. Wraps in a server block
4. Prepends the global options block (when `opts.CloudRun` is true)

The `AdminAddress` in the merged config must match the running Caddy admin API port. This address is threaded through `Options.AdminAddress` → `cloudRunGlobalBlock` so that after a hot-reload the new config keeps the same admin socket.

## Options

```go
type Options struct {
    ListenAddress  string   // e.g. ":8080" (default ":443")
    Format         string   // "caddyfile" or "json"
    Fragment       bool     // emit fragment only (no server block)
    CloudRun       bool     // add Cloud Run global block + server directives
    TrustedProxies []string // CIDR ranges for trusted_proxies static
    AdminAddress   string   // Caddy admin API address (default "localhost:2019")
    MatcherPrefix  string   // prefix for all named matchers
}
```

## Condition Translation (`internal/condition/`)

Apigee flow conditions like `(request.verb = "GET") AND (request.header.X-Api-Key NotEquals "")` are translated to Caddy matchers.

The translator maps common Apigee variable references:

| Apigee | Caddy matcher |
|---|---|
| `request.verb = "GET"` | `method GET` |
| `request.path ~~ "/v1/users.*"` | `path /v1/users*` |
| `request.header.X-Foo NotEquals ""` | `header X-Foo *` |
| `request.header.Authorization ~~ "Bearer .*"` | `header_regexp Authorization "Bearer .*"` |

Conditions that cannot be translated are emitted as `# WARNING:` comments and do not affect routing. The transpiler continues; the route matches everything (or uses the partially-translated matchers).

## Caddyfile Fragment Contract

A fragment is a snippet of Caddyfile text that can be inserted verbatim inside a server block. It must:

- Start with named matcher definitions (`@matcherName { ... }`)
- Follow with `route @matcherName { ... }` blocks
- Use the `MatcherPrefix` option to avoid name collisions when merged

Example fragment for a service at `/profile-api/v2`:

```caddyfile
	@profile_api_v2_get_user {
		method GET
		path /profile-api/v2/users/*
	}

	route @profile_api_v2_get_user {
		flow_state
		extract_vars {
			prefix auth
			header_pattern authorization "Bearer {clienttoken}"
		}
		verify_jwt {
			algorithm RS256
			jwks_uri https://auth.example.com/.well-known/jwks.json
			policy_name VerifyJWT
		}
		reverse_proxy https://profile-service.internal
	}
```

## CLI Commands

```bash
# Transpile a proxy bundle to a fragment
caddygee-cli transpile --input ./apiproxy --fragment --output service.caddyfile

# Transpile with full Cloud Run global block
caddygee-cli transpile --input ./apiproxy --cloud-run --output Caddyfile

# Merge all fragments in a directory into a complete Caddyfile
caddygee-cli merge --input ./fragments-dir --cloud-run --output Caddyfile

# Validate a Caddyfile without starting the server
caddy adapt --config Caddyfile --adapter caddyfile --validate
```
