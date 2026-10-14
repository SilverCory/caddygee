# caddygee Policy Reference

All supported Apigee policy types and their Caddy module equivalents.
Modules live in `modules/apigeecompat/`. The transpiler maps Apigee XML policy
types to these modules automatically during `caddygee transpile`.

## Firestore integration

Several modules optionally connect to Cloud Firestore for distributed state.
Enable by configuring the `apigee_firestore` Caddy app in your global options:

```json
{
    "apps": {
        "apigee_firestore": {
            "project_id": "my-gcp-project",
            "database_id": "(default)"
        }
    }
}
```

Or via the Caddyfile (place in the global options block):

```caddyfile
{
    apigee_firestore {
        project_id my-gcp-project
    }
}
```

When `apigee_firestore` is configured:

| Module | Behaviour without Firestore | Behaviour with Firestore |
|--------|----------------------------|--------------------------|
| `apigee_verify_api_key` | Passthrough (logs warning) | Enforces — looks up key in `api_keys` collection |
| `apigee_quota` | In-memory per-process counter | Distributed atomic counter in `quotas` collection |
| `apigee_kvm` | Static baked-in values only | Fetches live values from `kvm` collection (5 min TTL cache) |

### Firestore data model

**`api_keys/{key}`** — one document per API key:
```json
{
    "enabled":        true,
    "app_id":         "my-service",
    "quota_limit":    200,
    "quota_interval": 1,
    "quota_timeunit": "minute"
}
```

**`quotas/{identifier}_{window_key}`** — quota counters (auto-created):
```json
{ "count": 42, "window_end": "2026-10-14T12:01:00Z" }
```

**`kvm/{map_name}`** — KVM documents (field names become flow variable names):
```json
{ "getAuthApiBaseUrl": "auth.example.com" }
```

## Implementation checklist

- [x] `apigee_state` — flow state initialisation (required first handler on every route)
- [x] `apigee_conditional` — runtime condition evaluation wrapping an inner handler
- [x] `apigee_assign_message` — header and body manipulation (AssignMessage)
- [x] `apigee_raise_fault` — short-circuit with a fixed error response (RaiseFault)
- [x] `apigee_google_auth` — fetch Google OIDC ID Token and inject as Bearer (target authentication)
- [x] `apigee_verify_jwt` — verify RS256/RS512 JWT from Authorization header (VerifyJWT)
- [x] `apigee_javascript_callout` — execute inline JS against flow variables (Javascript)
- [x] `apigee_service_callout` — synchronous HTTP sub-request (ServiceCallout)
- [x] `apigee_spike_arrest` — per-server token-bucket rate limiting (SpikeArrest)
- [x] `apigee_cors` — CORS response headers + OPTIONS preflight (CORS)
- [x] `apigee_verify_api_key` — API key validation passthrough ⚠️ not enforced (VerifyAPIKey)
- [x] `apigee_extract_variables` — extract request values into flow variables (ExtractVariables)
- [x] `apigee_quota` — per-key in-memory request quota (Quota)
- [x] `apigee_kvm` — Key-Value Map: baked-in static values set at request time (KeyValueMapOperations)

---

## `apigee_state`

**File:** `modules/apigeecompat/state.go`
**Apigee equivalent:** internal flow initialisation (not a policy — implicit in every proxy)
**Tests:** `state_test.go` (5 tests)

Injects a fresh `FlowState` into the request context. Must be the **first handler**
in every route. Seeds `environment.name` from the `ENVIRONMENT_NAME` environment
variable at provision time.

```caddyfile
apigee_state
```

No configuration options. The transpiler emits this automatically as the first
handler in every route.

---

## `apigee_conditional`

**File:** `modules/apigeecompat/conditional.go`
**Apigee equivalent:** step-level `<Condition>` on any policy step
**Tests:** `conditional.go` (inline, via transpiler integration tests)

Evaluates an Apigee condition expression at request time. Invokes the inner handler
only when the condition is true; otherwise falls through to the next handler.

Supports: `AND`, `OR`, `NOT`, `=`, `!=`, `MatchesPath`, `Matches`, `StartsWith`,
`>`, `<`, `>=`, `<=`, and flow variables (`request.verb`, `proxy.pathsuffix`,
`request.header.*`, `environment.name`, arbitrary flow vars).

```caddyfile
apigee_conditional "environment.name = \"preview\"" {
    reverse_proxy https://service-preview.run.app
}

apigee_conditional "request.verb = \"POST\" AND proxy.pathsuffix = \"/graphql\"" {
    apigee_verify_jwt {
        algorithm RS256
        jwks_uri  https://login.example.com/v1/keys
        policy_name MyVerifyJWT
    }
}
```

---

## `apigee_assign_message`

**File:** `modules/apigeecompat/assign_message.go`
**Apigee equivalent:** `AssignMessage` policy
**Tests:** `assign_message_test.go` (8 tests)

Manipulates request or response headers and body. Header values support
`{flowvar.X}` substitution against the current flow state.

```caddyfile
apigee_assign_message MyPolicy {
    set_headers    Authorization "Bearer {flowvar.token}"
    add_headers    X-Forwarded-By "caddygee"
    remove_headers X-Internal-Key
}
```

| Config field | Type | Description |
|---|---|---|
| `set_headers` | map | Replace header value (creates if absent) |
| `add_headers` | map | Add header (appends if already present) |
| `remove_headers` | list | Remove headers from request/response |
| `set_body` | string | Replace request/response body |
| `phase` | `request`\|`response` | Which phase to apply (default: `request`) |

---

## `apigee_raise_fault`

**File:** `modules/apigeecompat/raise_fault.go`
**Apigee equivalent:** `RaiseFault` policy
**Tests:** none (covered by transpiler integration tests)

Short-circuits the handler chain and returns a fixed HTTP response immediately.
Used for method validation, auth failures, and error flows.

```caddyfile
apigee_raise_fault {
    status_code 405
    body "{\"error\":\"MethodNotAllowed\"}"
}
```

| Config field | Type | Description |
|---|---|---|
| `status_code` | int | HTTP status code (default: 500) |
| `body` | string | Response body (optional) |

---

## `apigee_google_auth`

**File:** `modules/apigeecompat/google_auth.go`
**Apigee equivalent:** `<Authentication><GoogleIDToken>` on a TargetEndpoint
**Tests:** none (requires GCP service account; tested on Cloud Run)

Fetches a Google OIDC ID Token for the configured audience using Application Default
Credentials and injects it as `Authorization: Bearer <token>` on the outbound
request. Required before `reverse_proxy` when targeting private Cloud Run services.

```caddyfile
apigee_google_auth https://my-service-abc123-nw.a.run.app
```

| Config field | Type | Description |
|---|---|---|
| `audience` | string | Cloud Run service URL used as the OIDC token audience |

The token is cached and refreshed automatically before expiry.

---

## `apigee_verify_jwt`

**File:** `modules/apigeecompat/verify_jwt.go`
**Apigee equivalent:** `VerifyJWT` policy
**Tests:** none (covered by transpiler integration tests)

Verifies a Bearer JWT from the `Authorization` header. On success, stores decoded
claims as flow variables under `jwt.<policy_name>.decoded.claim.<name>` for use by
downstream handlers. On failure, returns 401 and does not call the next handler.

Supports RS256 and RS512 with either a static PEM public key or a JWKS URI
(auto-refreshed every 5 minutes).

```caddyfile
# JWKS endpoint (recommended)
apigee_verify_jwt {
    algorithm   RS256
    jwks_uri    https://login.example.com/oauth2/v1/keys
    issuer      https://login.example.com
    policy_name VerifyCustomerToken
}

# Static PEM key
apigee_verify_jwt {
    algorithm   RS512
    public_key  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    issuer      https://idp.example.com
    policy_name VerifyServiceToken
}
```

| Config field | Type | Description |
|---|---|---|
| `algorithm` | `RS256`\|`RS512` | JWT signing algorithm |
| `jwks_uri` | string | JWKS endpoint URL (mutually exclusive with `public_key`) |
| `public_key` | string | PEM-encoded RSA public key |
| `issuer` | string | Expected `iss` claim value |
| `audience` | string | Expected `aud` claim value (optional) |
| `policy_name` | string | Used to namespace decoded claims in flow state (**required**) |

---

## `apigee_javascript_callout`

**File:** `modules/apigeecompat/javascript_callout.go`
**Apigee equivalent:** `Javascript` policy
**Tests:** `javascript_callout_test.go` (12 tests)

Executes an inline JavaScript snippet using the goja ECMAScript 5.1 runtime. The
script can read and write Apigee flow variables via `context.getVariable()` /
`context.setVariable()`.

```caddyfile
apigee_javascript_callout MyScript {
    source "context.setVariable('token', context.getVariable('request.header.authorization'));"
    timeout_ms 200
}
```

| Config field | Type | Description |
|---|---|---|
| `source` | string | Inline JavaScript source (**required**) |
| `timeout_ms` | int | Execution timeout in milliseconds (default: 200) |
| `lib_dir` | string | Path to directory of shared `.js` library files |

Flow variable access from JS:
```js
var verb = context.getVariable("request.verb");
context.setVariable("my.custom.var", "value");
```

---

## `apigee_service_callout`

**File:** `modules/apigeecompat/service_callout.go`
**Apigee equivalent:** `ServiceCallout` policy
**Tests:** `service_callout_test.go` (7 tests)

Executes a synchronous HTTP sub-request to an external service and stores the
response body in a named flow variable. Supports `{flowvar.X}` substitution in the
target URL. The resolved URL must use `http://` or `https://` (SSRF protection).

```caddyfile
apigee_service_callout MyCallout {
    target_url      https://internal-service.run.app/lookup
    method          POST
    response_var    callout.response
    timeout_seconds 10
}
```

| Config field | Type | Description |
|---|---|---|
| `target_url` | string | Callout endpoint; supports `{flowvar.X}` (**required**) |
| `method` | string | HTTP method (default: `GET`) |
| `request_body_var` | string | Flow variable whose value becomes the request body |
| `response_var` | string | Flow variable to store the response body in |
| `timeout_seconds` | int | Request timeout (default: 10) |

---

## `apigee_spike_arrest`

**File:** `modules/apigeecompat/spike_arrest.go`
**Apigee equivalent:** `SpikeArrest` policy
**Tests:** none (covered by transpiler integration tests)

Per-server token-bucket rate limiter. Rejects excess requests with
`429 Too Many Requests` and a JSON fault body matching Apigee's format.
The bucket is shared across all requests to the Caddy process (not per-client).

```caddyfile
# Inline form
apigee_spike_arrest 30ps

# Block form
apigee_spike_arrest {
    rate 10pm
}
```

| Config field | Type | Description |
|---|---|---|
| `rate` | string | Rate string: integer + `ps` (per second) or `pm` (per minute). e.g. `30ps`, `600pm` |

> **Note:** Apigee SpikeArrest is server-side (not per-client IP). This implementation
> matches that behaviour. For per-client rate limiting use a separate `rate_limit` module.

---

## `apigee_cors`

**File:** `modules/apigeecompat/cors.go`
**Apigee equivalent:** `CORS` policy
**Tests:** none (covered by transpiler integration tests)

Adds `Access-Control-*` response headers to all responses. For `OPTIONS` preflight
requests, responds immediately with `204 No Content` without calling the next handler.

```caddyfile
apigee_cors {
    allow_origins  https://example.com https://www.example.com
    allow_methods  GET POST OPTIONS PUT DELETE
    allow_headers  Authorization Content-Type X-Api-Key
    expose_headers X-Request-Id
    max_age        3600
}
```

| Config field | Type | Description |
|---|---|---|
| `allow_origins` | list | Allowed origin values; `*` permits any origin |
| `allow_methods` | list | Allowed HTTP methods |
| `allow_headers` | list | Allowed request headers |
| `expose_headers` | list | Response headers browsers may access |
| `max_age` | int | Preflight cache duration in seconds |
| `allow_credentials` | bool | Set `Access-Control-Allow-Credentials: true` |

---

## `apigee_verify_api_key`

**File:** `modules/apigeecompat/verify_api_key.go`
**Apigee equivalent:** `VerifyAPIKey` policy
**Tests:** none

Validates an API key against Firestore when the `apigee_firestore` app is configured.
Without Firestore, falls back to passthrough mode (logs a warning, does not block).

On success, writes quota metadata into flow variables for downstream `apigee_quota`:
- `verifyapikey.<policy_name>.app_id`
- `verifyapikey.<policy_name>.apiproduct.developer.quota.limit`
- `verifyapikey.<policy_name>.apiproduct.developer.quota.interval` (seconds)
- `verifyapikey.<policy_name>.apiproduct.developer.quota.timeunit`

On failure, returns 401 with a JSON fault body.

```caddyfile
# TODO: apigee_verify_api_key not enforced — passthrough mode
apigee_verify_api_key {
    api_key_ref  request.header.authorization
    policy_name  VA-ValidateServiceKeys
}
```

| Config field | Type | Description |
|---|---|---|
| `api_key_ref` | string | Apigee variable reference for where the key is read from |
| `policy_name` | string | Used to namespace flow variables set on success (default: `VerifyAPIKey`) |
| `collection` | string | Firestore collection name (default: `api_keys`) |

API key documents in Firestore (`api_keys/{key}`):
```json
{ "enabled": true, "app_id": "my-app", "quota_limit": 200, "quota_interval": 1, "quota_timeunit": "minute" }
```

---

## `apigee_extract_variables`

**File:** `modules/apigeecompat/extract_variables.go`
**Apigee equivalent:** `ExtractVariables` policy
**Tests:** none

Extracts values from request headers or the request path using `{varname}` placeholder patterns and stores them as flow variables under a configured prefix. Wildcards (`*`) match a single path segment without capturing.

```caddyfile
# Header extraction: "Bearer abc123" → auth.clienttoken = "abc123"
apigee_extract_variables {
    prefix auth
    header_pattern authorization "Bearer {clienttoken}"
}

# Path extraction: "/passkit/v1/passes/x/sn123" → applepass.serialnumber = "sn123"
apigee_extract_variables {
    prefix    applepass
    path_pattern "/passkit/v1/passes/*/{serialnumber}"
}
```

| Config field | Type | Description |
|---|---|---|
| `prefix` | string | Namespace for extracted variables, e.g. `auth` → `auth.clienttoken` |
| `header_pattern` | `<name> <pattern>` | Extract from a request header using `{var}` placeholders |
| `path_pattern` | string | Extract from the request path using `{var}` placeholders; `*` matches one segment |
| `ignore_unresolved` | bool | Silently skip when no pattern matches (default: true) |

---

## `apigee_quota`

**File:** `modules/apigeecompat/quota.go`
**Apigee equivalent:** `Quota` policy
**Tests:** none

Per-key quota enforcement. When `apigee_firestore` is configured, the counter is stored
in Firestore for distributed enforcement across replicas. Without Firestore, falls back
to an in-memory per-process sliding window.

The limit and interval can be static config values or resolved at request time from flow
variables (e.g. set by `apigee_verify_api_key`). When the quota is exceeded, returns
`429 Too Many Requests` with a JSON fault body matching Apigee's format.

```caddyfile
# Static quota
apigee_quota {
    allow          10
    interval       60
    identifier_ref applepass.serialnumber
}

# Dynamic quota from API key metadata
apigee_quota {
    limit_ref      verifyapikey.VA-ValidateServiceKeys.apiproduct.developer.quota.limit
    interval_ref   verifyapikey.VA-ValidateServiceKeys.apiproduct.developer.quota.interval
    identifier_ref verifyapikey.VA-ValidateServiceKeys.app_id
}
```

| Config field | Type | Description |
|---|---|---|
| `allow` | int | Maximum requests allowed per interval |
| `limit_ref` | string | Flow variable that overrides `allow` at request time |
| `interval` | int | Window size in seconds |
| `interval_ref` | string | Flow variable that overrides `interval` at request time |
| `identifier_ref` | string | Flow variable used as the per-key identifier; if empty, quota is global |
| `collection` | string | Firestore collection name (default: `quotas`) |

---

## `apigee_kvm`

**File:** `modules/apigeecompat/kvm.go`
**Apigee equivalent:** `KeyValueMapOperations` policy
**Tests:** none

Writes key-value entries into the request flow state so downstream handlers
(e.g. `apigee_service_callout`) can reference them via `{flowvar.X}`.

**Static mode** (default): values are baked in at transpile time from `<InitialEntries>`.

**Live mode** (when `apigee_firestore` is configured and `map_name` is set): values are
fetched from Firestore at request time with a 5-minute TTL cache. Live values overlay
static entries. This allows KVM values to be updated without redeploying caddygee.

```caddyfile
# Static (transpiler default)
apigee_kvm {
    entry getAuthApiBaseUrl "auth.example.com"
}

# Live Firestore (add map_name to enable)
apigee_kvm {
    map_name KVM-Prod-AuthApiBaseUrl
    entry    getAuthApiBaseUrl "auth.example.com"
}
```

Firestore document (`kvm/KVM-Prod-AuthApiBaseUrl`):
```json
{ "getAuthApiBaseUrl": "auth.example.com" }
```

| Config field | Type | Description |
|---|---|---|
| `entry` | `<varname> <value>` | Static flow variable name and value (baked in at transpile time) |
| `map_name` | string | Firestore document ID in the KVM collection; enables live mode |
| `collection` | string | Firestore collection name (default: `kvm`) |
