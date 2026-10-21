# caddygee Policy Reference

All supported Apigee policy types and their Caddy directive equivalents.
Modules live in `modules/apigeecompat/`. The transpiler maps Apigee XML policy
types to these directives automatically during `caddygee-cli transpile`.

## Firestore integration

Several modules optionally connect to Cloud Firestore for distributed state.
Enable by adding `firestore_app` to your Caddyfile global options block:

```caddyfile
{
    firestore_app {
        project_id  my-gcp-project
        database_id (default)
    }
}
```

When `firestore_app` is configured:

| Directive | Behaviour without Firestore | Behaviour with Firestore |
|-----------|-----------------------------|--------------------------|
| `verify_api_key` | Passthrough (logs warning) | Enforces — looks up key in `api_keys` collection |
| `quota` | In-memory per-process counter | Distributed atomic counter in `quotas` collection |
| `kvm` | Static baked-in values only | Fetches live values from `kvm` collection with TTL cache |

### Firestore data model

**`api_keys/{sha256(key)}`** — one document per API key (key is SHA-256 hashed):
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

**`kvm/{map_name}`** — KVM documents; field names must match `Get.assignTo` values from the Apigee XML:
```json
{ "getAuthApiBaseUrl": "auth.example.com" }
```

---

## Implementation checklist

- [x] `flow_state` — flow state initialisation (required first handler on every route)
- [x] `when` — runtime condition evaluation wrapping an inner handler
- [x] `assign_message` — header and body manipulation (AssignMessage)
- [x] `raise_fault` — short-circuit with a fixed error response (RaiseFault)
- [x] `google_auth` — fetch Google OIDC ID Token and inject as Bearer (target authentication)
- [x] `verify_jwt` — verify RS256/RS512 JWT from Authorization header (VerifyJWT)
- [x] `js_callout` — execute inline JS against flow variables (Javascript)
- [x] `service_callout` — synchronous HTTP sub-request (ServiceCallout)
- [x] `spike_arrest` — per-server token-bucket rate limiting (SpikeArrest)
- [x] `cors` — CORS response headers + OPTIONS preflight (CORS)
- [x] `verify_api_key` — API key validation via Firestore (VerifyAPIKey)
- [x] `extract_vars` — extract request values into flow variables (ExtractVariables)
- [x] `quota` — per-key quota enforcement (Quota)
- [x] `kvm` — Key-Value Map: static entries + live Firestore overlay (KeyValueMapOperations)

---

## `flow_state`

**File:** `modules/apigeecompat/state.go`
**Apigee equivalent:** internal flow initialisation (not a policy — implicit in every proxy)
**Tests:** `state_test.go`

Injects a fresh `FlowState` into the request context. Must be the **first handler**
in every route. Seeds `environment.name` from the `ENVIRONMENT_NAME` environment
variable at provision time.

Also gates debug logging: if `DEBUG_SIGNING_KEY` is set and the request includes a valid
HMAC-signed debug token in `X-Apigee-Debug` header or `?_debug=` query param, verbose
per-handler logs are emitted for that request only. Tokens are issued via `POST /debug-token`
on the deploy server and carry the issuer's GCP identity (`debug_sub` log field).

```caddyfile
flow_state
```

No configuration options. The transpiler emits this automatically as the first
handler in every route.

---

## `when`

**File:** `modules/apigeecompat/conditional.go`
**Apigee equivalent:** step-level `<Condition>` on any policy step
**Tests:** `conditional_test.go`

Evaluates an Apigee condition expression at request time. Invokes the inner handler
only when the condition is true; otherwise falls through to the next handler.

Supports: `AND`, `OR`, `NOT`, `=`, `!=`, `MatchesPath`, `Matches`, `StartsWith`,
`>`, `<`, `>=`, `<=`, and flow variables (`request.verb`, `proxy.pathsuffix`,
`request.header.*`, `environment.name`, arbitrary flow vars).

```caddyfile
when environment.name = "preview" {
    reverse_proxy https://service-preview.run.app
}

when request.verb = "POST" AND proxy.pathsuffix = "/graphql" {
    verify_jwt {
        algorithm  RS256
        jwks_uri   https://login.example.com/v1/keys
        policy_name MyVerifyJWT
    }
}
```

The condition is the bare arguments to `when` — no surrounding quotes needed.

---

## `assign_message`

**File:** `modules/apigeecompat/assign_message.go`
**Apigee equivalent:** `AssignMessage` policy
**Tests:** `assign_message_test.go`

Manipulates request or response headers and body. Header values support
`{flowvar.X}` substitution against the current flow state.

```caddyfile
assign_message {
    set_header  Authorization "Bearer {flowvar.token}"
    add_header  X-Forwarded-By "caddygee"
    remove_header X-Internal-Key
    phase       request
}
```

| Subdirective | Description |
|---|---|
| `set_header <name> <value>` | Replace header value (creates if absent) |
| `add_header <name> <value>` | Add header (appends if already present) |
| `remove_header <name>` | Remove header from request/response |
| `set_body <value>` | Replace request/response body |
| `phase request\|response` | Which phase to apply (default: `request`) |

---

## `raise_fault`

**File:** `modules/apigeecompat/raise_fault.go`
**Apigee equivalent:** `RaiseFault` policy

Short-circuits the handler chain and returns a fixed HTTP response immediately.
Used for method validation, auth failures, and error flows.

```caddyfile
raise_fault {
    status_code 405
    body        "{\"error\":\"MethodNotAllowed\"}"
}
```

| Subdirective | Description |
|---|---|
| `status_code <int>` | HTTP status code (default: 500) |
| `body <string>` | Response body (optional) |

---

## `google_auth`

**File:** `modules/apigeecompat/google_auth.go`
**Apigee equivalent:** `<Authentication><GoogleIDToken>` on a TargetEndpoint

Fetches a Google OIDC ID Token for the configured audience using Application Default
Credentials and injects it as `Authorization: Bearer <token>` on the outbound
request. Required before `reverse_proxy` when targeting private Cloud Run services.

```caddyfile
google_auth https://my-service-abc123-nw.a.run.app
```

The token is cached and refreshed automatically before expiry. Requires a service
account — will fail with user credentials locally.

---

## `verify_jwt`

**File:** `modules/apigeecompat/verify_jwt.go`
**Apigee equivalent:** `VerifyJWT` policy

Verifies a Bearer JWT from the `Authorization` header. On success, stores decoded
claims as flow variables under `jwt.<policy_name>.decoded.claim.<name>` for use by
downstream handlers. On failure, returns `401 Unauthorized` without leaking
internal error details.

Supports RS256 and RS512 with either a static PEM public key or a JWKS URI
(auto-refreshed every 5 minutes using a provisioned HTTP client with 10s timeout).
Validates `exp`, `nbf`, `iss`, and optionally `aud`.

```caddyfile
# JWKS endpoint (recommended)
verify_jwt {
    algorithm   RS256
    jwks_uri    https://login.example.com/oauth2/v1/keys
    issuer      https://login.example.com
    audience    https://api.example.com
    policy_name VerifyCustomerToken
}

# Static PEM key
verify_jwt {
    algorithm   RS512
    public_key  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    issuer      https://idp.example.com
    policy_name VerifyServiceToken
}
```

| Subdirective | Description |
|---|---|
| `algorithm RS256\|RS512` | JWT signing algorithm |
| `jwks_uri <url>` | JWKS endpoint URL (mutually exclusive with `public_key`) |
| `public_key <pem>` | PEM-encoded RSA public key |
| `issuer <string>` | Expected `iss` claim value |
| `audience <string>` | Expected `aud` claim value (optional) |
| `policy_name <string>` | Namespaces decoded claims in flow state (**required**) |

---

## `js_callout`

**File:** `modules/apigeecompat/javascript_callout.go`
**Apigee equivalent:** `Javascript` policy
**Tests:** `javascript_callout_test.go`

Executes an inline JavaScript snippet using the goja ECMAScript 5.1 runtime. The
script reads and writes Apigee flow variables via `context.getVariable()` /
`context.setVariable()`. Runs with a configurable timeout; the runtime is pooled
for performance.

```caddyfile
js_callout MyScript {
    source     "context.setVariable('token', context.getVariable('request.header.authorization'));"
    timeout_ms 200
}
```

| Subdirective | Description |
|---|---|
| `source <string>` | Inline JavaScript source (**required**) |
| `timeout_ms <int>` | Execution timeout in milliseconds (default: 200) |
| `lib_dir <path>` | Directory of shared `.js` library files pre-loaded into every runtime |

Flow variable access from JS:
```js
var verb = context.getVariable("request.verb");
context.setVariable("my.custom.var", "value");
// Also available: context.requestMethod, context.requestPath,
//                 context.requestHost, context.requestHeaders, context.queryParams
```

---

## `service_callout`

**File:** `modules/apigeecompat/service_callout.go`
**Apigee equivalent:** `ServiceCallout` policy
**Tests:** `service_callout_test.go`

Executes a synchronous HTTP sub-request to an external service and stores the
response in flow variables. Supports `{flowvar.X}` substitution in the target URL.
The resolved URL is validated to use `http://` or `https://` (SSRF protection applied
both at provision time and after flow variable substitution).

Response is stored as:
- `<response_var>.content` — response body
- `<response_var>.status` — status string (e.g. `"200 OK"`)
- `<response_var>.statusCode` — status code as string (e.g. `"200"`)

```caddyfile
service_callout {
    target_url      https://{flowvar.getAuthApiBaseUrl}/verify
    method          GET
    response_var    SC-AuthApiVerify
    timeout_seconds 10
}
```

| Subdirective | Description |
|---|---|
| `target_url <url>` | Callout endpoint; supports `{flowvar.X}` (**required**) |
| `method <string>` | HTTP method (default: `GET`) |
| `request_body_var <string>` | Flow variable whose value becomes the request body |
| `response_var <string>` | Flow variable prefix for storing the response |
| `timeout_seconds <int>` | Request timeout (default: 10) |

> **Note:** Outbound request headers set via `<Add><Headers>` in Apigee's
> `ServiceCallout` XML are not supported. The transpiler emits a `# WARNING` comment
> when it detects this pattern.

---

## `spike_arrest`

**File:** `modules/apigeecompat/spike_arrest.go`
**Apigee equivalent:** `SpikeArrest` policy

Per-server token-bucket rate limiter. Rejects excess requests with
`429 Too Many Requests` and a JSON fault body matching Apigee's format.
The bucket is shared across all requests to the Caddy process (not per-client).

```caddyfile
spike_arrest 30ps
```

| Argument | Description |
|---|---|
| `<rate>` | Integer + `ps` (per second) or `pm` (per minute). e.g. `30ps`, `600pm` |

---

## `cors`

**File:** `modules/apigeecompat/cors.go`
**Apigee equivalent:** `CORS` policy

Adds `Access-Control-*` response headers to all responses. For `OPTIONS` preflight
requests, responds immediately with `204 No Content` without calling the next handler.

```caddyfile
cors {
    allow_origins      https://example.com https://www.example.com
    allow_methods      GET POST OPTIONS PUT DELETE
    allow_headers      Authorization Content-Type X-Api-Key
    expose_headers     X-Request-Id
    max_age            3600
    allow_credentials  true
}
```

| Subdirective | Description |
|---|---|
| `allow_origins <list>` | Allowed origin values; `*` permits any origin |
| `allow_methods <list>` | Allowed HTTP methods |
| `allow_headers <list>` | Allowed request headers |
| `expose_headers <list>` | Response headers browsers may access |
| `max_age <int>` | Preflight cache duration in seconds |
| `allow_credentials true` | Set `Access-Control-Allow-Credentials: true` |

---

## `verify_api_key`

**File:** `modules/apigeecompat/verify_api_key.go`
**Apigee equivalent:** `VerifyAPIKey` policy

Validates an API key against Firestore when `firestore_app` is configured.
Without Firestore, falls back to passthrough mode (logs a warning, does not block).

The API key is SHA-256 hashed before use as a Firestore document ID. On success,
writes quota metadata into flow variables for downstream `quota`:

- `verifyapikey.<policy_name>.app_id`
- `verifyapikey.<policy_name>.apiproduct.developer.quota.limit`
- `verifyapikey.<policy_name>.apiproduct.developer.quota.interval`
- `verifyapikey.<policy_name>.apiproduct.developer.quota.timeunit`

On failure, returns `401 Unauthorized`.

```caddyfile
# TODO: verify_api_key not enforced — passthrough mode
verify_api_key {
    api_key_ref request.header.authorization
    policy_name VA-ValidateServiceKeys
}
```

| Subdirective | Description |
|---|---|
| `api_key_ref <string>` | Apigee variable reference for where the key is read from |
| `policy_name <string>` | Namespaces flow variables set on success (default: `VerifyAPIKey`) |
| `collection <string>` | Firestore collection name (default: `api_keys`) |

Firestore document (`api_keys/{sha256(key)}`):
```json
{ "enabled": true, "app_id": "my-app", "quota_limit": 200, "quota_interval": 1, "quota_timeunit": "minute" }
```

---

## `extract_vars`

**File:** `modules/apigeecompat/extract_variables.go`
**Apigee equivalent:** `ExtractVariables` policy
**Tests:** `extract_variables_test.go`

Extracts values from request headers or the request path using `{varname}` placeholder
patterns and stores them as flow variables under a configured prefix. `*` in a path
pattern matches one path segment without capturing.

```caddyfile
# Header extraction: "Bearer abc123" → auth.clienttoken = "abc123"
extract_vars {
    prefix         auth
    header_pattern authorization "Bearer {clienttoken}"
}

# Path extraction: "/passes/v1/passes/x/sn123" → applepass.serialnumber = "sn123"
extract_vars {
    prefix       applepass
    path_pattern "/passes/v1/passes/*/{serialnumber}"
}
```

| Subdirective | Description |
|---|---|
| `prefix <string>` | Namespace for extracted variables, e.g. `auth` → `auth.clienttoken` |
| `header_pattern <name> <pattern>` | Extract from a request header using `{var}` placeholders |
| `path_pattern <pattern>` | Extract from the request path; `*` matches one segment without capturing |

---

## `quota`

**File:** `modules/apigeecompat/quota.go`
**Apigee equivalent:** `Quota` policy
**Tests:** `quota_test.go`

Per-key quota enforcement using a sliding window counter. When `firestore_app` is
configured, the counter is stored in Firestore for distributed enforcement across
replicas. Without Firestore, falls back to an in-memory per-process counter.

The limit and interval can be static config values or resolved at request time from
flow variables (e.g. set by `verify_api_key`). Exceeding the quota returns
`429 Too Many Requests` with a JSON fault body matching Apigee's format.

```caddyfile
# Static quota
quota {
    allow          10
    interval       60
    identifier_ref applepass.serialnumber
}

# Dynamic quota from API key metadata
quota {
    limit_ref      verifyapikey.VA-ValidateServiceKeys.apiproduct.developer.quota.limit
    interval_ref   verifyapikey.VA-ValidateServiceKeys.apiproduct.developer.quota.interval
    identifier_ref verifyapikey.VA-ValidateServiceKeys.app_id
}
```

| Subdirective | Description |
|---|---|
| `allow <int>` | Maximum requests per interval |
| `limit_ref <string>` | Flow variable that overrides `allow` at request time |
| `interval <int>` | Window size in seconds |
| `interval_ref <string>` | Flow variable that overrides `interval` at request time |
| `identifier_ref <string>` | Flow variable used as the per-key identifier; if empty, quota is global |
| `collection <string>` | Firestore collection name (default: `quotas`) |

---

## `kvm`

**File:** `modules/apigeecompat/kvm.go`
**Apigee equivalent:** `KeyValueMapOperations` policy
**Tests:** `kvm_test.go`

Writes key-value entries into the request flow state so downstream handlers
(e.g. `service_callout`) can reference them via `{flowvar.X}`.

**Static mode** (always active): values baked in at transpile time from `<InitialEntries>`.

**Live mode** (when `firestore_app` is configured and `map_name` is set): values are
fetched from Firestore at request time with a TTL cache (from `<ExpiryTimeInSecs>`,
default 300s). Live values overlay static entries. Allows KVM values to be updated
without redeploying caddygee.

Apigee KVM scope is environment-level: each environment has its own Firestore document.
Update the document for the running environment; changes take effect within the TTL.

```caddyfile
# Transpiler output — static entries + live Firestore overlay
kvm {
    map_name         KVM-Prod-AuthApiBaseUrl
    cache_ttl_seconds 300
    entry            getAuthApiBaseUrl "auth.example.com"
}
```

Firestore document (`kvm/KVM-Prod-AuthApiBaseUrl`) — field names must match `Get.assignTo`
values from the Apigee XML (not the KVM key names):
```json
{ "getAuthApiBaseUrl": "auth.example.com" }
```

| Subdirective | Description |
|---|---|
| `entry <varname> <value>` | Static flow variable (baked in at transpile time; fallback when Firestore unavailable) |
| `map_name <string>` | Firestore document ID in the KVM collection; enables live mode |
| `cache_ttl_seconds <int>` | How long to cache Firestore values (default: 300) |
| `collection <string>` | Firestore collection name (default: `kvm`) |
