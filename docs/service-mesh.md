# Service Mesh — Service-to-Service Auth

## Context

caddygee already handles outbound auth to Cloud Run backends via `google_auth` (injects a Google OIDC ID token before `reverse_proxy`). The missing pieces for a full mesh are:

1. **Inbound**: no module to verify incoming Google OIDC tokens from other Cloud Run services — `verify_jwt` handles generic JWTs but has no Google-specific wiring.
2. **Callout auth**: `service_callout` makes HTTP sub-requests but cannot attach an OIDC token, so service-to-service callouts are unauthenticated.

The goal: two caddygee deployments (or any Cloud Run services) can mutually authenticate using GCP service account identity, with no API keys or static secrets — just ADC on the caller side and OIDC verification on the receiver side.

**Why not mTLS?** Cloud Run doesn't support mTLS at the infrastructure level; OIDC is the idiomatic Cloud Run service-to-service auth mechanism.

---

## New Modules

### 1. `verify_google_idtoken` — inbound OIDC verification

New file: `modules/apigeecompat/verify_google_idtoken.go`

```go
type VerifyGoogleIDToken struct {
    // PolicyName namespaces the flow variables set on success.
    PolicyName string `json:"policy_name"`
    // Audience is this service's own Cloud Run URL — the expected `aud` claim.
    Audience string `json:"audience"`
    // AllowedEmails, if non-empty, is an allowlist of service account emails.
    // When empty, any Google-issued token with the right audience is accepted.
    AllowedEmails []string `json:"allowed_emails,omitempty"`

    logger *zap.Logger
}
```

**Caddyfile syntax:**
```caddyfile
verify_google_idtoken {
    policy_name   MeshAuth
    audience      https://service-b-abc123-nw.a.run.app
    allowed_emails service-a@my-project.iam.gserviceaccount.com
}
```

**How it works:**
- Extracts Bearer token from `Authorization` header (reuses `extractBearer()` from `verify_jwt.go`)
- Calls `idtoken.Validate(ctx, token, audience)` — handles JWKS fetch, caching, signature, expiry, issuer, and audience in one call. No manual JWKS code needed.
- If `AllowedEmails` is set, checks `payload.Claims["email"]` against the list; rejects with 403 if not found.
- On success, stores into FlowState: `google_idtoken.<policy>.email`, `google_idtoken.<policy>.sub`, `google_idtoken.<policy>.hd`
- On failure: 401 with `{"error":"unauthorized"}`

**Inject-able validate function for tests** (package-level var):
```go
var googleIDTokenValidate = idtoken.Validate
```

**Module registration** (pointer receiver):
```go
func init() {
    caddy.RegisterModule(new(VerifyGoogleIDToken))
    httpcaddyfile.RegisterHandlerDirective("verify_google_idtoken", parseVerifyGoogleIDTokenCaddyfile)
}
func (*VerifyGoogleIDToken) CaddyModule() caddy.ModuleInfo { ... }
```

---

### 2. `service_callout` — add `audience` for outbound OIDC

Modify: `modules/apigeecompat/service_callout.go`

Add one field and its token source:
```go
type ServiceCallout struct {
    // ... existing fields unchanged ...

    // Audience, if set, fetches a Google OIDC ID Token for this audience
    // and attaches it as Authorization: Bearer on the outbound request.
    // Mirrors google_auth behaviour for sub-requests.
    Audience string `json:"audience,omitempty"`

    tokenSource oauth2.TokenSource // non-nil when Audience is set
}
```

**In `Provision`:** when `Audience != ""`, call `idtoken.NewTokenSource(context.Background(), s.Audience)` and store as `s.tokenSource`.

**In `ServeHTTP`:** before `s.client.Do(req)`, if `s.tokenSource != nil`, call `tok, err := s.tokenSource.Token()` and set `req.Header.Set("Authorization", "Bearer "+tok.AccessToken)`.

**In `parseServiceCalloutCaddyfile`:** add `case "audience":` subdirective.

---

## Transpiler Changes

### `internal/transpiler/mapper.go`

Add new handler type and config struct:

```go
type VerifyGoogleIDTokenHandler struct {
    Type   string          `json:"type"`
    Config json.RawMessage `json:"config,omitempty"`
}

type verifyGoogleIDTokenConfig struct {
    PolicyName    string   `json:"policy_name"`
    Audience      string   `json:"audience"`
    AllowedEmails []string `json:"allowed_emails,omitempty"`
}
```

Extend `serviceCalloutConfig` with `Audience string \`json:"audience,omitempty"\``.

There is no direct Apigee policy type that maps to `verify_google_idtoken`. It is written directly in fragments as a caddygee-native directive — no `mapPolicyToHandler` changes needed for the first pass.

### `internal/transpiler/emitter_caddyfile.go`

Add emit case in `emitHandler` for `"verify_google_idtoken"` (after the `verify_jwt`/`verify_api_key` cases):

```go
if shortName == "verify_google_idtoken" && len(v.Config) > 0 {
    var cfg verifyGoogleIDTokenConfig
    if err := json.Unmarshal(v.Config, &cfg); err == nil {
        fmt.Fprintf(b, "%sverify_google_idtoken {\n", indent)
        fmt.Fprintf(b, "%s\tpolicy_name %s\n", indent, cfg.PolicyName)
        fmt.Fprintf(b, "%s\taudience %s\n", indent, cfg.Audience)
        for _, email := range cfg.AllowedEmails {
            fmt.Fprintf(b, "%s\tallowed_emails %s\n", indent, email)
        }
        fmt.Fprintf(b, "%s}\n", indent)
        return
    }
}
```

Extend the `service_callout` emit case to include `audience` when set.

### `modules/apigeecompat/conditional.go`

Add `"verify_google_idtoken"` to the inner handler switch in the `when` block parser. Follow the same pattern as `verify_api_key`.

---

## Caddyfile Examples

**Service B receiving mesh calls:**
```caddyfile
route /internal/* {
    flow_state
    verify_google_idtoken {
        policy_name   MeshAuth
        audience      https://service-b-abc123-nw.a.run.app
        allowed_emails service-a@project.iam.gserviceaccount.com
    }
    reverse_proxy localhost:8081
}
```

**Service A making an authenticated sub-request:**
```caddyfile
route /api/* {
    flow_state
    service_callout {
        target_url   https://service-b-abc123-nw.a.run.app/internal/enrich
        audience     https://service-b-abc123-nw.a.run.app
        response_var enrichResult
    }
    reverse_proxy https://upstream
}
```

**Existing `google_auth` pattern for `reverse_proxy` targets is unchanged:**
```caddyfile
route /api/* {
    flow_state
    google_auth https://service-b-abc123-nw.a.run.app
    reverse_proxy https://service-b-abc123-nw.a.run.app
}
```

---

## Implementation Order

1. `modules/apigeecompat/verify_google_idtoken.go` — new file, self-contained
2. `modules/apigeecompat/verify_google_idtoken_test.go` — unit tests with injected validate func
3. `modules/apigeecompat/service_callout.go` — add `Audience` + token source
4. `modules/apigeecompat/service_callout_test.go` — add audience test with injected token source
5. `modules/apigeecompat/conditional.go` — add `verify_google_idtoken` to inner handler switch
6. `internal/transpiler/mapper.go` — add `verifyGoogleIDTokenConfig`, extend `serviceCalloutConfig`
7. `internal/transpiler/emitter_caddyfile.go` — emit both new types

Steps 1–4 can be tested independently of 5–7.

---

## What NOT to Build

- **`mesh` Caddy app module** — no central service registry needed; Cloud Run URLs are the registry.
- **Manual JWKS for `verify_google_idtoken`** — `idtoken.Validate` handles it with internal caching.
- **Auto-transpile Apigee `VerifyJWT` → `verify_google_idtoken`** — leave for a follow-up.
- **Token revocation checking** — Google OIDC tokens are 1-hour max; not appropriate on the fast path.
- **Workload Identity Federation** — ADC on Cloud Run covers the use case.
- **Distributed `spike_arrest`** — out of scope.

---

## Verification

```bash
# Build and vet
go build ./... && go vet ./...

# Run all tests (no live GCP needed)
go test -race ./...

# Integration tests (requires Cloud Run SA with ADC)
go test -tags integration -run TestVerifyGoogleIDToken_LiveToken ./modules/apigeecompat/

# Docker smoke test
docker build -t caddygee-test .
docker run --rm -e PORT=8080 -e DEPLOY_PORT=9090 -p 18080:8080 caddygee-test &
sleep 10 && curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/health
# expect: 200
```
