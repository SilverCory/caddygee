# Developing New Policies

This guide covers how to add a new Apigee policy module to caddygee: the Caddy middleware, the parser types, the transpiler mapping, and the Caddyfile emitter.

## Architecture Overview

Each Apigee policy maps to a Caddy HTTP middleware module. There are four layers to implement:

1. **Apigee types** (`internal/apigee/types.go`) — Go struct for parsing the policy XML
2. **Parser** (`internal/apigee/parser.go`) — XML unmarshalling of the policy file
3. **Transpiler mapper** (`internal/transpiler/mapper.go`) — maps parsed Apigee config to a `PolicyHandler`
4. **Caddyfile emitter** (`internal/transpiler/emitter_caddyfile.go`) — serialises the `PolicyHandler` back to Caddyfile text
5. **Caddy module** (`modules/apigeecompat/<policy>.go`) — the actual HTTP middleware

## Request Context: FlowState

All policy modules share a per-request `FlowState` map. It is injected by the `flow_state` middleware, which must be the first handler in every route.

```go
// Get the FlowState for this request. Returns nil, false if flow_state is missing.
fs, ok := apigeecompat.GetFlowState(r.Context())

// Read a variable (e.g. set by extract_vars upstream).
token := fs.GetString("auth.clienttoken")

// Write a variable (for downstream policies to read).
fs.Set("my_policy.result", "ok")
```

`FlowState` is concurrency-safe — it uses a `sync.RWMutex` internally.

Built-in variables seeded by `flow_state` at request start:

| Variable | Source |
|---|---|
| `environment.name` | `ENVIRONMENT_NAME` env var (set at provision time) |

## Step 1 — Add XML Types

Add a struct for the new policy to `internal/apigee/types.go`. Add a pointer field to `Policy`:

```go
// Policy is the root parsed policy type.
type Policy struct {
    // ... existing fields ...

    // MyPolicy fields
    MyPolicy *MyPolicyConfig
}

// MyPolicyConfig holds parsed config for a <MyPolicy> element.
type MyPolicyConfig struct {
    SomeField string `xml:"SomeField"`
    Rate      int    `xml:"Rate"`
}
```

## Step 2 — Parse the XML

In `internal/apigee/parser.go`, handle the new element name in the policy switch. The XML element name (e.g. `"MyPolicy"`) is the value of `p.Type`:

```go
case "MyPolicy":
    var cfg MyPolicyConfig
    if err := xml.Unmarshal(raw, &cfg); err != nil {
        return err
    }
    p.MyPolicy = &cfg
```

## Step 3 — Map to a Handler

In `internal/transpiler/mapper.go`, add a case in `mapStepToHandler` (or `mapStepToHandlerPhase` for response-phase policies):

```go
case "MyPolicy":
    if p.MyPolicy == nil {
        break
    }
    cfg, _ := json.Marshal(map[string]interface{}{
        "some_field": p.MyPolicy.SomeField,
        "rate":       p.MyPolicy.Rate,
    })
    return PolicyHandler{
        Module:     "http.handlers.my_policy",
        PolicyName: step.Name,
        Config:     cfg,
    }
```

**Response-phase policies** (those that modify the response after the upstream call) must be appended before `appendTargetHandlers` in `mapFlow`. The `phase` field in the policy config or the `AssignTo.Type == "response"` attribute determines this. See `assign_message` as the reference.

**Conditional steps** are wrapped automatically by `mapStepToHandlerPhase` when `step.Condition != ""`:

```go
if step.Condition != "" {
    return ConditionalHandler{Condition: step.Condition, Inner: inner}
}
```

## Step 4 — Emit Caddyfile

In `internal/transpiler/emitter_caddyfile.go`, add a case in `emitHandler` for the new short name. The short name is derived from the module ID by stripping the `http.handlers.` prefix:

```go
if shortName == "my_policy" && len(v.Config) > 0 {
    var cfg struct {
        SomeField string `json:"some_field"`
        Rate      int    `json:"rate"`
    }
    if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Rate > 0 {
        fmt.Fprintf(b, "%smy_policy {\n", indent)
        if cfg.SomeField != "" {
            fmt.Fprintf(b, "%s\tsome_field %s\n", indent, cfg.SomeField)
        }
        fmt.Fprintf(b, "%s\trate %d\n", indent, cfg.Rate)
        fmt.Fprintf(b, "%s}\n", indent)
        return
    }
}
```

Also register the module short name in `moduleShortName`:

```go
"http.handlers.my_policy": "my_policy",
```

## Step 5 — Write the Caddy Module

Create `modules/apigeecompat/my_policy.go`. The minimal structure:

```go
package apigeecompat

import (
    "net/http"
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
    caddy.RegisterModule(MyPolicy{})
    httpcaddyfile.RegisterHandlerDirective("my_policy", parseMyPolicyCaddyfile)
}

type MyPolicy struct {
    SomeField string `json:"some_field,omitempty"`
    Rate      int    `json:"rate"`
}

func (MyPolicy) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "http.handlers.my_policy",
        New: func() caddy.Module { return new(MyPolicy) },
    }
}

func (m *MyPolicy) Provision(_ caddy.Context) error {
    // Validate config, set up logger, etc.
    return nil
}

func (m *MyPolicy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    fs, _ := GetFlowState(r.Context())
    // ... policy logic ...
    return next.ServeHTTP(w, r)
}

func parseMyPolicyCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
    var m MyPolicy
    for h.Next() {
        for h.NextBlock(0) {
            switch h.Val() {
            case "some_field":
                if !h.NextArg() { return nil, h.ArgErr() }
                m.SomeField = h.Val()
            case "rate":
                if !h.NextArg() { return nil, h.ArgErr() }
                // parse int
            default:
                return nil, h.Errf("unrecognised subdirective %q", h.Val())
            }
        }
    }
    return &m, nil
}

// Interface guards.
var (
    _ caddy.Module                = MyPolicy{}
    _ caddy.Provisioner           = (*MyPolicy)(nil)
    _ caddyhttp.MiddlewareHandler = (*MyPolicy)(nil)
    _ caddyfile.Unmarshaler       = (*MyPolicy)(nil)
)

func (m *MyPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
```

The module is auto-registered via the blank import in `cmd/caddy/main.go`:

```go
import _ "caddygee/modules/apigeecompat"
```

## Variable Substitution

Policies that produce values in template strings (like `assign_message`) call `resolveValue` to expand `{varname}` patterns from the `FlowState`:

```go
// resolveValue handles both {flowvar.X} and bare {extracted.id} patterns.
resolved := resolveValue(templateString, fs)
```

The function handles both the explicit `{flowvar.X}` prefix form and the shorter bare `{varname}` form used throughout Apigee policy XML.

## Conditional Wrapping (apigee_conditional / `when`)

When a step has a non-empty `<Condition>` in the proxy XML, it is wrapped in a `ConditionalHandler`:

```go
ConditionalHandler{
    Condition: "request.verb = \"GET\"",
    Inner:     PolicyHandler{...},
}
```

At runtime the `when` module evaluates the Apigee condition expression against the current `FlowState` and only invokes the inner handler if it returns true.

Conditions have access to all flow variables including `environment.name`, request headers (as `request.header.<Name>`), `request.verb`, etc. The full condition language is implemented in `internal/condition/`.

## Debug Logging

Use `debugLog` for per-request debug output that is only emitted when debug mode is active:

```go
debugLog(r, ev.logger, "my_policy: extracted value",
    zap.String("key", key),
    zap.String("value", val),
)
```

Debug mode is enabled per-request via the `X-Apigee-Debug` header or `?_debug=` query param. Both must match the `DEBUG_TOKEN` env var. If `DEBUG_TOKEN` is unset, debug mode is disabled for all requests.
