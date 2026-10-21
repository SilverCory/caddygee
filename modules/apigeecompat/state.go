package apigeecompat

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func init() {
	caddy.RegisterModule(FlowStateManager{})
	httpcaddyfile.RegisterHandlerDirective("flow_state", parseFlowStateCaddyfile)
}

// debugBlocklistCollection is the Firestore collection used to store revoked debug token IDs.
const debugBlocklistCollection = "debug_blocklist"

// FlowStateManager is the flow_state Caddy module.
// It must be the first handler in every Caddy route that uses Apigee policy modules.
// It initialises a fresh FlowState for each request and injects it into the context.
// It also seeds the environment.name flow variable from the ENVIRONMENT_NAME env var.
//
// Per-request debug logging (X-Apigee-Debug header or ?_debug= query param) is only
// activated when the value is a valid HMAC-signed debug token (see debug.go).
// Tokens are issued by caddygee-server's /debug-token endpoint.
// If DEBUG_SIGNING_KEY is unset, debug mode is disabled entirely.
//
// Revoked token IDs are checked against a Firestore collection (debug_blocklist) when
// Firestore is configured, with a 30-second TTL cache. The DEBUG_BLOCKLIST env var
// (comma-separated IDs) provides a static fallback when Firestore is not available.
type FlowStateManager struct {
	envName        string                 // set at Provision time from ENVIRONMENT_NAME
	signingKey     []byte                 // set at Provision time from DEBUG_SIGNING_KEY; nil = disabled
	staticBlocklist map[string]struct{}   // seeded from DEBUG_BLOCKLIST env var
	fsClient       *firestore.Client      // nil when Firestore not configured
	blocklistCache *ttlCache[bool]        // Firestore blocklist lookup cache (30s TTL)
}

// CaddyModule returns the Caddy module metadata.
func (FlowStateManager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.flow_state",
		New: func() caddy.Module { return new(FlowStateManager) },
	}
}

// Provision reads environment configuration at startup.
func (f *FlowStateManager) Provision(ctx caddy.Context) error {
	f.envName = os.Getenv("ENVIRONMENT_NAME")

	if key := os.Getenv("DEBUG_SIGNING_KEY"); key != "" {
		f.signingKey = []byte(key)
	}

	f.staticBlocklist = make(map[string]struct{})
	if raw := os.Getenv("DEBUG_BLOCKLIST"); raw != "" {
		for _, id := range strings.Split(raw, ",") {
			if id = strings.TrimSpace(id); id != "" {
				f.staticBlocklist[id] = struct{}{}
			}
		}
	}

	if app, ok := GetFirestoreApp(ctx); ok {
		f.fsClient = app.Client()
		f.blocklistCache = newTTLCache[bool](30 * time.Second)
	}

	return nil
}

// ServeHTTP initialises flow state, seeds built-in variables, and injects it into the request context.
// If the request carries a valid X-Apigee-Debug token or _debug query param, the debug context flag
// is set so downstream handlers can emit per-request DEBUG log lines tagged with the token ID and subject.
func (f FlowStateManager) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs := &FlowState{vars: make(map[string]interface{})}
	if f.envName != "" {
		fs.Set("environment.name", f.envName)
	}
	ctx := context.WithValue(r.Context(), flowStateKey, fs)

	if len(f.signingKey) > 0 {
		token := r.Header.Get("X-Apigee-Debug")
		if token == "" {
			token = r.URL.Query().Get("_debug")
		}
		if token != "" {
			if id, sub, ok := verifyDebugToken(f.signingKey, token); ok && !f.isBlocked(r.Context(), id) {
				ctx = withDebug(ctx)
				ctx = withDebugID(ctx, id, sub)
			}
		}
	}

	return next.ServeHTTP(w, r.WithContext(ctx))
}

// isBlocked reports whether the token ID is in the blocklist.
// Checks the static env-var blocklist first, then Firestore (with cache).
func (f *FlowStateManager) isBlocked(ctx context.Context, id string) bool {
	if _, blocked := f.staticBlocklist[id]; blocked {
		return true
	}
	if f.fsClient == nil {
		return false
	}
	// Check the TTL cache first.
	if v, ok := f.blocklistCache.Get(id); ok {
		return v != nil && *v
	}
	// Cache miss — query Firestore.
	_, err := f.fsClient.Collection(debugBlocklistCollection).Doc(id).Get(ctx)
	if err == nil {
		t := true
		f.blocklistCache.Set(id, &t)
		return true
	}
	if status.Code(err) == codes.NotFound {
		t := false
		f.blocklistCache.Set(id, &t)
		return false
	}
	// On Firestore error, fail open (don't block the token).
	return false
}

func parseFlowStateCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	for h.Next() {
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return FlowStateManager{}, nil
}

// Interface guards.
var (
	_ caddy.Module                = FlowStateManager{}
	_ caddy.Provisioner           = (*FlowStateManager)(nil)
	_ caddyhttp.MiddlewareHandler = FlowStateManager{}
	_ caddyfile.Unmarshaler       = (*FlowStateManager)(nil)
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler (no-op, no config fields).
func (f *FlowStateManager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}
