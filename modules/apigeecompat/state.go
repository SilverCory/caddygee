package apigeecompat

import (
	"context"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(FlowStateManager{})
	httpcaddyfile.RegisterHandlerDirective("apigee_state", parseFlowStateCaddyfile)
}

// FlowStateManager is the apigee_state Caddy module.
// It must be the first handler in every Caddy route that uses Apigee policy modules.
// It initialises a fresh FlowState for each request and injects it into the context.
// It also seeds the environment.name flow variable from the ENVIRONMENT_NAME env var.
type FlowStateManager struct {
	envName string // set at Provision time from ENVIRONMENT_NAME env var
}

// CaddyModule returns the Caddy module metadata.
func (FlowStateManager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_state",
		New: func() caddy.Module { return new(FlowStateManager) },
	}
}

// Provision reads environment configuration at startup.
func (f *FlowStateManager) Provision(_ caddy.Context) error {
	f.envName = os.Getenv("ENVIRONMENT_NAME")
	return nil
}

// ServeHTTP initialises flow state, seeds built-in variables, and injects it into the request context.
func (f FlowStateManager) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs := &FlowState{vars: make(map[string]interface{})}
	if f.envName != "" {
		fs.Set("environment.name", f.envName)
	}
	ctx := context.WithValue(r.Context(), flowStateKey, fs)
	return next.ServeHTTP(w, r.WithContext(ctx))
}

func parseFlowStateCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	// apigee_state takes no arguments.
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
