package apigeecompat

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RaiseFault{})
	httpcaddyfile.RegisterHandlerDirective("apigee_raise_fault", parseRaiseFaultCaddyfile)
}

// RaiseFault is the apigee_raise_fault Caddy module.
// It immediately returns a fixed HTTP response, short-circuiting the handler
// chain. Equivalent to Apigee's RaiseFault policy.
type RaiseFault struct {
	// StatusCode is the HTTP status code to return (default: 500).
	StatusCode int `json:"status_code,omitempty"`
	// Body is the response body to send.
	Body string `json:"body,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (RaiseFault) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_raise_fault",
		New: func() caddy.Module { return new(RaiseFault) },
	}
}

// Provision validates and sets defaults.
func (rf *RaiseFault) Provision(ctx caddy.Context) error {
	rf.logger = ctx.Logger()
	if rf.StatusCode == 0 {
		rf.StatusCode = http.StatusInternalServerError
	}
	if rf.StatusCode < 100 || rf.StatusCode > 599 {
		return fmt.Errorf("apigee_raise_fault: invalid status_code %d", rf.StatusCode)
	}
	return nil
}

// ServeHTTP writes the fault response immediately without calling next.
func (rf RaiseFault) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	debugLog(r, rf.logger, "apigee_raise_fault",
		zap.Int("status_code", rf.StatusCode),
	)
	if rf.Body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rf.StatusCode)
	if rf.Body != "" {
		_, err := fmt.Fprint(w, rf.Body)
		return err
	}
	return nil
}

func parseRaiseFaultCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rf RaiseFault
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "status_code":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if _, err := fmt.Sscanf(h.Val(), "%d", &rf.StatusCode); err != nil {
					return nil, h.Errf("invalid status_code %q: %v", h.Val(), err)
				}
			case "body":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rf.Body = h.Val()
			}
		}
	}
	return &rf, nil
}

// Interface guards.
var (
	_ caddy.Module                = RaiseFault{}
	_ caddy.Provisioner           = (*RaiseFault)(nil)
	_ caddyhttp.MiddlewareHandler = RaiseFault{}
	_ caddyfile.Unmarshaler       = (*RaiseFault)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (rf *RaiseFault) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
