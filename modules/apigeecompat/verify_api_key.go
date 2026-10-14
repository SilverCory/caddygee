package apigeecompat

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(VerifyAPIKey{})
	httpcaddyfile.RegisterHandlerDirective("apigee_verify_api_key", parseVerifyAPIKeyCaddyfile)
}

// VerifyAPIKey is the apigee_verify_api_key Caddy module.
// It is currently a PASSTHROUGH that logs a warning but does not block requests.
//
// A real implementation would require a key store (e.g. Cloud Firestore or
// Secret Manager) to validate API keys against registered developer apps.
// For now, this module exists to prevent the transpiler from emitting
// "apigee_unknown" for VerifyAPIKey policies and to serve as a placeholder
// for future enforcement.
type VerifyAPIKey struct {
	// APIKeyRef is the Apigee variable reference for the API key source,
	// e.g. "request.header.authorization".
	APIKeyRef string `json:"api_key_ref,omitempty"`

	logger *zap.Logger
	warned bool
}

// CaddyModule returns the Caddy module metadata.
func (VerifyAPIKey) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_verify_api_key",
		New: func() caddy.Module { return new(VerifyAPIKey) },
	}
}

// Provision sets up logging.
func (v *VerifyAPIKey) Provision(ctx caddy.Context) error {
	v.logger = ctx.Logger()
	v.logger.Warn("apigee_verify_api_key: API key validation is NOT enforced (passthrough mode)",
		zap.String("api_key_ref", v.APIKeyRef))
	return nil
}

// ServeHTTP passes all requests through without validation.
// It logs a warning once per provisioning cycle.
func (v *VerifyAPIKey) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}

func parseVerifyAPIKeyCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var v VerifyAPIKey
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "api_key_ref":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.APIKeyRef = h.Val()
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &v, nil
}

// Interface guards.
var (
	_ caddy.Module                = VerifyAPIKey{}
	_ caddy.Provisioner           = (*VerifyAPIKey)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyAPIKey)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyAPIKey)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (v *VerifyAPIKey) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
