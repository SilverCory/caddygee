package apigeecompat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"google.golang.org/api/idtoken"
)

func init() {
	caddy.RegisterModule(new(VerifyGoogleIDToken))
	httpcaddyfile.RegisterHandlerDirective("verify_google_idtoken", parseVerifyGoogleIDTokenCaddyfile)
}

// VerifyGoogleIDToken is the verify_google_idtoken Caddy module.
// It verifies an inbound Google OIDC ID token (the kind produced by google_auth
// or Cloud Run service-to-service auth) using Google's public JWKS endpoint.
//
// On success it stores email, sub, and hd into flow state as
// google_idtoken.<policy_name>.email / .sub / .hd.
// On failure it writes a 401 response and does NOT call the next handler.
// If AllowedEmails is non-empty and the caller's email is not in the list, a
// 403 is returned instead.
type VerifyGoogleIDToken struct {
	// PolicyName namespaces the flow variables set on success.
	PolicyName string `json:"policy_name"`
	// Audience is this service's own Cloud Run URL — the expected aud claim.
	Audience string `json:"audience"`
	// AllowedEmails, if non-empty, is an allowlist of caller service account emails.
	// When empty, any Google-issued token with the correct audience is accepted.
	AllowedEmails []string `json:"allowed_emails,omitempty"`

	logger *zap.Logger
}

// googleIDTokenValidate is the token validation function. Replaced in unit tests.
// When CADDYGEE_BYPASS_IDTOKEN=1 the validator short-circuits: any non-empty
// bearer token is accepted and the raw token value is used as the email claim.
// This is ONLY for integration testing — never set this in production.
var googleIDTokenValidate = func(ctx context.Context, token, audience string) (email, sub, hd string, err error) {
	if os.Getenv("CADDYGEE_BYPASS_IDTOKEN") == "1" {
		return token, token, "", nil
	}
	payload, verr := idtoken.Validate(ctx, token, audience)
	if verr != nil {
		return "", "", "", verr
	}
	email, _ = payload.Claims["email"].(string)
	sub = payload.Subject
	hd, _ = payload.Claims["hd"].(string)
	return email, sub, hd, nil
}

// CaddyModule returns the Caddy module metadata.
func (*VerifyGoogleIDToken) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.verify_google_idtoken",
		New: func() caddy.Module { return new(VerifyGoogleIDToken) },
	}
}

// Provision validates configuration.
func (v *VerifyGoogleIDToken) Provision(ctx caddy.Context) error {
	v.logger = ctx.Logger()
	if v.PolicyName == "" {
		return fmt.Errorf("verify_google_idtoken: policy_name is required")
	}
	if v.Audience == "" {
		return fmt.Errorf("verify_google_idtoken: audience is required")
	}
	return nil
}

// ServeHTTP verifies the Google OIDC ID token and populates flow variables.
func (v *VerifyGoogleIDToken) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rawToken := extractBearer(r)
	if rawToken == "" {
		debugLog(r, v.logger, "verify_google_idtoken: rejected — no bearer token",
			zap.String("policy", v.PolicyName))
		return v.reject(w, http.StatusUnauthorized, "missing or malformed Authorization header")
	}

	email, sub, hd, err := googleIDTokenValidate(r.Context(), rawToken, v.Audience)
	if err != nil {
		debugLog(r, v.logger, "verify_google_idtoken: rejected — validation failed",
			zap.String("policy", v.PolicyName), zap.Error(err))
		return v.reject(w, http.StatusUnauthorized, "unauthorized")
	}

	if len(v.AllowedEmails) > 0 {
		allowed := false
		for _, e := range v.AllowedEmails {
			if e == email {
				allowed = true
				break
			}
		}
		if !allowed {
			debugLog(r, v.logger, "verify_google_idtoken: rejected — email not in allowlist",
				zap.String("policy", v.PolicyName), zap.String("email", email))
			return v.reject(w, http.StatusForbidden, "unauthorized")
		}
	}

	if fs, ok := GetFlowState(r.Context()); ok {
		prefix := "google_idtoken." + v.PolicyName + "."
		fs.Set(prefix+"email", email)
		fs.Set(prefix+"sub", sub)
		fs.Set(prefix+"hd", hd)
	}

	debugLog(r, v.logger, "verify_google_idtoken: accepted",
		zap.String("policy", v.PolicyName),
		zap.String("email", email),
	)
	return next.ServeHTTP(w, r)
}

func (v *VerifyGoogleIDToken) reject(w http.ResponseWriter, status int, reason string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
	return nil
}

func parseVerifyGoogleIDTokenCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var v VerifyGoogleIDToken
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "policy_name":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.PolicyName = h.Val()
			case "audience":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.Audience = h.Val()
			case "allowed_emails":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.ArgErr()
				}
				v.AllowedEmails = append(v.AllowedEmails, args...)
			}
		}
	}
	return &v, nil
}

// Interface guards.
var (
	_ caddy.Module                = (*VerifyGoogleIDToken)(nil)
	_ caddy.Provisioner           = (*VerifyGoogleIDToken)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyGoogleIDToken)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyGoogleIDToken)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (v *VerifyGoogleIDToken) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
