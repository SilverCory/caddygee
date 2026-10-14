package apigeecompat

import (
	"context"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func init() {
	caddy.RegisterModule(GoogleAuth{})
	httpcaddyfile.RegisterHandlerDirective("google_auth", parseGoogleAuthCaddyfile)
}

// GoogleAuth is the google_auth Caddy module.
// It fetches a Google OIDC ID Token for the configured audience and injects it
// as "Authorization: Bearer <token>" on the outbound request, replicating the
// behaviour of Apigee's <Authentication><GoogleIDToken> target config.
//
// Token acquisition uses Application Default Credentials (ADC): the standard
// Google auth chain (GOOGLE_APPLICATION_CREDENTIALS env var, gcloud login,
// GCE/GKE metadata server). Tokens are cached and auto-refreshed by the
// underlying TokenSource.
type GoogleAuth struct {
	// Audience is the target URL audience for the ID token (typically the
	// Cloud Run service URL, e.g. "https://my-service-abc123-nw.a.run.app").
	Audience string `json:"audience"`

	tokenSource oauth2.TokenSource
	logger      *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (GoogleAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.google_auth",
		New: func() caddy.Module { return new(GoogleAuth) },
	}
}

// Provision validates config and initialises the token source.
func (g *GoogleAuth) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	if g.Audience == "" {
		return fmt.Errorf("google_auth: audience is required")
	}
	ts, err := idtoken.NewTokenSource(context.Background(), g.Audience)
	if err != nil {
		return fmt.Errorf("google_auth: creating token source for %q: %w", g.Audience, err)
	}
	g.tokenSource = ts
	return nil
}

// ServeHTTP fetches a fresh (or cached) ID token and sets the Authorization header.
func (g *GoogleAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	tok, err := g.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("google_auth: fetching ID token for %q: %w", g.Audience, err)
	}
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	debugLog(r, g.logger, "google_auth: injected ID token",
		zap.String("audience", g.Audience),
		zap.Time("token_expiry", tok.Expiry),
	)
	return next.ServeHTTP(w, r)
}

func parseGoogleAuthCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var g GoogleAuth
	for h.Next() {
		args := h.RemainingArgs()
		if len(args) > 0 {
			g.Audience = args[0]
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "audience":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				g.Audience = h.Val()
			}
		}
	}
	return &g, nil
}

// Interface guards.
var (
	_ caddy.Module                = GoogleAuth{}
	_ caddy.Provisioner           = (*GoogleAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoogleAuth)(nil)
	_ caddyfile.Unmarshaler       = (*GoogleAuth)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (g *GoogleAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
