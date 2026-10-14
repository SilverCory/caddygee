package apigeecompat

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CORS{})
	httpcaddyfile.RegisterHandlerDirective("cors", parseCORSCaddyfile)
}

// CORS is the cors Caddy module.
// It adds Access-Control-* response headers and handles OPTIONS preflight
// requests, equivalent to Apigee's CORS policy.
type CORS struct {
	// AllowOrigins is the list of allowed origins.
	AllowOrigins []string `json:"allow_origins,omitempty"`
	// AllowMethods is the list of allowed HTTP methods.
	AllowMethods []string `json:"allow_methods,omitempty"`
	// AllowHeaders is the list of allowed request headers.
	AllowHeaders []string `json:"allow_headers,omitempty"`
	// ExposeHeaders is the list of headers to expose to the client.
	ExposeHeaders []string `json:"expose_headers,omitempty"`
	// MaxAge is the preflight cache duration in seconds.
	MaxAge int `json:"max_age,omitempty"`
	// AllowCredentials indicates whether credentials are allowed.
	AllowCredentials bool `json:"allow_credentials,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (CORS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cors",
		New: func() caddy.Module { return new(CORS) },
	}
}

// Provision sets defaults.
func (c *CORS) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger()
	return nil
}

// ServeHTTP sets CORS headers on the response. For OPTIONS preflight requests,
// it responds with 204 No Content immediately without calling next.
func (c CORS) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	origin := r.Header.Get("Origin")

	// Determine if the origin is allowed.
	allowOrigin := ""
	if len(c.AllowOrigins) == 0 || (len(c.AllowOrigins) == 1 && c.AllowOrigins[0] == "*") {
		allowOrigin = "*"
	} else if origin != "" {
		for _, o := range c.AllowOrigins {
			if strings.EqualFold(o, origin) {
				allowOrigin = origin
				break
			}
		}
	}

	if allowOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	}
	if len(c.AllowMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.AllowMethods, ", "))
	}
	if len(c.AllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.AllowHeaders, ", "))
	}
	if len(c.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposeHeaders, ", "))
	}
	if c.MaxAge > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(c.MaxAge))
	}
	if c.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Preflight: respond 204 immediately.
	if r.Method == http.MethodOptions {
		debugLog(r, c.logger, "cors: preflight",
			zap.String("origin", origin),
			zap.String("allow_origin", allowOrigin),
		)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	debugLog(r, c.logger, "cors: headers set",
		zap.String("origin", origin),
		zap.String("allow_origin", allowOrigin),
	)
	return next.ServeHTTP(w, r)
}

func parseCORSCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var c CORS
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "allow_origins":
				c.AllowOrigins = append(c.AllowOrigins, h.RemainingArgs()...)
			case "allow_methods":
				c.AllowMethods = append(c.AllowMethods, h.RemainingArgs()...)
			case "allow_headers":
				c.AllowHeaders = append(c.AllowHeaders, h.RemainingArgs()...)
			case "expose_headers":
				c.ExposeHeaders = append(c.ExposeHeaders, h.RemainingArgs()...)
			case "max_age":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				n, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.Errf("invalid max_age %q: %v", h.Val(), err)
				}
				c.MaxAge = n
			case "allow_credentials":
				if h.NextArg() {
					c.AllowCredentials = strings.EqualFold(h.Val(), "true")
				} else {
					c.AllowCredentials = true
				}
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &c, nil
}

// Interface guards.
var (
	_ caddy.Module                = CORS{}
	_ caddy.Provisioner           = (*CORS)(nil)
	_ caddyhttp.MiddlewareHandler = CORS{}
	_ caddyfile.Unmarshaler       = (*CORS)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (c *CORS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Ensure fmt is used.
var _ = fmt.Sprint
