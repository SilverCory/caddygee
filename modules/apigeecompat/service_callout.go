package apigeecompat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func init() {
	caddy.RegisterModule(ServiceCallout{})
	httpcaddyfile.RegisterHandlerDirective("service_callout", parseServiceCalloutCaddyfile)
}

// ServiceCallout is the service_callout Caddy module.
// It executes a synchronous HTTP request and stores the response in flow state.
type ServiceCallout struct {
	// TargetURL is the callout endpoint. Supports {flowvar.X} substitution.
	TargetURL string `json:"target_url"`
	// Method is the HTTP method (default: GET).
	Method string `json:"method,omitempty"`
	// RequestBodyVar is the flow state key whose value is used as the request body.
	RequestBodyVar string `json:"request_body_var,omitempty"`
	// ResponseVar is the flow state key prefix for storing response data.
	// Results are stored as ResponseVar.content, ResponseVar.status, ResponseVar.statusCode.
	ResponseVar string `json:"response_var,omitempty"`
	// TimeoutSeconds is the HTTP client timeout (default: 10).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Audience, if set, fetches a Google OIDC ID Token for this audience
	// and attaches it as Authorization: Bearer on the outbound request.
	Audience string `json:"audience,omitempty"`

	// client is the shared HTTP client constructed during Provision.
	client      *http.Client
	tokenSource oauth2.TokenSource
	logger      *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (ServiceCallout) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.service_callout",
		New: func() caddy.Module { return new(ServiceCallout) },
	}
}

// Provision validates and sets defaults.
func (s *ServiceCallout) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	if s.TargetURL == "" {
		return fmt.Errorf("service_callout: target_url is required")
	}
	// H1: SSRF guard — validate URL scheme unless the URL contains flow var placeholders.
	if !strings.Contains(s.TargetURL, "{flowvar.") {
		if !strings.HasPrefix(s.TargetURL, "http://") && !strings.HasPrefix(s.TargetURL, "https://") {
			return fmt.Errorf("service_callout: target_url must use http:// or https:// scheme, got %q", s.TargetURL)
		}
	}
	if s.Method == "" {
		s.Method = http.MethodGet
	}
	if s.TimeoutSeconds <= 0 {
		s.TimeoutSeconds = 10
	}
	// C1: Build the shared HTTP client once at provision time.
	s.client = &http.Client{
		Timeout: time.Duration(s.TimeoutSeconds) * time.Second,
	}
	if s.Audience != "" {
		// CADDYGEE_BYPASS_IDTOKEN=1: use a static token source for integration
		// testing without real ADC. The token value is taken from
		// CADDYGEE_STATIC_OUTBOUND_TOKEN (or "bypass-token" as fallback).
		if os.Getenv("CADDYGEE_BYPASS_IDTOKEN") == "1" {
			tok := os.Getenv("CADDYGEE_STATIC_OUTBOUND_TOKEN")
			if tok == "" {
				tok = "bypass-token"
			}
			s.tokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok})
		} else {
			ts, err := idtoken.NewTokenSource(context.Background(), s.Audience)
			if err != nil {
				return fmt.Errorf("service_callout: creating token source for audience %q: %w", s.Audience, err)
			}
			s.tokenSource = ts
		}
	}
	return nil
}

// ServeHTTP executes the callout and stores the response in flow state.
func (s *ServiceCallout) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, ok := GetFlowState(r.Context())
	if !ok {
		// No flow state — skip callout and continue.
		return next.ServeHTTP(w, r)
	}

	targetURL := resolveFlowVars(s.TargetURL, fs)

	// SEC-2: Re-validate scheme after flowvar substitution to prevent SSRF.
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		return fmt.Errorf("service_callout: resolved target_url has invalid scheme: %q", targetURL)
	}

	debugLog(r, s.logger, "service_callout: executing",
		zap.String("method", s.Method),
		zap.String("url", targetURL),
		zap.String("response_var", s.ResponseVar),
	)

	var bodyReader io.Reader
	if s.RequestBodyVar != "" {
		if bodyStr := fs.GetString(s.RequestBodyVar); bodyStr != "" {
			bodyReader = strings.NewReader(bodyStr)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.TimeoutSeconds)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, s.Method, targetURL, bodyReader)
	if err != nil {
		return fmt.Errorf("service_callout: building request: %w", err)
	}

	if s.tokenSource != nil {
		tok, err := s.tokenSource.Token()
		if err != nil {
			return fmt.Errorf("service_callout: fetching OIDC token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}

	// C1: Use the shared client provisioned once in Provision.
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("service_callout: executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("service_callout: reading response: %w", err)
	}

	prefix := s.ResponseVar
	if prefix == "" {
		prefix = "calloutResponse"
	}
	fs.Set(prefix+".content", string(body))
	fs.Set(prefix+".status", resp.Status)
	fs.Set(prefix+".statusCode", fmt.Sprintf("%d", resp.StatusCode))

	debugLog(r, s.logger, "service_callout: response",
		zap.String("url", targetURL),
		zap.Int("status", resp.StatusCode),
		zap.String("response_var", prefix),
	)

	return next.ServeHTTP(w, r)
}

// flowVarPattern matches {flowvar.X} placeholders.
var flowVarPattern = regexp.MustCompile(`\{flowvar\.([^}]+)\}`)

// resolveFlowVars substitutes {flowvar.X} placeholders with values from flow state.
func resolveFlowVars(s string, fs *FlowState) string {
	return flowVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := flowVarPattern.FindStringSubmatch(match)[1]
		if val := fs.GetString(key); val != "" {
			return val
		}
		return match // leave unresolved placeholder as-is
	})
}

func parseServiceCalloutCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s ServiceCallout
	for h.Next() {
		// service_callout <policy_name> [against <url>]
		// The policy name argument is informational; URL may follow.
		args := h.RemainingArgs()
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "against":
				i++
				if i < len(args) {
					s.TargetURL = args[i]
				}
			}
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "target_url":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				s.TargetURL = h.Val()
			case "method":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				s.Method = h.Val()
			case "response_var":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				s.ResponseVar = h.Val()
			case "timeout_seconds":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				fmt.Sscanf(h.Val(), "%d", &s.TimeoutSeconds)
			case "audience":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				s.Audience = h.Val()
			}
		}
	}
	return &s, nil
}

// Interface guards.
var (
	_ caddy.Module                = (*ServiceCallout)(nil)
	_ caddy.Provisioner           = (*ServiceCallout)(nil)
	_ caddyhttp.MiddlewareHandler = (*ServiceCallout)(nil)
	_ caddyfile.Unmarshaler       = (*ServiceCallout)(nil)
)

// UnmarshalCaddyfile satisfies the interface (parsing is handled by the directive helper).
func (s *ServiceCallout) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
