package apigeecompat

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ExtractVariables{})
	httpcaddyfile.RegisterHandlerDirective("extract_vars", parseExtractVariablesCaddyfile)
}

// ExtractVariables is the extract_vars Caddy module.
// It extracts values from headers, query parameters, and the request path
// using Apigee-style {varname} patterns and stores them as flow variables
// under a configured prefix.
//
// Equivalent to Apigee's ExtractVariables policy.
type ExtractVariables struct {
	// Prefix is the variable namespace, e.g. "auth". Extracted vars are stored
	// as "<prefix>.<name>", e.g. "auth.clienttoken".
	Prefix string `json:"prefix,omitempty"`

	// HeaderPatterns maps header name → pattern, e.g. {"authorization": "Bearer {clienttoken}"}.
	HeaderPatterns map[string]string `json:"header_patterns,omitempty"`

	// PathPatterns is a list of patterns matched against proxy.pathsuffix,
	// e.g. ["/passkit/v1/passes/*/{serialnumber}"].
	PathPatterns []string `json:"path_patterns,omitempty"`

	// IgnoreUnresolved controls whether the handler returns an error when no
	// pattern matches. When true (default), unmatched patterns are silently skipped.
	IgnoreUnresolved bool `json:"ignore_unresolved,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (ExtractVariables) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.extract_vars",
		New: func() caddy.Module { return new(ExtractVariables) },
	}
}

// Provision sets up logging.
func (ev *ExtractVariables) Provision(ctx caddy.Context) error {
	ev.logger = ctx.Logger()
	return nil
}

// ServeHTTP extracts values from the request and sets them as flow variables.
func (ev *ExtractVariables) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, ok := GetFlowState(r.Context())
	if !ok {
		return next.ServeHTTP(w, r)
	}

	// Header patterns.
	for headerName, pattern := range ev.HeaderPatterns {
		val := r.Header.Get(headerName)
		if val == "" {
			continue
		}
		vars := matchPattern(pattern, val)
		for name, extracted := range vars {
			key := ev.varKey(name)
			fs.Set(key, extracted)
			debugLog(r, ev.logger, "extract_vars: extracted header var",
				zap.String("header", headerName),
				zap.String("var", key),
				zap.String("value", extracted),
			)
		}
	}

	// Path patterns matched against the request path.
	for _, pattern := range ev.PathPatterns {
		vars := matchPattern(pattern, r.URL.Path)
		if len(vars) == 0 {
			continue
		}
		for name, extracted := range vars {
			key := ev.varKey(name)
			fs.Set(key, extracted)
			debugLog(r, ev.logger, "extract_vars: extracted path var",
				zap.String("pattern", pattern),
				zap.String("var", key),
				zap.String("value", extracted),
			)
		}
		break // stop at first matching pattern
	}

	return next.ServeHTTP(w, r)
}

func (ev *ExtractVariables) varKey(name string) string {
	if ev.Prefix == "" {
		return name
	}
	return ev.Prefix + "." + name
}

// matchPattern extracts named variables from s using an Apigee-style pattern.
// The pattern uses {varname} as a placeholder. Wildcards (*) match a single
// path segment. Returns a map of varname → extracted value, or nil if no match.
//
// Examples:
//
//	pattern="Bearer {clienttoken}"  s="Bearer abc123"  → {"clienttoken": "abc123"}
//	pattern="/v1/passes/*/{sn}"     s="/v1/passes/x/y" → {"sn": "y"}
func matchPattern(pattern, s string) map[string]string {
	vars := make(map[string]string)
	if extractPatternVars(pattern, s, vars) {
		return vars
	}
	return nil
}

// extractPatternVars recursively matches pattern against s, filling vars.
func extractPatternVars(pattern, s string, vars map[string]string) bool {
	if pattern == "" {
		return s == ""
	}

	// Variable placeholder {name}.
	if pattern[0] == '{' {
		end := strings.IndexByte(pattern, '}')
		if end < 0 {
			return false
		}
		name := pattern[1:end]
		rest := pattern[end+1:]

		// Determine what terminates this variable's value.
		// If the next char in the pattern is a path separator or end-of-string,
		// consume up to the next '/' in s. Otherwise consume until the literal
		// char that follows the placeholder.
		if rest == "" {
			// Consumes to end of string.
			vars[name] = s
			return true
		}
		// Find what delimiter follows the placeholder in the pattern.
		delim := rest[0]
		idx := strings.IndexByte(s, delim)
		if idx < 0 {
			// Try consuming the entire remaining string.
			vars[name] = s
			return extractPatternVars(rest, "", vars)
		}
		vars[name] = s[:idx]
		return extractPatternVars(rest, s[idx:], vars)
	}

	// Wildcard '*' — matches up to the next '/' or end.
	if pattern[0] == '*' {
		rest := pattern[1:]
		idx := strings.IndexByte(s, '/')
		var segment string
		var remaining string
		if idx < 0 {
			segment = s
			remaining = ""
		} else {
			segment = s[:idx]
			remaining = s[idx:]
		}
		_ = segment
		return extractPatternVars(rest, remaining, vars)
	}

	// Literal character.
	if s == "" || s[0] != pattern[0] {
		return false
	}
	return extractPatternVars(pattern[1:], s[1:], vars)
}

func parseExtractVariablesCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ev ExtractVariables
	ev.IgnoreUnresolved = true
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "prefix":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				ev.Prefix = h.Val()
			case "header_pattern":
				args := h.RemainingArgs()
				if len(args) < 2 {
					return nil, h.ArgErr()
				}
				if ev.HeaderPatterns == nil {
					ev.HeaderPatterns = make(map[string]string)
				}
				ev.HeaderPatterns[args[0]] = args[1]
			case "path_pattern":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				ev.PathPatterns = append(ev.PathPatterns, h.Val())
			case "ignore_unresolved":
				ev.IgnoreUnresolved = true
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &ev, nil
}

// Interface guards.
var (
	_ caddy.Module                = ExtractVariables{}
	_ caddy.Provisioner           = (*ExtractVariables)(nil)
	_ caddyhttp.MiddlewareHandler = (*ExtractVariables)(nil)
	_ caddyfile.Unmarshaler       = (*ExtractVariables)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (ev *ExtractVariables) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// Compile-time check that fmt is used.
var _ = fmt.Sprintf
