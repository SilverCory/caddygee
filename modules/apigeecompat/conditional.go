package apigeecompat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Conditional{})
	httpcaddyfile.RegisterHandlerDirective("apigee_conditional", parseConditionalCaddyfile)
}

// Conditional is the apigee_conditional Caddy module.
// It evaluates an Apigee condition expression at request time and only invokes
// its inner handler when the condition is true. The condition is evaluated
// against the current request and flow variables.
type Conditional struct {
	// Condition is the raw Apigee condition expression, e.g.
	// "request.verb = \"POST\" AND proxy.pathsuffix = \"/graphql/current-user\""
	Condition string `json:"condition"`
	// Inner is the handler to invoke when the condition is true.
	// Uses Caddy's inline module loading (handler key identifies the module).
	Inner json.RawMessage `json:"inner" caddy:"namespace=http.handlers inline_key=handler"`

	inner caddyhttp.MiddlewareHandler
}

// CaddyModule returns the Caddy module metadata.
func (Conditional) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_conditional",
		New: func() caddy.Module { return new(Conditional) },
	}
}

// Provision decodes and provisions the inner handler.
func (c *Conditional) Provision(ctx caddy.Context) error {
	if c.Condition == "" {
		return fmt.Errorf("apigee_conditional: condition is required")
	}
	if len(c.Inner) == 0 {
		return fmt.Errorf("apigee_conditional: inner handler is required")
	}

	// Decode the handler module ID from the inner JSON.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(c.Inner, &m); err != nil {
		return fmt.Errorf("apigee_conditional: decoding inner handler: %w", err)
	}
	var handlerID string
	if err := json.Unmarshal(m["handler"], &handlerID); err != nil {
		return fmt.Errorf("apigee_conditional: reading inner handler id: %w", err)
	}

	val, err := ctx.LoadModule(c, "Inner")
	if err != nil {
		return fmt.Errorf("apigee_conditional: loading inner module %q: %w", handlerID, err)
	}
	h, ok := val.(caddyhttp.MiddlewareHandler)
	if !ok {
		return fmt.Errorf("apigee_conditional: inner module %q does not implement MiddlewareHandler", handlerID)
	}
	c.inner = h
	return nil
}

// ServeHTTP evaluates the condition and conditionally invokes the inner handler.
func (c *Conditional) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, _ := GetFlowState(r.Context())
	if evalCondition(c.Condition, r, fs) {
		return c.inner.ServeHTTP(w, r, next)
	}
	return next.ServeHTTP(w, r)
}

// evalCondition evaluates a simplified Apigee condition expression against the
// current request and flow state. Supports AND/OR/NOT and common variables:
//   - request.verb
//   - proxy.pathsuffix / request.path
//   - request.header.<name>
//   - environment.name (from flow var "environment.name")
//   - <flowvar> (any flow variable, for boolean checks)
func evalCondition(expr string, r *http.Request, fs *FlowState) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	result, _ := evalExpr(expr, r, fs)
	return result
}

// evalExpr returns (result, remaining) for recursive evaluation.
func evalExpr(expr string, r *http.Request, fs *FlowState) (bool, string) {
	return evalOr(expr, r, fs)
}

func evalOr(expr string, r *http.Request, fs *FlowState) (bool, string) {
	left, rest := evalAnd(expr, r, fs)
	for {
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(strings.ToLower(rest), "or ") && !strings.EqualFold(rest, "or") {
			break
		}
		rest = strings.TrimSpace(rest[2:])
		right, remaining := evalAnd(rest, r, fs)
		left = left || right
		rest = remaining
	}
	return left, rest
}

func evalAnd(expr string, r *http.Request, fs *FlowState) (bool, string) {
	left, rest := evalUnary(expr, r, fs)
	for {
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(strings.ToLower(rest), "and ") && !strings.EqualFold(rest, "and") {
			break
		}
		rest = strings.TrimSpace(rest[3:])
		right, remaining := evalUnary(rest, r, fs)
		left = left && right
		rest = remaining
	}
	return left, rest
}

func evalUnary(expr string, r *http.Request, fs *FlowState) (bool, string) {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		result, rest := evalUnary(expr[4:], r, fs)
		return !result, rest
	}
	if strings.HasPrefix(expr, "!") {
		result, rest := evalUnary(expr[1:], r, fs)
		return !result, rest
	}
	return evalPrimary(expr, r, fs)
}

func evalPrimary(expr string, r *http.Request, fs *FlowState) (bool, string) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") {
		inner, rest := splitParen(expr[1:])
		result, _ := evalOr(inner, r, fs)
		return result, rest
	}
	return evalComparison(expr, r, fs)
}

// splitParen finds the matching close paren and returns (inside, rest).
func splitParen(s string) (string, string) {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i], strings.TrimSpace(s[i+1:])
			}
		}
	}
	return s, ""
}

func evalComparison(expr string, r *http.Request, fs *FlowState) (bool, string) {
	// Tokenise just enough to get left, op, right.
	left, rest := nextToken(expr)
	if left == "" {
		return false, rest
	}
	op, rest2 := nextToken(rest)
	if !isComparisonOp(op) {
		// Boolean variable reference.
		return resolveVarBool(left, r, fs), rest
	}
	right, rest3 := nextToken(rest2)
	// Unquote string literals.
	right = unquote(right)

	leftVal := resolveVar(left, r, fs)
	return compare(leftVal, op, right), rest3
}

func isComparisonOp(s string) bool {
	switch strings.ToLower(s) {
	case "=", "==", "!=", ">", "<", ">=", "<=", "matchespath", "matches", "startswith":
		return true
	}
	return false
}

func compare(left, op, right string) bool {
	rightLower := strings.ToLower(right)
	switch strings.ToLower(op) {
	case "=", "==":
		if rightLower == "null" {
			return left == ""
		}
		return strings.EqualFold(left, right) || left == right
	case "!=":
		if rightLower == "null" {
			return left != ""
		}
		return left != right
	case "matchespath", "matches":
		return matchPath(left, right)
	case "startswith":
		return strings.HasPrefix(left, right)
	case ">", "<", ">=", "<=":
		// Numeric comparison first; fall back to lexicographic string compare.
		lf, lerr := strconv.ParseFloat(left, 64)
		rf, rerr := strconv.ParseFloat(right, 64)
		if lerr == nil && rerr == nil {
			switch strings.ToLower(op) {
			case ">":
				return lf > rf
			case "<":
				return lf < rf
			case ">=":
				return lf >= rf
			case "<=":
				return lf <= rf
			}
		}
		switch strings.ToLower(op) {
		case ">":
			return left > right
		case "<":
			return left < right
		case ">=":
			return left >= right
		case "<=":
			return left <= right
		}
		return false
	}
	return false
}

func resolveVar(name string, r *http.Request, fs *FlowState) string {
	lower := strings.ToLower(name)
	switch lower {
	case "request.verb":
		return r.Method
	case "proxy.pathsuffix", "request.path":
		return r.URL.Path
	case "request.url.path":
		return r.URL.Path
	}
	if strings.HasPrefix(lower, "request.header.") {
		return r.Header.Get(name[len("request.header."):])
	}
	// Fall back to flow state.
	if fs != nil {
		return fs.GetString(name)
	}
	return ""
}

func resolveVarBool(name string, r *http.Request, fs *FlowState) bool {
	val := resolveVar(name, r, fs)
	switch strings.ToLower(val) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no", "":
		return false
	}
	return val != ""
}

// matchPath implements a simple glob match for MatchesPath/Matches.
// Supports * (single segment) and ** (multi-segment).
func matchPath(path, pattern string) bool {
	return globMatch(pattern, path)
}

func globMatch(pattern, s string) bool {
	if pattern == "**" {
		return true
	}
	if pattern == "" {
		return s == ""
	}
	if pattern[0] == '*' {
		if len(pattern) > 1 && pattern[1] == '*' {
			// ** matches any
			return strings.HasPrefix(s, "/") || s == ""
		}
		// * matches up to next /
		rest := pattern[1:]
		idx := strings.IndexByte(s, '/')
		if idx < 0 {
			return globMatch(rest, "") || globMatch(rest, s)
		}
		return globMatch(rest, s[idx:])
	}
	if s == "" {
		return false
	}
	if pattern[0] == s[0] {
		return globMatch(pattern[1:], s[1:])
	}
	return false
}

// nextToken returns the next token and remaining string.
func nextToken(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == quote {
				return s[:i+1], strings.TrimSpace(s[i+1:])
			}
		}
		return s, ""
	}
	// Two-char operators.
	if len(s) >= 2 {
		two := s[:2]
		if two == "==" || two == "!=" || two == ">=" || two == "<=" {
			return two, strings.TrimSpace(s[2:])
		}
	}
	// Single-char operators.
	if s[0] == '=' || s[0] == '>' || s[0] == '<' || s[0] == '!' {
		return string(s[0]), strings.TrimSpace(s[1:])
	}
	// Word.
	end := 0
	for end < len(s) && !isSpace(s[end]) && s[end] != '=' && s[end] != '!' &&
		s[end] != '>' && s[end] != '<' && s[end] != '"' && s[end] != '\'' && s[end] != '(' && s[end] != ')' {
		end++
	}
	return s[:end], strings.TrimSpace(s[end:])
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// Ensure time is used (needed for future iat/exp checks in evalComparison).
var _ = time.Now

func parseConditionalCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var c Conditional
	for h.Next() {
		args := h.RemainingArgs()
		if len(args) > 0 {
			c.Condition = args[0]
		}
		// Parse the inner handler block, e.g.:
		//   apigee_conditional "cond" {
		//       reverse_proxy https://example.com
		//   }
		for h.NextBlock(0) {
			innerDirective := h.Val()
			innerArgs := h.RemainingArgs()
			// Build a minimal JSON object for known inner handlers.
			switch innerDirective {
			case "reverse_proxy":
				if len(innerArgs) == 0 {
					return nil, h.ArgErr()
				}
				host := stripScheme(innerArgs[0])
				isHTTPS := strings.HasPrefix(innerArgs[0], "https://")
				if isHTTPS && !strings.Contains(host, ":") {
					host = host + ":443"
				}
				if isHTTPS {
					c.Inner = json.RawMessage(fmt.Sprintf(
						`{"handler":"reverse_proxy","upstreams":[{"dial":%s}],"transport":{"protocol":"http","tls":{}}}`,
						jsonString(host),
					))
				} else {
					c.Inner = json.RawMessage(fmt.Sprintf(
						`{"handler":"reverse_proxy","upstreams":[{"dial":%s}]}`,
						jsonString(host),
					))
				}
			case "apigee_google_auth":
				if len(innerArgs) == 0 {
					return nil, h.ArgErr()
				}
				c.Inner = json.RawMessage(fmt.Sprintf(
					`{"handler":"apigee_google_auth","audience":%s}`,
					jsonString(innerArgs[0]),
				))
			case "apigee_verify_jwt":
				var algorithm, jwksURI, publicKey, issuer, audience, policyName string
				for h.NextBlock(1) {
					switch h.Val() {
					case "algorithm":
						if h.NextArg() {
							algorithm = h.Val()
						}
					case "jwks_uri":
						if h.NextArg() {
							jwksURI = h.Val()
						}
					case "public_key":
						if h.NextArg() {
							publicKey = h.Val()
						}
					case "issuer":
						if h.NextArg() {
							issuer = h.Val()
						}
					case "audience":
						if h.NextArg() {
							audience = h.Val()
						}
					case "policy_name":
						if h.NextArg() {
							policyName = h.Val()
						}
					}
				}
				obj := fmt.Sprintf(`{"handler":"apigee_verify_jwt","algorithm":%s,"policy_name":%s`,
					jsonString(algorithm), jsonString(policyName))
				if jwksURI != "" {
					obj += fmt.Sprintf(`,"jwks_uri":%s`, jsonString(jwksURI))
				}
				if publicKey != "" {
					obj += fmt.Sprintf(`,"public_key":%s`, jsonString(publicKey))
				}
				if issuer != "" {
					obj += fmt.Sprintf(`,"issuer":%s`, jsonString(issuer))
				}
				if audience != "" {
					obj += fmt.Sprintf(`,"audience":%s`, jsonString(audience))
				}
				obj += `}`
				c.Inner = json.RawMessage(obj)
			case "apigee_raise_fault":
				var statusCode int
				var body string
				for h.NextBlock(1) {
					switch h.Val() {
					case "status_code":
						if h.NextArg() {
							fmt.Sscanf(h.Val(), "%d", &statusCode)
						}
					case "body":
						if h.NextArg() {
							body = h.Val()
						}
					}
				}
				obj := fmt.Sprintf(`{"handler":"apigee_raise_fault","status_code":%d`, statusCode)
				if body != "" {
					obj += fmt.Sprintf(`,"body":%s`, jsonString(body))
				}
				obj += `}`
				c.Inner = json.RawMessage(obj)
			case "apigee_spike_arrest":
				var rate string
				if len(innerArgs) > 0 {
					rate = innerArgs[0]
				}
				for h.NextBlock(1) {
					switch h.Val() {
					case "rate":
						if h.NextArg() {
							rate = h.Val()
						}
					}
				}
				c.Inner = json.RawMessage(fmt.Sprintf(`{"handler":"apigee_spike_arrest","rate":%s}`, jsonString(rate)))
			case "apigee_cors":
				// Drain the block; CORS config is fully in JSON.
				for h.NextBlock(1) {
					_ = h.Val()
					_ = h.RemainingArgs()
				}
				c.Inner = json.RawMessage(`{"handler":"apigee_cors"}`)
			case "apigee_verify_api_key":
				var apiKeyRef string
				for h.NextBlock(1) {
					switch h.Val() {
					case "api_key_ref":
						if h.NextArg() {
							apiKeyRef = h.Val()
						}
					}
				}
				obj := `{"handler":"apigee_verify_api_key"`
				if apiKeyRef != "" {
					obj += fmt.Sprintf(`,"api_key_ref":%s`, jsonString(apiKeyRef))
				}
				obj += `}`
				c.Inner = json.RawMessage(obj)
			case "raw_json":
				// The transpiler bakes full JSON into a raw_json subdirective so
				// that all handler configs survive the Caddyfile round-trip intact.
				if len(innerArgs) == 0 {
					return nil, h.ArgErr()
				}
				c.Inner = json.RawMessage(innerArgs[0])
			case "apigee_javascript_callout":
				// Parse the nested source/timeout_ms block.
				var source string
				var timeoutMs int
				for h.NextBlock(1) {
					switch h.Val() {
					case "source":
						if h.NextArg() {
							source = h.Val()
						}
					case "timeout_ms":
						if h.NextArg() {
							fmt.Sscanf(h.Val(), "%d", &timeoutMs)
						}
					}
				}
				obj := fmt.Sprintf(`{"handler":"apigee_javascript_callout","source":%s`, jsonString(source))
				if timeoutMs > 0 {
					obj += fmt.Sprintf(`,"timeout_ms":%d`, timeoutMs)
				}
				obj += `}`
				c.Inner = json.RawMessage(obj)
			default:
				// For handlers with a sub-block, drain the block without capturing
				// it — the inner handler key alone is sufficient for zero-config
				// handlers (e.g. apigee_assign_message, apigee_raise_fault, etc.)
				// that carry all their config at provision time.
				for h.NextBlock(1) {
					_ = h.Val()
					_ = h.RemainingArgs()
				}
				c.Inner = json.RawMessage(fmt.Sprintf(`{"handler":%s}`, jsonString(innerDirective)))
			}
		}
	}
	if c.Condition == "" {
		return nil, fmt.Errorf("apigee_conditional: condition argument is required")
	}
	if len(c.Inner) == 0 {
		return nil, fmt.Errorf("apigee_conditional: inner handler block is required")
	}
	return &c, nil
}

// jsonString returns s as a JSON string literal.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// stripScheme removes https:// or http:// from a URL, returning host:port.
func stripScheme(u string) string {
	for _, pfx := range []string{"https://", "http://"} {
		if strings.HasPrefix(u, pfx) {
			return u[len(pfx):]
		}
	}
	return u
}

// Interface guards.
var (
	_ caddy.Module                = Conditional{}
	_ caddy.Provisioner           = (*Conditional)(nil)
	_ caddyhttp.MiddlewareHandler = (*Conditional)(nil)
	_ caddyfile.Unmarshaler       = (*Conditional)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (c *Conditional) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
