// Package transpiler converts a parsed Apigee bundle into a Caddy configuration.
package transpiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"caddygee/internal/apigee"
	"caddygee/internal/condition"
)

// Options controls how the transpiler generates output.
type Options struct {
	// ListenAddress is the address Caddy will bind to (e.g. ":443", ":2015").
	ListenAddress string
	// Format is "json" or "caddyfile".
	Format string
	// Fragment omits the outer server block, emitting only named matchers and
	// handle blocks. Used when producing a fragment for the deploy endpoint.
	Fragment bool
	// CloudRun prepends the standard Cloud Run global options block and server-level
	// directives (admin, auto_https off, trusted_proxies, structured logging, /health).
	CloudRun bool
	// MatcherPrefix is prepended to all named matcher identifiers to avoid
	// collisions when multiple bundles are merged into a single Caddyfile.
	// When empty, no prefix is added.
	MatcherPrefix string
}

// CaddyConfig is the top-level internal model for a Caddy configuration.
// It maps directly to the Caddy JSON admin API envelope.
type CaddyConfig struct {
	Servers map[string]*Server
}

// Server represents a single Caddy HTTP server (listen address + routes).
type Server struct {
	Listen []string
	Routes []*Route
}

// Route is a Caddy route: a set of matchers and an ordered list of handlers.
type Route struct {
	// MatcherName is the @name used in Caddyfile output. Empty = match all.
	MatcherName string
	// Matcher holds the translated condition. Nil = match all.
	Matcher *condition.CaddyMatcher
	// UnsupportedCondition is the raw Apigee condition string when translation
	// produced warnings (for comment output).
	UnsupportedCondition string
	// Handlers is the ordered list of middleware + terminal handler.
	Handlers []Handler
}

// Handler is a single entry in a route's handler chain.
type Handler interface {
	handlerTag()
	// ModuleID returns the Caddy module identifier, e.g. "http.handlers.reverse_proxy".
	ModuleID() string
}

// FlowStateHandler injects the Apigee flow state into request context.
// It must be the first handler in every route.
type FlowStateHandler struct{}

func (FlowStateHandler) handlerTag()       {}
func (FlowStateHandler) ModuleID() string  { return "http.handlers.apigee_state" }

// PolicyHandler invokes one of the custom apigeecompat Caddy modules.
type PolicyHandler struct {
	Module     string          // e.g. "http.handlers.apigee_assign_message"
	PolicyName string          // original Apigee policy name (for docs/comments)
	Config     json.RawMessage // module-specific JSON config
}

func (PolicyHandler) handlerTag()      {}
func (p PolicyHandler) ModuleID() string { return p.Module }

// ReverseProxyHandler is the terminal reverse_proxy directive.
type ReverseProxyHandler struct {
	Upstream string // e.g. "https://backend-service.internal:8080"
}

func (ReverseProxyHandler) handlerTag()      {}
func (ReverseProxyHandler) ModuleID() string { return "http.handlers.reverse_proxy" }

// GoogleAuthHandler fetches a Google OIDC ID Token for Audience and injects
// it as Authorization: Bearer before the upstream call.
type GoogleAuthHandler struct {
	Audience string
}

func (GoogleAuthHandler) handlerTag()      {}
func (GoogleAuthHandler) ModuleID() string { return "http.handlers.apigee_google_auth" }

// StaticResponseHandler returns a fixed response (used for error flows).
type StaticResponseHandler struct {
	StatusCode int
	Body       string
}

func (StaticResponseHandler) handlerTag()      {}
func (StaticResponseHandler) ModuleID() string { return "http.handlers.static_response" }

// RewriteHandler strips a URI prefix before forwarding to the upstream.
// Equivalent to Caddy's `rewrite` directive.
type RewriteHandler struct {
	StripPathPrefix string
}

func (RewriteHandler) handlerTag()      {}
func (RewriteHandler) ModuleID() string { return "http.handlers.rewrite" }

// ConditionalHandler wraps another handler and only invokes it when the
// Apigee condition expression evaluates to true at runtime.
type ConditionalHandler struct {
	Condition string  // raw Apigee condition expression
	Inner     Handler // the wrapped handler
}

func (ConditionalHandler) handlerTag()      {}
func (ConditionalHandler) ModuleID() string { return "http.handlers.apigee_conditional" }

// Transpile converts an Apigee bundle into a CaddyConfig using the given options.
func Transpile(bundle *apigee.Bundle, opts Options) (*CaddyConfig, error) {
	if opts.ListenAddress == "" {
		opts.ListenAddress = ":443"
	}

	cfg := &CaddyConfig{
		Servers: make(map[string]*Server),
	}

	// H4: Merge all ProxyEndpoints into a single server so they share the same
	// listen address. Routes from each endpoint are collected in order with their
	// respective base-path prefixes applied inside mapProxyEndpointRoutes.
	if len(bundle.ProxyEndpoints) > 0 {
		srv0 := &Server{Listen: []string{opts.ListenAddress}}
		for _, ep := range bundle.ProxyEndpoints {
			routes, err := mapProxyEndpointRoutes(ep, bundle, opts)
			if err != nil {
				return nil, fmt.Errorf("proxy endpoint %q: %w", ep.Name, err)
			}
			srv0.Routes = append(srv0.Routes, routes...)
		}
		cfg.Servers["srv0"] = srv0
	}

	return cfg, nil
}

// mapProxyEndpointRoutes translates one ProxyEndpoint into its ordered route list.
// Callers are responsible for placing routes into the appropriate Server.
func mapProxyEndpointRoutes(ep apigee.ProxyEndpoint, bundle *apigee.Bundle, opts Options) ([]*Route, error) {
	var routes []*Route

	// Resolve all upstream targets (with conditions) for this endpoint.
	targets := resolveTargetForEndpoint(ep, bundle)

	// PreFlow request steps — always executed, no condition matcher.
	preRoute := &Route{MatcherName: ""}
	preRoute.Handlers = append(preRoute.Handlers, FlowStateHandler{})
	for _, step := range ep.PreFlow.Request.Steps {
		h := mapStepToHandler(step, bundle)
		preRoute.Handlers = append(preRoute.Handlers, h)
	}
	// Only emit a PreFlow route when there are actual policy steps beyond the FlowStateHandler.
	if len(preRoute.Handlers) > 1 {
		routes = append(routes, preRoute)
	}

	// Derive matcher prefix from options or the endpoint base path.
	matcherPrefix := opts.MatcherPrefix
	if matcherPrefix == "" && ep.HTTPProxyConnection.BasePath != "" && ep.HTTPProxyConnection.BasePath != "/" {
		matcherPrefix = sanitizeName(strings.TrimPrefix(ep.HTTPProxyConnection.BasePath, "/"))
	}

	// Named flows.
	for _, flow := range ep.Flows {
		route, err := mapFlow(flow, bundle, targets, matcherPrefix)
		if err != nil {
			return nil, fmt.Errorf("flow %q: %w", flow.Name, err)
		}
		// Prefix the flow-level base path matcher from the proxy endpoint.
		if ep.HTTPProxyConnection.BasePath != "" && ep.HTTPProxyConnection.BasePath != "/" {
			if route.Matcher == nil {
				route.Matcher = &condition.CaddyMatcher{}
			}
			// Prepend base path to all path matchers.
			base := strings.TrimSuffix(ep.HTTPProxyConnection.BasePath, "/")
			for j, p := range route.Matcher.Paths {
				route.Matcher.Paths[j] = base + p
			}
			if len(route.Matcher.Paths) == 0 {
				route.Matcher.Paths = []string{base + "/*"}
			}
			// Strip the base path before forwarding to the upstream (Apigee
			// passes only the pathsuffix to the backend, not the full path).
			route.Handlers = prependRewrite(route.Handlers, base)
		}
		routes = append(routes, route)
	}

	// PostFlow — append to each route or as its own catch-all route.
	postSteps := ep.PostFlow.Request.Steps
	if len(postSteps) > 0 {
		postRoute := &Route{MatcherName: ""}
		postRoute.Handlers = append(postRoute.Handlers, FlowStateHandler{})
		if ep.HTTPProxyConnection.BasePath != "" && ep.HTTPProxyConnection.BasePath != "/" {
			base := strings.TrimSuffix(ep.HTTPProxyConnection.BasePath, "/")
			postRoute.Handlers = append(postRoute.Handlers, RewriteHandler{StripPathPrefix: base})
		}
		for _, step := range postSteps {
			postRoute.Handlers = append(postRoute.Handlers, mapStepToHandler(step, bundle))
		}
		appendTargetHandlers(postRoute, targets)
		routes = append(routes, postRoute)
	}

	// If there are no named flows and no post-flow, emit a single catch-all route.
	if len(targets) > 0 && len(routes) == 0 {
		r := &Route{Handlers: []Handler{FlowStateHandler{}}}
		if ep.HTTPProxyConnection.BasePath != "" && ep.HTTPProxyConnection.BasePath != "/" {
			base := strings.TrimSuffix(ep.HTTPProxyConnection.BasePath, "/")
			r.Handlers = append(r.Handlers, RewriteHandler{StripPathPrefix: base})
		}
		appendTargetHandlers(r, targets)
		routes = append(routes, r)
	}

	return routes, nil
}

// prependRewrite inserts a RewriteHandler that strips base from the URI path,
// positioned after the FlowStateHandler (which must stay first) if present.
func prependRewrite(handlers []Handler, base string) []Handler {
	rw := RewriteHandler{StripPathPrefix: base}
	if len(handlers) > 0 {
		if _, ok := handlers[0].(FlowStateHandler); ok {
			// Insert after FlowStateHandler.
			result := make([]Handler, 0, len(handlers)+1)
			result = append(result, handlers[0])
			result = append(result, rw)
			result = append(result, handlers[1:]...)
			return result
		}
	}
	return append([]Handler{rw}, handlers...)
}

// conditionalTarget holds one RouteRule's upstream URL, optional Google auth
// audience, and the raw Apigee condition that selects it.
// An empty Condition means "always" (unconditional default).
type conditionalTarget struct {
	Condition string
	URL       string
	Audience  string
}

// appendTargetHandlers appends target handlers for all conditional targets.
// Each conditional target is wrapped in an apigee_conditional handler so that
// the correct upstream is chosen at runtime based on environment.name etc.
// An unconditional target is emitted as a bare reverse_proxy (last resort).
func appendTargetHandlers(route *Route, targets []conditionalTarget) {
	for _, t := range targets {
		if t.URL == "" {
			continue
		}
		var inner Handler
		if t.Audience != "" {
			// Two handlers needed; wrap both in a ConditionalHandler group via
			// a synthetic inner chain. Since ConditionalHandler wraps a single
			// Handler, we use GoogleAuthHandler first then ReverseProxyHandler
			// as separate conditional entries sharing the same condition.
			if t.Condition != "" {
				route.Handlers = append(route.Handlers,
					ConditionalHandler{Condition: t.Condition, Inner: GoogleAuthHandler{Audience: t.Audience}},
					ConditionalHandler{Condition: t.Condition, Inner: ReverseProxyHandler{Upstream: t.URL}},
				)
			} else {
				route.Handlers = append(route.Handlers,
					GoogleAuthHandler{Audience: t.Audience},
					ReverseProxyHandler{Upstream: t.URL},
				)
			}
			continue
		}
		if t.Condition != "" {
			inner = ConditionalHandler{Condition: t.Condition, Inner: ReverseProxyHandler{Upstream: t.URL}}
		} else {
			inner = ReverseProxyHandler{Upstream: t.URL}
		}
		route.Handlers = append(route.Handlers, inner)
	}
}

func mapFlow(flow apigee.Flow, bundle *apigee.Bundle, targets []conditionalTarget, matcherPrefix string) (*Route, error) {
	name := sanitizeName(flow.Name)
	if matcherPrefix != "" {
		name = matcherPrefix + "_" + name
	}
	route := &Route{
		MatcherName:          name,
		UnsupportedCondition: flow.Condition,
	}

	// Parse and translate the condition.
	if flow.Condition != "" {
		node, err := condition.Parse(flow.Condition)
		if err != nil {
			// Non-fatal: record the raw condition and continue.
			route.Matcher = &condition.CaddyMatcher{
				Unsupported: []string{"parse error: " + err.Error() + " in: " + flow.Condition},
			}
		} else {
			route.Matcher = condition.ToCaddyMatcher(node)
		}
	}

	// Handler chain: state manager first.
	route.Handlers = append(route.Handlers, FlowStateHandler{})

	// Request steps.
	for _, step := range flow.Request.Steps {
		route.Handlers = append(route.Handlers, mapStepToHandler(step, bundle))
	}

	// Terminal: google auth (if needed) + reverse proxy, one per conditional target.
	appendTargetHandlers(route, targets)

	// Response steps run after the upstream responds.
	// apigee_assign_message with phase=response buffers the response internally.
	for _, step := range flow.Response.Steps {
		route.Handlers = append(route.Handlers, mapStepToHandlerPhase(step, bundle, "response"))
	}

	return route, nil
}

func mapStepToHandlerPhase(step apigee.Step, bundle *apigee.Bundle, phase string) Handler {
	h := mapPolicyToHandler(step.Name, bundle, phase)
	if step.Condition != "" {
		return ConditionalHandler{Condition: step.Condition, Inner: h}
	}
	return h
}

func mapStepToHandler(step apigee.Step, bundle *apigee.Bundle) Handler {
	h := mapPolicyToHandler(step.Name, bundle, "request")
	if step.Condition != "" {
		return ConditionalHandler{Condition: step.Condition, Inner: h}
	}
	return h
}

func mapPolicyToHandler(policyName string, bundle *apigee.Bundle, phase string) Handler {
	pol, ok := bundle.Policies[policyName]
	if !ok {
		// Unknown policy — emit a placeholder comment via a static handler.
		return PolicyHandler{
			Module:     "http.handlers.apigee_unknown",
			PolicyName: policyName,
			Config:     json.RawMessage(`{}`),
		}
	}

	switch pol.Type {
	case "AssignMessage":
		cfg := buildAssignMessageConfig(pol)
		if phase != "" {
			cfg.Phase = phase
		}
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_assign_message",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "ServiceCallout":
		cfg := buildServiceCalloutConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_service_callout",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "Javascript":
		jsc := pol.JavaScriptCallout
		// Resolve ResourceURL to inline source if needed.
		if jsc.Source == "" && jsc.ResourceURL != "" {
			src, err := resolveResourceURL(jsc.ResourceURL, bundle.Dir)
			if err != nil {
				return PolicyHandler{
					Module:     "http.handlers.apigee_unknown",
					PolicyName: pol.Name,
					Config:     json.RawMessage(fmt.Sprintf(`{"type":"Javascript","reason":%q}`, err.Error())),
				}
			}
			jsc = &apigee.JavaScriptCallout{
				Source:    src,
				TimeLimit: jsc.TimeLimit,
			}
			pol.JavaScriptCallout = jsc
		}
		if jsc.Source == "" {
			return PolicyHandler{
				Module:     "http.handlers.apigee_unknown",
				PolicyName: pol.Name,
				Config:     json.RawMessage(`{"type":"Javascript","reason":"no Source or ResourceURL found"}`),
			}
		}
		cfg := buildJavaScriptCalloutConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_javascript_callout",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "RaiseFault":
		cfg := buildRaiseFaultConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_raise_fault",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "VerifyJWT":
		cfg := buildVerifyJWTConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_verify_jwt",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "SpikeArrest":
		cfg := buildSpikeArrestConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_spike_arrest",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "CORS":
		cfg := buildCORSConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_cors",
			PolicyName: pol.Name,
			Config:     raw,
		}
	case "VerifyAPIKey":
		cfg := buildVerifyAPIKeyConfig(pol)
		raw, _ := json.Marshal(cfg)
		return PolicyHandler{
			Module:     "http.handlers.apigee_verify_api_key",
			PolicyName: pol.Name,
			Config:     raw,
		}
	default:
		return PolicyHandler{
			Module:     "http.handlers.apigee_unknown",
			PolicyName: pol.Name,
			Config:     json.RawMessage(fmt.Sprintf(`{"type":%q}`, pol.Type)),
		}
	}
}

// assignMessageConfig is the JSON shape consumed by apigee_assign_message.
type assignMessageConfig struct {
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	RemoveHeaders []string          `json:"remove_headers,omitempty"`
	AddHeaders    map[string]string `json:"add_headers,omitempty"`
	SetBody       string            `json:"set_body,omitempty"`
	Phase         string            `json:"phase,omitempty"`
}

func buildAssignMessageConfig(pol apigee.Policy) assignMessageConfig {
	am := pol.AssignMessage
	cfg := assignMessageConfig{Phase: "request"}
	if am.AssignTo.Type == "response" {
		cfg.Phase = "response"
	}
	if len(am.Set.Headers) > 0 {
		cfg.SetHeaders = make(map[string]string)
		for _, h := range am.Set.Headers {
			cfg.SetHeaders[h.Name] = h.Value
		}
	}
	if len(am.Remove.Headers) > 0 {
		for _, h := range am.Remove.Headers {
			cfg.RemoveHeaders = append(cfg.RemoveHeaders, h.Name)
		}
	}
	if len(am.Add.Headers) > 0 {
		cfg.AddHeaders = make(map[string]string)
		for _, h := range am.Add.Headers {
			cfg.AddHeaders[h.Name] = h.Value
		}
	}
	if am.Set.Body != "" {
		cfg.SetBody = am.Set.Body
	}
	return cfg
}

// serviceCalloutConfig is the JSON shape consumed by apigee_service_callout.
type serviceCalloutConfig struct {
	TargetURL      string `json:"target_url"`
	Method         string `json:"method,omitempty"`
	ResponseVar    string `json:"response_var,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

func buildServiceCalloutConfig(pol apigee.Policy) serviceCalloutConfig {
	sc := pol.ServiceCallout
	cfg := serviceCalloutConfig{
		TargetURL:      sc.HTTPTargetConnection.URL,
		ResponseVar:    sc.Response,
		TimeoutSeconds: 10,
	}
	return cfg
}

// jsCalloutConfig is the JSON shape consumed by apigee_javascript_callout.
type jsCalloutConfig struct {
	Source    string `json:"source"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

func buildJavaScriptCalloutConfig(pol apigee.Policy) jsCalloutConfig {
	jsc := pol.JavaScriptCallout
	cfg := jsCalloutConfig{
		Source:    jsc.Source,
		TimeoutMs: jsc.TimeLimit,
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 200
	}
	return cfg
}

// raiseFaultConfig is the JSON shape consumed by apigee_raise_fault.
type raiseFaultConfig struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body,omitempty"`
}

func buildRaiseFaultConfig(pol apigee.Policy) raiseFaultConfig {
	rf := pol.RaiseFault
	code := rf.FaultResponse.Set.StatusCode
	if code == 0 {
		code = 500
	}
	return raiseFaultConfig{
		StatusCode: code,
		Body:       rf.FaultResponse.Set.Payload,
	}
}

// verifyJWTConfig is the JSON shape consumed by apigee_verify_jwt.
type verifyJWTConfig struct {
	Algorithm  string `json:"algorithm"`
	PublicKey  string `json:"public_key,omitempty"`
	JWKSURI    string `json:"jwks_uri,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Audience   string `json:"audience,omitempty"`
	PolicyName string `json:"policy_name"`
}

func buildVerifyJWTConfig(pol apigee.Policy) verifyJWTConfig {
	vj := pol.VerifyJWT
	return verifyJWTConfig{
		Algorithm:  vj.Algorithm,
		PublicKey:  strings.TrimSpace(vj.PublicKey.Value),
		JWKSURI:    vj.PublicKey.JWKS.URI,
		Issuer:     vj.Issuer,
		Audience:   vj.Audience,
		PolicyName: pol.Name,
	}
}

// spikeArrestConfig is the JSON shape consumed by apigee_spike_arrest.
type spikeArrestConfig struct {
	Rate string `json:"rate"`
}

func buildSpikeArrestConfig(pol apigee.Policy) spikeArrestConfig {
	sa := pol.SpikeArrest
	return spikeArrestConfig{
		Rate: strings.TrimSpace(sa.Rate),
	}
}

// corsConfig is the JSON shape consumed by apigee_cors.
type corsConfig struct {
	AllowOrigins     []string `json:"allow_origins,omitempty"`
	AllowMethods     []string `json:"allow_methods,omitempty"`
	AllowHeaders     []string `json:"allow_headers,omitempty"`
	ExposeHeaders    []string `json:"expose_headers,omitempty"`
	MaxAge           int      `json:"max_age,omitempty"`
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
}

func buildCORSConfig(pol apigee.Policy) corsConfig {
	c := pol.CORS
	return corsConfig{
		AllowOrigins:     splitAndTrim(c.AllowOrigins),
		AllowMethods:     splitAndTrim(c.AllowMethods),
		AllowHeaders:     splitAndTrim(c.AllowHeaders),
		ExposeHeaders:    splitAndTrim(c.ExposeHeaders),
		MaxAge:           c.MaxAge,
		AllowCredentials: strings.EqualFold(strings.TrimSpace(c.AllowCredentials), "true"),
	}
}

// splitAndTrim splits a comma-or-whitespace-separated string into trimmed tokens.
func splitAndTrim(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Replace commas with spaces, then split on whitespace.
	s = strings.ReplaceAll(s, ",", " ")
	parts := strings.Fields(s)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// verifyAPIKeyConfig is the JSON shape consumed by apigee_verify_api_key.
type verifyAPIKeyConfig struct {
	APIKeyRef string `json:"api_key_ref"`
}

func buildVerifyAPIKeyConfig(pol apigee.Policy) verifyAPIKeyConfig {
	vak := pol.VerifyAPIKey
	return verifyAPIKeyConfig{
		APIKeyRef: vak.APIKey.Ref,
	}
}

// resolveResourceURL reads a jsc:// resource file from the bundle's resources/jsc/ directory.
// resourceURL has the form "jsc://filename.js".
func resolveResourceURL(resourceURL, bundleDir string) (string, error) {
	const prefix = "jsc://"
	if !strings.HasPrefix(resourceURL, prefix) {
		return "", fmt.Errorf("unsupported resource URL scheme: %q", resourceURL)
	}
	filename := strings.TrimPrefix(resourceURL, prefix)
	path := filepath.Join(bundleDir, "resources", "jsc", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading resource %q: %w", filename, err)
	}
	return string(data), nil
}

// resolveTargetForEndpoint returns all RouteRule targets as conditionalTargets.
// Each entry carries the raw Apigee condition and the upstream URL/audience.
// RouteRules with no TargetEndpoint (e.g. NoRoute for CORS) are skipped.
// If there are no RouteRules, the first available TargetEndpoint is returned
// as an unconditional target.
func resolveTargetForEndpoint(ep apigee.ProxyEndpoint, bundle *apigee.Bundle) []conditionalTarget {
	// Build name → TargetEndpoint lookup.
	byName := make(map[string]apigee.TargetEndpoint, len(bundle.TargetEndpoints))
	for _, te := range bundle.TargetEndpoints {
		byName[te.Name] = te
	}

	pickTarget := func(cond string, te apigee.TargetEndpoint) conditionalTarget {
		t := conditionalTarget{Condition: cond, URL: te.HTTPTargetConnection.URL}
		if te.HTTPTargetConnection.Authentication != nil &&
			te.HTTPTargetConnection.Authentication.GoogleIDToken != nil {
			t.Audience = te.HTTPTargetConnection.Authentication.GoogleIDToken.Audience
		}
		return t
	}

	if len(ep.RouteRules) == 0 {
		for _, te := range bundle.TargetEndpoints {
			if te.HTTPTargetConnection.URL != "" {
				return []conditionalTarget{pickTarget("", te)}
			}
		}
		return nil
	}

	var targets []conditionalTarget
	for _, rr := range ep.RouteRules {
		if rr.TargetEndpoint == "" {
			// NoRoute rule (e.g. CORS preflight) — skip, no upstream.
			continue
		}
		te, ok := byName[rr.TargetEndpoint]
		if !ok || te.HTTPTargetConnection.URL == "" {
			continue
		}
		targets = append(targets, pickTarget(rr.Condition, te))
	}
	return targets
}

// sanitizeName converts a flow name like "GetUsers" to "get_users" for use as
// a Caddy named matcher identifier.
func sanitizeName(name string) string {
	var b strings.Builder
	for i, r := range name {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32) // to lower
		} else if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
