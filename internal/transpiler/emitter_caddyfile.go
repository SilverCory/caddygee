package transpiler

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const cloudRunGlobalBlock = `{
	admin localhost:2019
	auto_https off
	servers {
		trusted_proxies static 130.211.0.0/22 35.191.0.0/16
	}
	log {
		output stdout
		format json
		level INFO
	}
}
`

const cloudRunServerDirectives = `
	log {
		output stdout
		format json
	}
	handle /health {
		respond 200
	}
`

// EmitCaddyfile serialises a CaddyConfig to a human-readable Caddyfile.
// opts controls whether to emit a fragment (no server block) or a full Caddyfile
// with optional Cloud Run global options.
func EmitCaddyfile(cfg *CaddyConfig, opts Options) (string, error) {
	var b strings.Builder

	if opts.Fragment {
		// Fragment mode: emit only the inner route content for one server,
		// no global block, no server block wrapper.
		srvKeys := make([]string, 0, len(cfg.Servers))
		for k := range cfg.Servers {
			srvKeys = append(srvKeys, k)
		}
		sort.Strings(srvKeys)
		for _, srvKey := range srvKeys {
			emitRoutes(&b, cfg.Servers[srvKey].Routes, "\t")
		}
		return b.String(), nil
	}

	if opts.CloudRun {
		b.WriteString(cloudRunGlobalBlock)
	}

	// M4: Sort server keys for deterministic output.
	srvKeys := make([]string, 0, len(cfg.Servers))
	for k := range cfg.Servers {
		srvKeys = append(srvKeys, k)
	}
	sort.Strings(srvKeys)

	for _, srvKey := range srvKeys {
		srv := cfg.Servers[srvKey]
		addr := ":443"
		if len(srv.Listen) > 0 {
			addr = srv.Listen[0]
		}
		fmt.Fprintf(&b, "\n%s {\n", addr)

		if opts.CloudRun {
			b.WriteString(cloudRunServerDirectives)
		}

		emitRoutes(&b, srv.Routes, "\t")

		fmt.Fprintf(&b, "}\n")
	}

	return b.String(), nil
}

// emitRoutes writes named matchers and handle blocks at the given indent level.
func emitRoutes(b *strings.Builder, routes []*Route, indent string) {
	// Collect named matchers first (must appear before handle blocks).
	for _, route := range routes {
		if route.MatcherName == "" || route.Matcher == nil {
			continue
		}
		if !hasConstraints(route.Matcher) {
			continue
		}
		fmt.Fprintf(b, "%s@%s {\n", indent, route.MatcherName)
		if len(route.Matcher.Methods) > 0 {
			if route.Matcher.NegateMethods {
				fmt.Fprintf(b, "%s\tnot method %s\n", indent, strings.Join(route.Matcher.Methods, " "))
			} else {
				fmt.Fprintf(b, "%s\tmethod %s\n", indent, strings.Join(route.Matcher.Methods, " "))
			}
		}
		for _, p := range route.Matcher.Paths {
			fmt.Fprintf(b, "%s\tpath %s\n", indent, p)
		}
		for _, p := range route.Matcher.ExcludePaths {
			fmt.Fprintf(b, "%s\tnot path %s\n", indent, p)
		}
		// M4: Sort header keys for deterministic output.
		headerKeys := make([]string, 0, len(route.Matcher.Headers))
		for k := range route.Matcher.Headers {
			headerKeys = append(headerKeys, k)
		}
		sort.Strings(headerKeys)
		for _, k := range headerKeys {
			// M3: Quote header values so spaces and special chars are safe.
			fmt.Fprintf(b, "%s\theader %s %q\n", indent, k, route.Matcher.Headers[k])
		}
		for _, h := range route.Matcher.HeadersPresent {
			// Caddy requires "header <Field> *" to match presence (any non-empty value).
			fmt.Fprintf(b, "%s\theader %s *\n", indent, h)
		}
		// M4: Sort header regexp keys for deterministic output.
		hrKeys := make([]string, 0, len(route.Matcher.HeaderRegexp))
		for k := range route.Matcher.HeaderRegexp {
			hrKeys = append(hrKeys, k)
		}
		sort.Strings(hrKeys)
		for _, k := range hrKeys {
			fmt.Fprintf(b, "%s\theader_regexp %s %q\n", indent, k, route.Matcher.HeaderRegexp[k])
		}
		// Negated header regexp.
		nhrKeys := make([]string, 0, len(route.Matcher.NegateHeaderRegexp))
		for k := range route.Matcher.NegateHeaderRegexp {
			nhrKeys = append(nhrKeys, k)
		}
		sort.Strings(nhrKeys)
		for _, k := range nhrKeys {
			fmt.Fprintf(b, "%s\tnot header_regexp %s %q\n", indent, k, route.Matcher.NegateHeaderRegexp[k])
		}
		fmt.Fprintf(b, "%s}\n", indent)

		// Emit warnings for untranslatable conditions as comments.
		for _, warn := range route.Matcher.Unsupported {
			fmt.Fprintf(b, "%s# WARNING: %s\n", indent, warn)
		}
		if route.UnsupportedCondition != "" && len(route.Matcher.Unsupported) > 0 {
			// Flatten to a single line so multi-line conditions don't break Caddyfile parsing.
			flat := strings.Join(strings.Fields(route.UnsupportedCondition), " ")
			fmt.Fprintf(b, "%s# Original condition: %s\n", indent, flat)
		}
	}

	// Emit route blocks (preserves handler order without Caddy's directive ordering).
	for _, route := range routes {
		if route.MatcherName != "" && route.Matcher != nil && hasConstraints(route.Matcher) {
			fmt.Fprintf(b, "\n%sroute @%s {\n", indent, route.MatcherName)
		} else {
			fmt.Fprintf(b, "\n%sroute {\n", indent)
		}

		for _, h := range route.Handlers {
			emitHandler(b, h, indent+"\t")
		}

		fmt.Fprintf(b, "%s}\n", indent)
	}
}

func emitHandler(b *strings.Builder, h Handler, indent string) {
	switch v := h.(type) {
	case FlowStateHandler:
		fmt.Fprintf(b, "%sapigee_state\n", indent)

	case PolicyHandler:
		shortName := moduleShortName(v.Module)
		if shortName == "apigee_unknown" {
			fmt.Fprintf(b, "%s# WARNING: unsupported policy %q — no Caddy module available\n", indent, v.PolicyName)
			return
		}
		// apigee_verify_jwt carries algorithm, jwks_uri/public_key, issuer, audience,
		// and policy_name from the policy config — emit as a subdirective block.
		if shortName == "apigee_verify_jwt" && len(v.Config) > 0 {
			var cfg struct {
				Algorithm  string `json:"algorithm"`
				PublicKey  string `json:"public_key,omitempty"`
				JWKSURI    string `json:"jwks_uri,omitempty"`
				Issuer     string `json:"issuer,omitempty"`
				Audience   string `json:"audience,omitempty"`
				PolicyName string `json:"policy_name"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.PolicyName != "" {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if cfg.Algorithm != "" {
					fmt.Fprintf(b, "%s\talgorithm %s\n", indent, cfg.Algorithm)
				}
				if cfg.JWKSURI != "" {
					fmt.Fprintf(b, "%s\tjwks_uri %s\n", indent, cfg.JWKSURI)
				}
				if cfg.PublicKey != "" {
					fmt.Fprintf(b, "%s\tpublic_key %s\n", indent, jsonStringLiteral(cfg.PublicKey))
				}
				if cfg.Issuer != "" {
					fmt.Fprintf(b, "%s\tissuer %s\n", indent, cfg.Issuer)
				}
				if cfg.Audience != "" {
					fmt.Fprintf(b, "%s\taudience %s\n", indent, cfg.Audience)
				}
				fmt.Fprintf(b, "%s\tpolicy_name %s\n", indent, cfg.PolicyName)
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_raise_fault carries status_code and body from the policy config.
		if shortName == "apigee_raise_fault" && len(v.Config) > 0 {
			var cfg struct {
				StatusCode int    `json:"status_code"`
				Body       string `json:"body,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.StatusCode != 0 {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				fmt.Fprintf(b, "%s\tstatus_code %d\n", indent, cfg.StatusCode)
				if cfg.Body != "" {
					fmt.Fprintf(b, "%s\tbody %s\n", indent, jsonStringLiteral(cfg.Body))
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_javascript_callout requires the source to be present in the
		// Caddyfile block — emit it as an inline block with a source subdirective.
		if shortName == "apigee_javascript_callout" && len(v.Config) > 0 {
			var cfg struct {
				Source    string `json:"source"`
				TimeoutMs int    `json:"timeout_ms,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Source != "" {
				fmt.Fprintf(b, "%s%s %s {\n", indent, shortName, v.PolicyName)
				fmt.Fprintf(b, "%s\tsource %s\n", indent, jsonStringLiteral(cfg.Source))
				if cfg.TimeoutMs > 0 {
					fmt.Fprintf(b, "%s\ttimeout_ms %d\n", indent, cfg.TimeoutMs)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_spike_arrest carries rate config.
		if shortName == "apigee_spike_arrest" && len(v.Config) > 0 {
			var cfg struct {
				Rate string `json:"rate"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Rate != "" {
				fmt.Fprintf(b, "%s%s %s\n", indent, shortName, cfg.Rate)
				return
			}
		}
		// apigee_cors carries allow_origins, allow_methods, etc.
		if shortName == "apigee_cors" && len(v.Config) > 0 {
			var cfg struct {
				AllowOrigins     []string `json:"allow_origins,omitempty"`
				AllowMethods     []string `json:"allow_methods,omitempty"`
				AllowHeaders     []string `json:"allow_headers,omitempty"`
				ExposeHeaders    []string `json:"expose_headers,omitempty"`
				MaxAge           int      `json:"max_age,omitempty"`
				AllowCredentials bool     `json:"allow_credentials,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if len(cfg.AllowOrigins) > 0 {
					fmt.Fprintf(b, "%s\tallow_origins %s\n", indent, strings.Join(cfg.AllowOrigins, " "))
				}
				if len(cfg.AllowMethods) > 0 {
					fmt.Fprintf(b, "%s\tallow_methods %s\n", indent, strings.Join(cfg.AllowMethods, " "))
				}
				if len(cfg.AllowHeaders) > 0 {
					fmt.Fprintf(b, "%s\tallow_headers %s\n", indent, strings.Join(cfg.AllowHeaders, " "))
				}
				if len(cfg.ExposeHeaders) > 0 {
					fmt.Fprintf(b, "%s\texpose_headers %s\n", indent, strings.Join(cfg.ExposeHeaders, " "))
				}
				if cfg.MaxAge > 0 {
					fmt.Fprintf(b, "%s\tmax_age %d\n", indent, cfg.MaxAge)
				}
				if cfg.AllowCredentials {
					fmt.Fprintf(b, "%s\tallow_credentials true\n", indent)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_extract_variables — emit prefix + header_pattern / path_pattern subdirectives.
		if shortName == "apigee_extract_variables" && len(v.Config) > 0 {
			var cfg struct {
				Prefix         string            `json:"prefix,omitempty"`
				HeaderPatterns map[string]string `json:"header_patterns,omitempty"`
				PathPatterns   []string          `json:"path_patterns,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if cfg.Prefix != "" {
					fmt.Fprintf(b, "%s\tprefix %s\n", indent, cfg.Prefix)
				}
				// Sort header keys for deterministic output.
				hkeys := make([]string, 0, len(cfg.HeaderPatterns))
				for k := range cfg.HeaderPatterns {
					hkeys = append(hkeys, k)
				}
				sort.Strings(hkeys)
				for _, k := range hkeys {
					fmt.Fprintf(b, "%s\theader_pattern %s %s\n", indent, k, jsonStringLiteral(cfg.HeaderPatterns[k]))
				}
				for _, p := range cfg.PathPatterns {
					fmt.Fprintf(b, "%s\tpath_pattern %s\n", indent, jsonStringLiteral(p))
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_quota — emit allow, interval, identifier_ref subdirectives.
		if shortName == "apigee_quota" && len(v.Config) > 0 {
			var cfg struct {
				Allow         int    `json:"allow"`
				Interval      int    `json:"interval"`
				IdentifierRef string `json:"identifier_ref,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Allow > 0 {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				fmt.Fprintf(b, "%s\tallow %d\n", indent, cfg.Allow)
				fmt.Fprintf(b, "%s\tinterval %d\n", indent, cfg.Interval)
				if cfg.IdentifierRef != "" {
					fmt.Fprintf(b, "%s\tidentifier_ref %s\n", indent, cfg.IdentifierRef)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_kvm — emit entry subdirectives.
		if shortName == "apigee_kvm" && len(v.Config) > 0 {
			var cfg struct {
				Entries map[string]string `json:"entries,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && len(cfg.Entries) > 0 {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				ekeys := make([]string, 0, len(cfg.Entries))
				for k := range cfg.Entries {
					ekeys = append(ekeys, k)
				}
				sort.Strings(ekeys)
				for _, k := range ekeys {
					fmt.Fprintf(b, "%s\tentry %s %s\n", indent, k, jsonStringLiteral(cfg.Entries[k]))
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_verify_api_key (passthrough) — emit a TODO comment.
		if shortName == "apigee_verify_api_key" && len(v.Config) > 0 {
			var cfg struct {
				APIKeyRef string `json:"api_key_ref"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil {
				fmt.Fprintf(b, "%s# TODO: apigee_verify_api_key not enforced — passthrough mode\n", indent)
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if cfg.APIKeyRef != "" {
					fmt.Fprintf(b, "%s\tapi_key_ref %s\n", indent, cfg.APIKeyRef)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		fmt.Fprintf(b, "%s%s %s\n", indent, shortName, v.PolicyName)

	case GoogleAuthHandler:
		fmt.Fprintf(b, "%sapigee_google_auth %s\n", indent, v.Audience)

	case RewriteHandler:
		if v.StripPathPrefix != "" {
			fmt.Fprintf(b, "%suri strip_prefix %s\n", indent, v.StripPathPrefix)
		}

	case ReverseProxyHandler:
		fmt.Fprintf(b, "%sreverse_proxy %s\n", indent, v.Upstream)

	case StaticResponseHandler:
		fmt.Fprintf(b, "%srespond %d %q\n", indent, v.StatusCode, v.Body)

	case ConditionalHandler:
		// Skip the conditional wrapper entirely when the inner handler has no
		// Caddyfile representation (e.g. unsupported policy → comment only).
		// An empty apigee_conditional block is a parse error.
		if isUnsupportedPolicy(v.Inner) {
			ph := v.Inner.(PolicyHandler)
			fmt.Fprintf(b, "%s# WARNING: unsupported policy %q skipped (no Caddy module available)\n", indent, ph.PolicyName)
			return
		}
		// For PolicyHandlers with embedded JSON config, use the raw_json
		// passthrough so parseConditionalCaddyfile can reconstruct the full
		// module config without re-parsing each handler's Caddyfile syntax.
		// Use backtick quoting so JSON escape sequences survive the Caddyfile
		// tokenizer unmodified (backtick strings are stored verbatim).
		if ph, ok := v.Inner.(PolicyHandler); ok && len(ph.Config) > 0 {
			innerJSON := buildInnerJSON(ph)
			if innerJSON != "" && !strings.ContainsRune(innerJSON, '`') {
				fmt.Fprintf(b, "%sapigee_conditional %q {\n", indent, v.Condition)
				fmt.Fprintf(b, "%s\traw_json `%s`\n", indent, innerJSON)
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		fmt.Fprintf(b, "%sapigee_conditional %q {\n", indent, v.Condition)
		emitHandler(b, v.Inner, indent+"\t")
		fmt.Fprintf(b, "%s}\n", indent)
	}
}

// isUnsupportedPolicy reports whether h is a PolicyHandler with no Caddy module.
func isUnsupportedPolicy(h Handler) bool {
	ph, ok := h.(PolicyHandler)
	return ok && moduleShortName(ph.Module) == "apigee_unknown"
}

// buildInnerJSON produces the full JSON object for a PolicyHandler so it can be
// embedded as a raw_json value inside apigee_conditional Caddyfile blocks.
// Returns "" if the handler has no config to embed.
func buildInnerJSON(ph PolicyHandler) string {
	if len(ph.Config) == 0 {
		return ""
	}
	// The Config is already a JSON object. Inject the "handler" key.
	// Result: {"handler":"<short>", ...rest of config...}
	short := moduleShortName(ph.Module)
	if short == "apigee_unknown" {
		return ""
	}
	// Config may be a JSON object; we need to merge in the handler key.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(ph.Config, &m); err != nil {
		return ""
	}
	handlerBytes, _ := json.Marshal(short)
	m["handler"] = json.RawMessage(handlerBytes)
	merged, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(merged)
}

// jsonStringLiteral marshals s as a JSON string literal for embedding in Caddyfile directives.
func jsonStringLiteral(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
