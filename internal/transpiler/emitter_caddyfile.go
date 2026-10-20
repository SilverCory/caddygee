package transpiler

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var defaultTrustedProxies = []string{"130.211.0.0/22", "35.191.0.0/16"}

func cloudRunGlobalBlock(adminAddr string, trustedProxies []string) string {
	if adminAddr == "" {
		adminAddr = "localhost:2019"
	}
	if len(trustedProxies) == 0 {
		trustedProxies = defaultTrustedProxies
	}
	return fmt.Sprintf("{"+`
	admin %s
	auto_https off
	servers {
		trusted_proxies static %s
	}
	log {
		output stdout
		format json
		level INFO
	}
}
`, adminAddr, strings.Join(trustedProxies, " "))
}

const cloudRunServerDirectives = `
	log {
		output stdout
		format json
	}
	handle /health {
		respond 200
	}
	handle /deploy {
		reverse_proxy localhost:9090
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
		b.WriteString(cloudRunGlobalBlock(opts.AdminAddress, opts.TrustedProxies))
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
		fmt.Fprintf(b, "%sflow_state\n", indent)

	case PolicyHandler:
		shortName := moduleShortName(v.Module)
		if shortName == "unknown" {
			fmt.Fprintf(b, "%s# WARNING: unsupported policy %q — no Caddy module available\n", indent, v.PolicyName)
			return
		}
		// apigee_verify_jwt carries algorithm, jwks_uri/public_key, issuer, audience,
		// and policy_name from the policy config — emit as a subdirective block.
		if shortName == "verify_jwt" && len(v.Config) > 0 {
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
					// Backtick quoting preserves real newlines in the PEM block.
					fmt.Fprintf(b, "%s\tpublic_key `%s`\n", indent, cfg.PublicKey)
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
		if shortName == "raise_fault" && len(v.Config) > 0 {
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
		if shortName == "js_callout" && len(v.Config) > 0 {
			var cfg struct {
				Source    string `json:"source"`
				TimeoutMs int    `json:"timeout_ms,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Source != "" {
				fmt.Fprintf(b, "%s%s %s {\n", indent, shortName, v.PolicyName)
				fmt.Fprintf(b, "%s\tsource `%s`\n", indent, cfg.Source)
				if cfg.TimeoutMs > 0 {
					fmt.Fprintf(b, "%s\ttimeout_ms %d\n", indent, cfg.TimeoutMs)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_spike_arrest carries rate config.
		if shortName == "spike_arrest" && len(v.Config) > 0 {
			var cfg struct {
				Rate string `json:"rate"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.Rate != "" {
				fmt.Fprintf(b, "%s%s %s\n", indent, shortName, cfg.Rate)
				return
			}
		}
		// apigee_cors carries allow_origins, allow_methods, etc.
		if shortName == "cors" && len(v.Config) > 0 {
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
		if shortName == "extract_vars" && len(v.Config) > 0 {
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
		if shortName == "quota" && len(v.Config) > 0 {
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
		// kvm — emit map_name, cache_ttl_seconds, and entry subdirectives.
		if shortName == "kvm" && len(v.Config) > 0 {
			var cfg struct {
				MapName         string            `json:"map_name,omitempty"`
				CacheTTLSeconds int               `json:"cache_ttl_seconds,omitempty"`
				Entries         map[string]string `json:"entries,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && (cfg.MapName != "" || len(cfg.Entries) > 0) {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if cfg.MapName != "" {
					fmt.Fprintf(b, "%s\tmap_name %s\n", indent, cfg.MapName)
				}
				if cfg.CacheTTLSeconds > 0 {
					fmt.Fprintf(b, "%s\tcache_ttl_seconds %d\n", indent, cfg.CacheTTLSeconds)
				}
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
		// assign_message — emit set_header / add_header / remove_header / set_body / phase subdirectives.
		if shortName == "assign_message" && len(v.Config) > 0 {
			var cfg struct {
				SetHeaders    map[string]string `json:"set_headers,omitempty"`
				AddHeaders    map[string]string `json:"add_headers,omitempty"`
				RemoveHeaders []string          `json:"remove_headers,omitempty"`
				SetBody       string            `json:"set_body,omitempty"`
				Phase         string            `json:"phase,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil {
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				if cfg.Phase != "" && cfg.Phase != "request" {
					fmt.Fprintf(b, "%s\tphase %s\n", indent, cfg.Phase)
				}
				// Sort keys for deterministic output.
				shKeys := make([]string, 0, len(cfg.SetHeaders))
				for k := range cfg.SetHeaders {
					shKeys = append(shKeys, k)
				}
				sort.Strings(shKeys)
				for _, k := range shKeys {
					fmt.Fprintf(b, "%s\tset_header %s %s\n", indent, k, jsonStringLiteral(cfg.SetHeaders[k]))
				}
				ahKeys := make([]string, 0, len(cfg.AddHeaders))
				for k := range cfg.AddHeaders {
					ahKeys = append(ahKeys, k)
				}
				sort.Strings(ahKeys)
				for _, k := range ahKeys {
					fmt.Fprintf(b, "%s\tadd_header %s %s\n", indent, k, jsonStringLiteral(cfg.AddHeaders[k]))
				}
				for _, h := range cfg.RemoveHeaders {
					fmt.Fprintf(b, "%s\tremove_header %s\n", indent, h)
				}
				if cfg.SetBody != "" {
					fmt.Fprintf(b, "%s\tset_body %s\n", indent, jsonStringLiteral(cfg.SetBody))
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// service_callout — emit target_url, method, request_body_var, response_var, timeout_seconds subdirectives.
		if shortName == "service_callout" && len(v.Config) > 0 {
			var cfg struct {
				TargetURL          string `json:"target_url"`
				Method             string `json:"method,omitempty"`
				RequestBodyVar     string `json:"request_body_var,omitempty"`
				ResponseVar        string `json:"response_var,omitempty"`
				TimeoutSeconds     int    `json:"timeout_seconds,omitempty"`
				WarnRequestHeaders bool   `json:"warn_request_headers,omitempty"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil && cfg.TargetURL != "" {
				if cfg.WarnRequestHeaders {
					fmt.Fprintf(b, "%s# WARNING: %s adds outbound request headers — not supported by service_callout module\n", indent, v.PolicyName)
				}
				fmt.Fprintf(b, "%s%s {\n", indent, shortName)
				fmt.Fprintf(b, "%s\ttarget_url %s\n", indent, cfg.TargetURL)
				if cfg.Method != "" {
					fmt.Fprintf(b, "%s\tmethod %s\n", indent, cfg.Method)
				}
				if cfg.RequestBodyVar != "" {
					fmt.Fprintf(b, "%s\trequest_body_var %s\n", indent, cfg.RequestBodyVar)
				}
				if cfg.ResponseVar != "" {
					fmt.Fprintf(b, "%s\tresponse_var %s\n", indent, cfg.ResponseVar)
				}
				if cfg.TimeoutSeconds > 0 {
					fmt.Fprintf(b, "%s\ttimeout_seconds %d\n", indent, cfg.TimeoutSeconds)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				return
			}
		}
		// apigee_verify_api_key (passthrough) — emit a TODO comment.
		if shortName == "verify_api_key" && len(v.Config) > 0 {
			var cfg struct {
				APIKeyRef string `json:"api_key_ref"`
			}
			if err := json.Unmarshal(v.Config, &cfg); err == nil {
				fmt.Fprintf(b, "%s# TODO: verify_api_key not enforced — passthrough mode\n", indent)
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
		fmt.Fprintf(b, "%sgoogle_auth %s\n", indent, v.Audience)

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
		// Caddyfile representation (e.g. unsupported policy -> comment only).
		// An empty when block is a parse error.
		if isUnsupportedPolicy(v.Inner) {
			ph := v.Inner.(PolicyHandler)
			fmt.Fprintf(b, "%s# WARNING: unsupported policy %q skipped (no Caddy module available)\n", indent, ph.PolicyName)
			return
		}
		fmt.Fprintf(b, "%swhen %s {\n", indent, v.Condition)
		emitHandler(b, v.Inner, indent+"\t")
		fmt.Fprintf(b, "%s}\n", indent)
	}
}

// isUnsupportedPolicy reports whether h is a PolicyHandler with no Caddy module.
func isUnsupportedPolicy(h Handler) bool {
	ph, ok := h.(PolicyHandler)
	return ok && moduleShortName(ph.Module) == "unknown"
}

// jsonStringLiteral marshals s as a JSON string literal for embedding in Caddyfile directives.
func jsonStringLiteral(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
