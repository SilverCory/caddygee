package transpiler

import (
	"encoding/json"
	"fmt"
	"strings"

	"caddygee/internal/condition"
)

// caddyJSONServer is the Caddy JSON schema for a single HTTP server.
type caddyJSONServer struct {
	Listen []string        `json:"listen"`
	Routes []caddyJSONRoute `json:"routes,omitempty"`
}

// caddyJSONRoute is a single Caddy route in JSON format.
type caddyJSONRoute struct {
	Match   []json.RawMessage `json:"match,omitempty"`
	Handle  []json.RawMessage `json:"handle"`
	// Terminal prevents subsequent routes from matching when this one matches.
	Terminal bool `json:"terminal,omitempty"`
}

// EmitJSON serialises a CaddyConfig to the Caddy admin API JSON format.
func EmitJSON(cfg *CaddyConfig) ([]byte, error) {
	servers := make(map[string]*caddyJSONServer, len(cfg.Servers))
	for key, srv := range cfg.Servers {
		jsonSrv, err := serverToJSON(srv)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", key, err)
		}
		servers[key] = jsonSrv
	}

	envelope := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": servers,
			},
		},
	}
	return json.MarshalIndent(envelope, "", "  ")
}

func serverToJSON(srv *Server) (*caddyJSONServer, error) {
	out := &caddyJSONServer{Listen: srv.Listen}
	for _, route := range srv.Routes {
		jr, err := routeToJSON(route)
		if err != nil {
			return nil, err
		}
		out.Routes = append(out.Routes, jr)
	}
	return out, nil
}

func routeToJSON(route *Route) (caddyJSONRoute, error) {
	jr := caddyJSONRoute{Terminal: true}

	// Build matcher set.
	if route.Matcher != nil && hasConstraints(route.Matcher) {
		m := make(map[string]any)
		if len(route.Matcher.Methods) > 0 {
			if route.Matcher.NegateMethods {
				m["not"] = map[string]any{"method": route.Matcher.Methods}
			} else {
				m["method"] = route.Matcher.Methods
			}
		}
		if len(route.Matcher.Paths) > 0 {
			m["path"] = route.Matcher.Paths
		}
		if len(route.Matcher.ExcludePaths) > 0 {
			// Caddy JSON: "not" is an array of matcher sets.
			var notMatchers []map[string]any
			for _, p := range route.Matcher.ExcludePaths {
				notMatchers = append(notMatchers, map[string]any{
					"path": []string{p},
				})
			}
			m["not"] = notMatchers
		}
		if len(route.Matcher.Headers) > 0 {
			hm := make(map[string][]string)
			for k, v := range route.Matcher.Headers {
				hm[k] = []string{v}
			}
			m["header"] = hm
		}
		if len(route.Matcher.HeadersPresent) > 0 {
			// In Caddy JSON, an empty string value means "header must be present".
			hm, ok := m["header"].(map[string][]string)
			if !ok {
				hm = make(map[string][]string)
				m["header"] = hm
			}
			for _, h := range route.Matcher.HeadersPresent {
				hm[h] = []string{}
			}
		}
		if len(route.Matcher.HeaderRegexp) > 0 {
			hrm := make(map[string]any)
			for k, v := range route.Matcher.HeaderRegexp {
				hrm[k] = v
			}
			m["header_regexp"] = hrm
		}
		if len(route.Matcher.NegateHeaderRegexp) > 0 {
			// Add negated header regexp entries to the "not" array.
			notMatchers, _ := m["not"].([]map[string]any)
			for k, v := range route.Matcher.NegateHeaderRegexp {
				notMatchers = append(notMatchers, map[string]any{
					"header_regexp": map[string]any{k: v},
				})
			}
			m["not"] = notMatchers
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return jr, err
		}
		jr.Match = []json.RawMessage{raw}
	}

	// Build handler chain.
	for _, h := range route.Handlers {
		raw, err := handlerToJSON(h)
		if err != nil {
			return jr, fmt.Errorf("handler %q: %w", h.ModuleID(), err)
		}
		jr.Handle = append(jr.Handle, raw)
	}

	return jr, nil
}

func handlerToJSON(h Handler) (json.RawMessage, error) {
	switch v := h.(type) {
	case FlowStateHandler:
		return json.Marshal(map[string]string{"handler": "apigee_state"})

	case PolicyHandler:
		// Merge the module ID into the policy's own config object.
		var m map[string]any
		if err := json.Unmarshal(v.Config, &m); err != nil {
			m = map[string]any{}
		}
		// Extract just the module suffix (e.g. "apigee_assign_message").
		m["handler"] = moduleShortName(v.Module)
		return json.MarshalIndent(m, "", "  ")

	case GoogleAuthHandler:
		return json.Marshal(map[string]any{
			"handler":  "apigee_google_auth",
			"audience": v.Audience,
		})

	case RewriteHandler:
		if v.StripPathPrefix == "" {
			return nil, nil
		}
		return json.Marshal(map[string]any{
			"handler":            "rewrite",
			"strip_path_prefix": v.StripPathPrefix,
		})

	case ReverseProxyHandler:
		host := stripScheme(v.Upstream)
		isHTTPS := strings.HasPrefix(v.Upstream, "https://")
		if isHTTPS && !strings.Contains(host, ":") {
			host = host + ":443"
		}
		if isHTTPS {
			return json.Marshal(map[string]any{
				"handler": "reverse_proxy",
				"upstreams": []map[string]string{
					{"dial": host},
				},
				"transport": map[string]any{
					"protocol": "http",
					"tls":      map[string]any{},
				},
			})
		}
		return json.Marshal(map[string]any{
			"handler": "reverse_proxy",
			"upstreams": []map[string]string{
				{"dial": host},
			},
		})

	case StaticResponseHandler:
		return json.Marshal(map[string]any{
			"handler":     "static_response",
			"status_code": v.StatusCode,
			"body":        v.Body,
		})

	case ConditionalHandler:
		inner, err := handlerToJSON(v.Inner)
		if err != nil {
			return nil, fmt.Errorf("conditional inner handler: %w", err)
		}
		return json.Marshal(map[string]any{
			"handler":   "apigee_conditional",
			"condition": v.Condition,
			"inner":     json.RawMessage(inner),
		})

	default:
		return nil, fmt.Errorf("unknown handler type %T", h)
	}
}

func hasConstraints(m *condition.CaddyMatcher) bool {
	return len(m.Methods) > 0 || len(m.Paths) > 0 || len(m.ExcludePaths) > 0 ||
		len(m.Headers) > 0 || len(m.HeadersPresent) > 0 || len(m.HeaderRegexp) > 0 ||
		len(m.NegateHeaderRegexp) > 0
}

// moduleShortName extracts the last segment of a dot-delimited module ID.
// "http.handlers.reverse_proxy" → "reverse_proxy"
func moduleShortName(id string) string {
	parts := splitLast(id, '.')
	return parts
}

func splitLast(s string, sep byte) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep {
			return s[i+1:]
		}
	}
	return s
}

// stripScheme removes https:// or http:// prefix for use as a dial address.
func stripScheme(u string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(u) > len(prefix) && u[:len(prefix)] == prefix {
			return u[len(prefix):]
		}
	}
	return u
}
