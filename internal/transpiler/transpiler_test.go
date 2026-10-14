package transpiler_test

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"caddygee/internal/apigee"
	"caddygee/internal/condition"
	"caddygee/internal/transpiler"
)

func testdataPath(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "testdata")
	return filepath.Join(append([]string{root}, parts...)...)
}

func loadSimpleBundle(t *testing.T) *apigee.Bundle {
	t.Helper()
	bundle, err := apigee.ParseBundle(testdataPath("simple"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	return bundle
}

func TestTranspile_Simple(t *testing.T) {
	bundle := loadSimpleBundle(t)
	cfg, err := transpiler.Transpile(bundle, transpiler.Options{ListenAddress: ":2015"})
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if len(cfg.Servers) == 0 {
		t.Fatal("expected at least one server")
	}
	srv := cfg.Servers["srv0"]
	if srv == nil {
		t.Fatal("expected srv0")
	}
	if len(srv.Listen) == 0 || srv.Listen[0] != ":2015" {
		t.Errorf("listen: %v", srv.Listen)
	}
	// 2 named flows → 2 routes.
	if len(srv.Routes) < 2 {
		t.Errorf("expected at least 2 routes, got %d", len(srv.Routes))
	}
}

func TestEmitJSON_Simple(t *testing.T) {
	bundle := loadSimpleBundle(t)
	out, err := transpiler.Emit(bundle, transpiler.Options{Format: "json", ListenAddress: ":2015"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("output is not valid JSON:\n%s", out)
	}
	// Must contain the Caddy admin API envelope keys.
	if !strings.Contains(out, `"apps"`) {
		t.Error("JSON missing 'apps' key")
	}
	if !strings.Contains(out, `"http"`) {
		t.Error("JSON missing 'http' key")
	}
	if !strings.Contains(out, `"servers"`) {
		t.Error("JSON missing 'servers' key")
	}
	// Must contain the upstream.
	if !strings.Contains(out, "backend-service.internal") {
		t.Error("JSON missing upstream address")
	}
}

func TestEmitCaddyfile_Simple(t *testing.T) {
	bundle := loadSimpleBundle(t)
	out, err := transpiler.Emit(bundle, transpiler.Options{Format: "caddyfile", ListenAddress: ":2015"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.Contains(out, ":2015") {
		t.Error("Caddyfile missing listen address")
	}
	if !strings.Contains(out, "reverse_proxy") {
		t.Error("Caddyfile missing reverse_proxy")
	}
	// Matcher name is prefixed with the base path slug (api_v1 for /api/v1).
	if !strings.Contains(out, "get_users") {
		t.Errorf("Caddyfile missing get_users named matcher; got:\n%s", out)
	}
	if !strings.Contains(out, "method GET") {
		t.Errorf("Caddyfile missing method matcher; got:\n%s", out)
	}
}

func TestEmitCaddyfile_ContainsFlowStateHandler(t *testing.T) {
	bundle := loadSimpleBundle(t)
	out, err := transpiler.Emit(bundle, transpiler.Options{Format: "caddyfile", ListenAddress: ":2015"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.Contains(out, "flow_state") {
		t.Errorf("Caddyfile missing flow_state handler; got:\n%s", out)
	}
}

func TestTranspile_PreFlowSteps(t *testing.T) {
	bundle := &apigee.Bundle{
		Policies: map[string]apigee.Policy{
			"SetCorrelationID": {
				Name: "SetCorrelationID",
				Type: "AssignMessage",
				AssignMessage: &apigee.AssignMessage{
					Set: apigee.MessageMutation{
						Headers: []apigee.Header{{Name: "X-Correlation-ID", Value: "test-id"}},
					},
				},
			},
		},
		ProxyEndpoints: []apigee.ProxyEndpoint{
			{
				Name: "default",
				HTTPProxyConnection: apigee.HTTPProxyConnection{BasePath: "/v1"},
				PreFlow: apigee.PreFlow{
					Request: apigee.StepList{
						Steps: []apigee.Step{{Name: "SetCorrelationID"}},
					},
				},
			},
		},
		TargetEndpoints: []apigee.TargetEndpoint{
			{
				Name: "default",
				HTTPTargetConnection: apigee.HTTPTargetConnection{URL: "https://backend.internal"},
			},
		},
	}

	cfg, err := transpiler.Transpile(bundle, transpiler.Options{ListenAddress: ":443"})
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}

	srv := cfg.Servers["srv0"]
	if srv == nil {
		t.Fatal("expected srv0")
	}

	// There must be at least one route containing the AssignMessage handler for the PreFlow step.
	found := false
	for _, route := range srv.Routes {
		for _, h := range route.Handlers {
			if ph, ok := h.(transpiler.PolicyHandler); ok {
				if ph.Module == "http.handlers.assign_message" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected PreFlow AssignMessage handler in routes, not found")
	}
}

func TestTranspile_DefaultListenAddress(t *testing.T) {
	bundle := &apigee.Bundle{
		Policies:       map[string]apigee.Policy{},
		ProxyEndpoints: []apigee.ProxyEndpoint{{Name: "default"}},
		TargetEndpoints: []apigee.TargetEndpoint{
			{Name: "default", HTTPTargetConnection: apigee.HTTPTargetConnection{URL: "https://backend.internal"}},
		},
	}

	cfg, err := transpiler.Transpile(bundle, transpiler.Options{})
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	srv := cfg.Servers["srv0"]
	if srv == nil {
		t.Fatal("expected srv0")
	}
	if len(srv.Listen) == 0 || srv.Listen[0] != ":443" {
		t.Errorf("listen: got %v, want [:443]", srv.Listen)
	}
}

func TestTranspile_ServiceCalloutPolicy(t *testing.T) {
	bundle := &apigee.Bundle{
		Policies: map[string]apigee.Policy{
			"CallAuth": {
				Name: "CallAuth",
				Type: "ServiceCallout",
				ServiceCallout: &apigee.ServiceCallout{
					Response: "authResponse",
					HTTPTargetConnection: apigee.HTTPTargetConnection{URL: "https://auth.internal/validate"},
				},
			},
		},
		ProxyEndpoints: []apigee.ProxyEndpoint{
			{
				Name: "default",
				Flows: []apigee.Flow{
					{
						Name:      "AuthFlow",
						Condition: `request.verb = "POST"`,
						Request: apigee.StepList{
							Steps: []apigee.Step{{Name: "CallAuth"}},
						},
					},
				},
			},
		},
		TargetEndpoints: []apigee.TargetEndpoint{
			{Name: "default", HTTPTargetConnection: apigee.HTTPTargetConnection{URL: "https://backend.internal"}},
		},
	}

	out, err := transpiler.Emit(bundle, transpiler.Options{Format: "json", ListenAddress: ":443"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.Contains(out, "service_callout") {
		t.Errorf("JSON output missing service_callout; got:\n%s", out)
	}
}

func TestEmitCaddyfile_Deterministic(t *testing.T) {
	bundle := loadSimpleBundle(t)
	opts := transpiler.Options{Format: "caddyfile", ListenAddress: ":2015"}

	first, err := transpiler.Emit(bundle, opts)
	if err != nil {
		t.Fatalf("Emit first: %v", err)
	}
	for i := 1; i < 20; i++ {
		got, err := transpiler.Emit(bundle, opts)
		if err != nil {
			t.Fatalf("Emit iteration %d: %v", i, err)
		}
		if got != first {
			t.Fatalf("non-deterministic output at iteration %d:\nfirst:\n%s\ngot:\n%s", i, first, got)
		}
	}
}

func TestEmitCaddyfile_HeaderValuesQuoted(t *testing.T) {
	cfg := &transpiler.CaddyConfig{
		Servers: map[string]*transpiler.Server{
			"srv0": {
				Listen: []string{":443"},
				Routes: []*transpiler.Route{
					{
						MatcherName: "with_space",
						Matcher: &condition.CaddyMatcher{
							Headers: map[string]string{
								"X-My-Header": "value with spaces",
							},
						},
						Handlers: []transpiler.Handler{transpiler.FlowStateHandler{}},
					},
				},
			},
		},
	}

	out, err := transpiler.EmitCaddyfile(cfg, transpiler.Options{})
	if err != nil {
		t.Fatalf("EmitCaddyfile: %v", err)
	}
	// The header value must be quoted in the output.
	if !strings.Contains(out, `"value with spaces"`) {
		t.Errorf("header value not quoted; got:\n%s", out)
	}
}
