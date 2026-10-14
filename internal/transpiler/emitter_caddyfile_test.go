package transpiler_test

import (
	"encoding/json"
	"strings"
	"testing"

	"caddygee/internal/transpiler"
)

// buildSingleHandlerCaddyfile is a test helper that builds a minimal CaddyConfig
// with one server ("srv0"), one route (match-all), and the given handler, then
// calls EmitCaddyfile and returns the output string.
func buildSingleHandlerCaddyfile(t *testing.T, h transpiler.Handler) string {
	t.Helper()
	cfg := &transpiler.CaddyConfig{
		Servers: map[string]*transpiler.Server{
			"srv0": {
				Listen: []string{":443"},
				Routes: []*transpiler.Route{
					{Handlers: []transpiler.Handler{h}},
				},
			},
		},
	}
	out, err := transpiler.EmitCaddyfile(cfg, transpiler.Options{})
	if err != nil {
		t.Fatalf("EmitCaddyfile: %v", err)
	}
	return out
}

// mustJSON marshals v to a json.RawMessage, failing the test on error.
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return json.RawMessage(b)
}

// ---------------------------------------------------------------------------
// assign_message
// ---------------------------------------------------------------------------

// TestEmitCaddyfile_AssignMessage_Full verifies that all five subdirectives
// (set_header, add_header, remove_header, set_body, phase) are emitted when
// phase is set to "response" (non-default).
func TestEmitCaddyfile_AssignMessage_Full(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "SetResponseHeaders",
		Config: mustJSON(t, map[string]any{
			"set_headers":    map[string]string{"X-Set": "set-value"},
			"add_headers":    map[string]string{"X-Add": "add-value"},
			"remove_headers": []string{"X-Remove"},
			"set_body":       "override body",
			"phase":          "response",
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	checks := []struct {
		label   string
		contain string
	}{
		{"block open", "assign_message {"},
		{"phase response", "phase response"},
		{"set_header", `set_header X-Set "set-value"`},
		{"add_header", `add_header X-Add "add-value"`},
		{"remove_header", "remove_header X-Remove"},
		{"set_body", `set_body "override body"`},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.contain) {
			t.Errorf("[%s] expected %q in output; got:\n%s", c.label, c.contain, out)
		}
	}
}

// TestEmitCaddyfile_AssignMessage_OnlyAddHeaders verifies that when phase is
// absent (defaults to request), the "phase" subdirective is suppressed.
func TestEmitCaddyfile_AssignMessage_OnlyAddHeaders(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "AddCustomHeader",
		Config: mustJSON(t, map[string]any{
			"add_headers": map[string]string{"X-Custom": "custom-value"},
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "assign_message {") {
		t.Errorf("expected assign_message block; got:\n%s", out)
	}
	if !strings.Contains(out, `add_header X-Custom "custom-value"`) {
		t.Errorf("expected add_header directive; got:\n%s", out)
	}
	// Phase "request" is the default and must NOT appear in the output.
	if strings.Contains(out, "phase") {
		t.Errorf("expected 'phase' to be suppressed for default request phase; got:\n%s", out)
	}
}

// TestEmitCaddyfile_AssignMessage_PhaseRequest checks that an explicit
// phase=request is also suppressed (same as the default).
func TestEmitCaddyfile_AssignMessage_PhaseRequest(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "ExplicitRequestPhase",
		Config: mustJSON(t, map[string]any{
			"set_headers": map[string]string{"X-Foo": "bar"},
			"phase":       "request",
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if strings.Contains(out, "phase") {
		t.Errorf("expected 'phase request' to be suppressed; got:\n%s", out)
	}
}

// TestEmitCaddyfile_AssignMessage_SetHeadersSorted verifies that multiple
// set_header entries are emitted in lexicographic key order (deterministic).
func TestEmitCaddyfile_AssignMessage_SetHeadersSorted(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "MultiSetHeaders",
		Config: mustJSON(t, map[string]any{
			"set_headers": map[string]string{
				"Z-Last":  "z",
				"A-First": "a",
				"M-Mid":   "m",
			},
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	posA := strings.Index(out, "A-First")
	posM := strings.Index(out, "M-Mid")
	posZ := strings.Index(out, "Z-Last")
	if posA < 0 || posM < 0 || posZ < 0 {
		t.Fatalf("missing expected set_header keys; got:\n%s", out)
	}
	if !(posA < posM && posM < posZ) {
		t.Errorf("set_header keys not in sorted order (A=%d M=%d Z=%d); got:\n%s", posA, posM, posZ, out)
	}
}

// TestEmitCaddyfile_AssignMessage_EmptyConfig verifies that an empty JSON object
// still emits a block (the marshal succeeds and the block is opened/closed).
func TestEmitCaddyfile_AssignMessage_EmptyConfig(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "EmptyAssign",
		Config:     json.RawMessage(`{}`),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	// An empty config still produces a valid (empty) block.
	if !strings.Contains(out, "assign_message {") {
		t.Errorf("expected assign_message block for empty config; got:\n%s", out)
	}
}

// TestEmitCaddyfile_AssignMessage_NilConfig verifies that a nil Config falls
// through to the bare "assign_message <PolicyName>" line.
func TestEmitCaddyfile_AssignMessage_NilConfig(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.assign_message",
		PolicyName: "NilConfigPolicy",
		Config:     nil,
	}

	out := buildSingleHandlerCaddyfile(t, h)

	// nil Config → len(v.Config) == 0, falls through to bare name line.
	if !strings.Contains(out, "assign_message NilConfigPolicy") {
		t.Errorf("expected bare 'assign_message NilConfigPolicy' fallthrough; got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// service_callout
// ---------------------------------------------------------------------------

// TestEmitCaddyfile_ServiceCallout_Basic verifies target_url and response_var
// are emitted; method and timeout use defaults (GET / 10s) and must be suppressed.
func TestEmitCaddyfile_ServiceCallout_Basic(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "CallAuthService",
		Config: mustJSON(t, map[string]any{
			"target_url":   "https://auth.internal/validate",
			"response_var": "authResponse",
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "service_callout {") {
		t.Errorf("expected service_callout block; got:\n%s", out)
	}
	if !strings.Contains(out, "target_url https://auth.internal/validate") {
		t.Errorf("expected target_url directive; got:\n%s", out)
	}
	if !strings.Contains(out, "response_var authResponse") {
		t.Errorf("expected response_var directive; got:\n%s", out)
	}
	// Default method (GET) must be suppressed.
	if strings.Contains(out, "method") {
		t.Errorf("expected 'method' to be suppressed for default GET; got:\n%s", out)
	}
	// Default timeout (10s) must be suppressed (not set here, so zero → also suppressed).
	if strings.Contains(out, "timeout_seconds") {
		t.Errorf("expected 'timeout_seconds' to be suppressed when not set; got:\n%s", out)
	}
}

// TestEmitCaddyfile_ServiceCallout_PostNonDefaultTimeout verifies that method=POST
// and a non-default timeout are both emitted.
func TestEmitCaddyfile_ServiceCallout_PostNonDefaultTimeout(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "CallWithPost",
		Config: mustJSON(t, map[string]any{
			"target_url":      "https://api.internal/enrich",
			"method":          "POST",
			"response_var":    "enrichResponse",
			"timeout_seconds": 30,
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "target_url https://api.internal/enrich") {
		t.Errorf("expected target_url directive; got:\n%s", out)
	}
	if !strings.Contains(out, "method POST") {
		t.Errorf("expected 'method POST' directive; got:\n%s", out)
	}
	if !strings.Contains(out, "response_var enrichResponse") {
		t.Errorf("expected response_var directive; got:\n%s", out)
	}
	if !strings.Contains(out, "timeout_seconds 30") {
		t.Errorf("expected 'timeout_seconds 30' directive; got:\n%s", out)
	}
}

// TestEmitCaddyfile_ServiceCallout_GetMethodEmitted verifies that an explicit
// method=GET is emitted (no default suppression — avoids fragility if defaults change).
func TestEmitCaddyfile_ServiceCallout_GetMethodEmitted(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "ExplicitGet",
		Config: mustJSON(t, map[string]any{
			"target_url": "https://lookup.internal/check",
			"method":     "GET",
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "method GET") {
		t.Errorf("expected 'method GET' to be emitted; got:\n%s", out)
	}
}

// TestEmitCaddyfile_ServiceCallout_DefaultTimeoutEmitted verifies that
// timeout_seconds=10 is emitted (no default suppression).
func TestEmitCaddyfile_ServiceCallout_DefaultTimeoutEmitted(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "DefaultTimeout",
		Config: mustJSON(t, map[string]any{
			"target_url":      "https://service.internal/ping",
			"timeout_seconds": 10,
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "timeout_seconds 10") {
		t.Errorf("expected 'timeout_seconds 10' to be emitted; got:\n%s", out)
	}
}

// TestEmitCaddyfile_ServiceCallout_MissingTargetURL verifies that when
// target_url is absent the emitter falls through to the bare policy name line.
func TestEmitCaddyfile_ServiceCallout_MissingTargetURL(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "NoTargetURL",
		Config: mustJSON(t, map[string]any{
			"response_var": "resp",
		}),
	}

	out := buildSingleHandlerCaddyfile(t, h)

	// target_url is required; missing it causes fallthrough to bare name.
	if !strings.Contains(out, "service_callout NoTargetURL") {
		t.Errorf("expected bare 'service_callout NoTargetURL' fallthrough; got:\n%s", out)
	}
}

// TestEmitCaddyfile_ServiceCallout_NilConfig verifies that a nil Config falls
// through to the bare "service_callout <PolicyName>" line.
func TestEmitCaddyfile_ServiceCallout_NilConfig(t *testing.T) {
	h := transpiler.PolicyHandler{
		Module:     "http.handlers.service_callout",
		PolicyName: "NilCallout",
		Config:     nil,
	}

	out := buildSingleHandlerCaddyfile(t, h)

	if !strings.Contains(out, "service_callout NilCallout") {
		t.Errorf("expected bare 'service_callout NilCallout' fallthrough; got:\n%s", out)
	}
}
