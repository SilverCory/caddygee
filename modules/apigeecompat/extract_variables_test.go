package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
)

// ---------------------------------------------------------------------------
// matchPattern (white-box via export)
// ---------------------------------------------------------------------------

func TestMatchPattern_BearerHeader(t *testing.T) {
	got := apigeecompat.MatchPattern("Bearer {token}", "Bearer abc123")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got["token"] != "abc123" {
		t.Errorf("token: got %q, want %q", got["token"], "abc123")
	}
}

func TestMatchPattern_PathWithWildcard(t *testing.T) {
	got := apigeecompat.MatchPattern("/v1/passes/*/{sn}", "/v1/passes/loyalty/ABC99")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got["sn"] != "ABC99" {
		t.Errorf("sn: got %q, want %q", got["sn"], "ABC99")
	}
}

func TestMatchPattern_MultipleVars(t *testing.T) {
	got := apigeecompat.MatchPattern("/v1/{resource}/{id}", "/v1/users/42")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got["resource"] != "users" {
		t.Errorf("resource: got %q, want %q", got["resource"], "users")
	}
	if got["id"] != "42" {
		t.Errorf("id: got %q, want %q", got["id"], "42")
	}
}

func TestMatchPattern_VarAtEnd(t *testing.T) {
	got := apigeecompat.MatchPattern("/api/{name}", "/api/foobar")
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got["name"] != "foobar" {
		t.Errorf("name: got %q, want %q", got["name"], "foobar")
	}
}

func TestMatchPattern_NoMatch_LiteralMismatch(t *testing.T) {
	got := apigeecompat.MatchPattern("/v1/{id}", "/v2/something")
	if got != nil {
		t.Errorf("expected nil for non-matching pattern, got %v", got)
	}
}

func TestMatchPattern_EmptyInput(t *testing.T) {
	got := apigeecompat.MatchPattern("Bearer {token}", "")
	if got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestMatchPattern_ExactLiteralMatch_NoVars(t *testing.T) {
	// A pattern with no variables that matches exactly should return an empty (non-nil) map.
	got := apigeecompat.MatchPattern("/health", "/health")
	if got == nil {
		t.Fatal("expected non-nil result for exact match")
	}
}

func TestMatchPattern_ExactLiteralMatch_NoMatch(t *testing.T) {
	got := apigeecompat.MatchPattern("/health", "/status")
	if got != nil {
		t.Errorf("expected nil for literal mismatch, got %v", got)
	}
}

func TestMatchPattern_WildcardOnly(t *testing.T) {
	// * should consume a single path segment (no slash).
	got := apigeecompat.MatchPattern("/v1/*/end", "/v1/segment/end")
	if got == nil {
		t.Fatal("expected non-nil for wildcard match")
	}
}

// ---------------------------------------------------------------------------
// ExtractVariables.ServeHTTP — integration through FlowStateManager
// ---------------------------------------------------------------------------

func TestExtractVariables_HeaderExtraction(t *testing.T) {
	ev := &apigeecompat.ExtractVariables{
		Prefix:         "auth",
		HeaderPatterns: map[string]string{"Authorization": "Bearer {token}"},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	var gotToken string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotToken = fs.GetString("auth.token")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken42")
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(ev, next))

	if gotToken != "mytoken42" {
		t.Errorf("auth.token: got %q, want %q", gotToken, "mytoken42")
	}
}

func TestExtractVariables_PathExtraction(t *testing.T) {
	ev := &apigeecompat.ExtractVariables{
		Prefix:       "pass",
		PathPatterns: []string{"/passes/*/v1/{serialnumber}"},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	var gotSerial string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotSerial = fs.GetString("pass.serialnumber")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/passes/loyalty/v1/SERIAL99", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(ev, next))

	if gotSerial != "SERIAL99" {
		t.Errorf("pass.serialnumber: got %q, want %q", gotSerial, "SERIAL99")
	}
}

func TestExtractVariables_PathFirstPatternWins(t *testing.T) {
	// Only the first matching path pattern should be applied (break after first match).
	ev := &apigeecompat.ExtractVariables{
		Prefix: "p",
		PathPatterns: []string{
			"/v1/{first}",
			"/v1/{second}", // should never be reached if first matches
		},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	var gotFirst, gotSecond string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotFirst = fs.GetString("p.first")
		gotSecond = fs.GetString("p.second")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/v1/hello", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(ev, next))

	if gotFirst != "hello" {
		t.Errorf("p.first: got %q, want %q", gotFirst, "hello")
	}
	if gotSecond != "" {
		t.Errorf("p.second should be empty (second pattern skipped), got %q", gotSecond)
	}
}

func TestExtractVariables_NoFlowState_PassesThrough(t *testing.T) {
	ev := &apigeecompat.ExtractVariables{
		HeaderPatterns: map[string]string{"Authorization": "Bearer {token}"},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	called := false
	next := makeCapturingHandler(func(r *http.Request) { called = true })

	// No FlowStateManager — request has no flow state.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	_ = ev.ServeHTTP(httptest.NewRecorder(), req, next)

	if !called {
		t.Error("expected next handler to be called when no flow state")
	}
}

func TestExtractVariables_MissingHeader_Skipped(t *testing.T) {
	// Header not present — no var should be set, but next is still called.
	ev := &apigeecompat.ExtractVariables{
		Prefix:         "auth",
		HeaderPatterns: map[string]string{"Authorization": "Bearer {token}"},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	var gotToken string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotToken = fs.GetString("auth.token")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no Authorization header
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(ev, next))

	if gotToken != "" {
		t.Errorf("auth.token should be empty when header absent, got %q", gotToken)
	}
}

func TestExtractVariables_NoPrefixKey(t *testing.T) {
	ev := &apigeecompat.ExtractVariables{
		// No Prefix — var key should just be the name.
		HeaderPatterns: map[string]string{"X-Client-ID": "{clientid}"},
	}
	_ = ev.Provision(apigeecompat.ZeroContext())

	var gotID string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotID = fs.GetString("clientid")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-ID", "client-abc")
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(ev, next))

	if gotID != "client-abc" {
		t.Errorf("clientid: got %q, want %q", gotID, "client-abc")
	}
}

// makeCapturingHandler creates a caddyhttp.Handler that calls fn with the request.
func makeCapturingHandler(fn func(*http.Request)) interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
} {
	return terminalFn(fn)
}

type terminalFn func(*http.Request)

func (f terminalFn) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	f(r)
	return nil
}
