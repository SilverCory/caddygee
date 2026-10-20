package apigeecompat_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestServiceCallout_StoresResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:   upstream.URL,
		Method:      http.MethodGet,
		ResponseVar: "auth",
	}
	if err := sc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	innerTerminal := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Chain: FlowStateManager → ServiceCallout → innerTerminal
	scHandler := wrapMiddleware(sc, innerTerminal)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, scHandler); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if capturedFS == nil {
		t.Fatal("capturedFS is nil")
	}
	if v := capturedFS.GetString("auth.content"); v != `{"ok":true}` {
		t.Errorf("auth.content: got %q", v)
	}
	if v := capturedFS.GetString("auth.statusCode"); v != "200" {
		t.Errorf("auth.statusCode: got %q", v)
	}
}

func TestServiceCallout_FlowVarSubstitution(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:   upstream.URL + "/users/{flowvar.user.id}",
		ResponseVar: "result",
	}
	_ = sc.Provision(apigeecompat.ZeroContext())

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Set flow var before service callout runs
	setVarThenCallout := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		fs.Set("user.id", "42")
		return sc.ServeHTTP(w, r, terminal)
	})
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, setVarThenCallout)

	if receivedPath != "/users/42" {
		t.Errorf("path: got %q, want /users/42", receivedPath)
	}
}

func TestServiceCallout_NoFlowState_Skips(t *testing.T) {
	called := false
	sc := &apigeecompat.ServiceCallout{TargetURL: "http://unused"}
	_ = sc.Provision(apigeecompat.ZeroContext())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	_ = sc.ServeHTTP(httptest.NewRecorder(), req, next)
	if !called {
		t.Error("expected next handler to be called when no flow state")
	}
}

func TestServiceCallout_RequestBodyVar(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:      upstream.URL,
		Method:         http.MethodPost,
		RequestBodyVar: "myBody",
		ResponseVar:    "result",
	}
	if err := sc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	setVarThenCallout := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		fs.Set("myBody", "hello from flow")
		return sc.ServeHTTP(w, r, terminal)
	})
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, setVarThenCallout); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if receivedBody != "hello from flow" {
		t.Errorf("upstream body: got %q, want %q", receivedBody, "hello from flow")
	}
}

func TestServiceCallout_UpstreamFailure(t *testing.T) {
	// Start and immediately close a server to ensure the port is unreachable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:   closedURL,
		ResponseVar: "result",
	}
	if err := sc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	var calloutErr error
	calloutHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calloutErr = sc.ServeHTTP(w, r, terminal)
		return calloutErr
	})
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, calloutHandler)

	if calloutErr == nil {
		t.Error("expected non-nil error when upstream is unreachable")
	}
}

func TestServiceCallout_InvalidScheme(t *testing.T) {
	sc := &apigeecompat.ServiceCallout{TargetURL: "file:///etc/passwd"}
	err := sc.Provision(apigeecompat.ZeroContext())
	if err == nil {
		t.Error("expected error for file:// scheme, got nil")
	}
}

func TestServiceCallout_AudienceInjectsToken(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:   upstream.URL,
		ResponseVar: "result",
	}
	if err := sc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Inject a static token source instead of calling idtoken.NewTokenSource.
	sc.SetTokenSource(staticTokenSource("test-oidc-token"))

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	calloutHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return sc.ServeHTTP(w, r, terminal)
	})
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, calloutHandler); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if receivedAuth != "Bearer test-oidc-token" {
		t.Errorf("Authorization: got %q", receivedAuth)
	}
}

func TestServiceCallout_ClientReuse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	sc := &apigeecompat.ServiceCallout{
		TargetURL:   upstream.URL,
		ResponseVar: "result",
	}
	if err := sc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Verify the client is non-nil after Provision.
	if sc.Client() == nil {
		t.Fatal("client should be non-nil after Provision")
	}
	firstClient := sc.Client()

	// Run two requests and confirm the same client instance is used.
	mgr := apigeecompat.FlowStateManager{}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		calloutHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return sc.ServeHTTP(w, r, terminal)
		})
		if err := mgr.ServeHTTP(httptest.NewRecorder(), req, calloutHandler); err != nil {
			t.Fatalf("ServeHTTP iteration %d: %v", i, err)
		}
	}

	// Client pointer must be the same instance across calls.
	if sc.Client() != firstClient {
		t.Error("client was replaced between calls; expected same *http.Client instance")
	}
}
