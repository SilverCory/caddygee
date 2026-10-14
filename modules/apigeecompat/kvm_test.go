package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
)

func TestKVM_StaticEntries_AppliedToFlowState(t *testing.T) {
	k := &apigeecompat.KVM{
		Entries: map[string]string{
			"authApiBaseUrl": "auth.example.com",
			"timeout":        "30",
		},
	}
	_ = k.Provision(apigeecompat.ZeroContext())

	var gotURL, gotTimeout string
	next := makeCapturingHandler(func(r *http.Request) {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		gotURL = fs.GetString("authApiBaseUrl")
		gotTimeout = fs.GetString("timeout")
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(k, next))

	if gotURL != "auth.example.com" {
		t.Errorf("authApiBaseUrl: got %q, want %q", gotURL, "auth.example.com")
	}
	if gotTimeout != "30" {
		t.Errorf("timeout: got %q, want %q", gotTimeout, "30")
	}
}

func TestKVM_NoFlowState_PassesThrough(t *testing.T) {
	k := &apigeecompat.KVM{
		Entries: map[string]string{"key": "value"},
	}
	_ = k.Provision(apigeecompat.ZeroContext())

	called := false
	next := makeCapturingHandler(func(_ *http.Request) { called = true })

	// No FlowStateManager — no flow state in context.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = k.ServeHTTP(httptest.NewRecorder(), req, next)

	if !called {
		t.Error("expected next handler to be called when no flow state")
	}
}

func TestKVM_EmptyEntries_NoOp(t *testing.T) {
	// No entries and no MapName — handler should pass through without error.
	k := &apigeecompat.KVM{}
	_ = k.Provision(apigeecompat.ZeroContext())

	called := false
	next := makeCapturingHandler(func(_ *http.Request) { called = true })

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(k, next))

	if !called {
		t.Error("expected next handler to be called for empty KVM")
	}
}

func TestKVM_MultipleRequests_StaticEntriesConsistent(t *testing.T) {
	k := &apigeecompat.KVM{
		Entries: map[string]string{"env": "prod"},
	}
	_ = k.Provision(apigeecompat.ZeroContext())

	mgr := apigeecompat.FlowStateManager{}
	for i := 0; i < 5; i++ {
		var got string
		next := makeCapturingHandler(func(r *http.Request) {
			fs, _ := apigeecompat.GetFlowState(r.Context())
			got = fs.GetString("env")
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(k, next))
		if got != "prod" {
			t.Errorf("iteration %d: env: got %q, want %q", i, got, "prod")
		}
	}
}
