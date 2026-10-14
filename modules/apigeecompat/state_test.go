package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestFlowStateManager_InjectsState(t *testing.T) {
	var capturedFS *apigeecompat.FlowState

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, ok := apigeecompat.GetFlowState(r.Context())
		if !ok {
			t.Error("flow state not present in context")
			return nil
		}
		capturedFS = fs
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if capturedFS == nil {
		t.Fatal("flow state was nil")
	}
}

func TestFlowStateManager_FreshStatePerRequest(t *testing.T) {
	var states []*apigeecompat.FlowState

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		states = append(states, fs)
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)
	}
	if len(states) != 3 {
		t.Fatalf("expected 3 states, got %d", len(states))
	}
	if states[0] == states[1] || states[1] == states[2] {
		t.Error("expected distinct FlowState instances per request")
	}
}

func TestFlowStateManager_SeedsEnvironmentName(t *testing.T) {
	const wantEnv = "preview"
	mgr := apigeecompat.NewFlowStateManagerWithEnv(wantEnv)

	var got string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, ok := apigeecompat.GetFlowState(r.Context())
		if !ok {
			t.Error("flow state not present in context")
			return nil
		}
		got = fs.GetString("environment.name")
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got != wantEnv {
		t.Errorf("environment.name: got %q, want %q", got, wantEnv)
	}
}

func TestFlowStateManager_NoEnvName_NotSeeded(t *testing.T) {
	mgr := apigeecompat.FlowStateManager{} // envName is empty

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		if v := fs.GetString("environment.name"); v != "" {
			t.Errorf("expected empty environment.name, got %q", v)
		}
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)
}

func TestFlowState_GetSet(t *testing.T) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		fs.Set("foo", "bar")
		if v := fs.GetString("foo"); v != "bar" {
			t.Errorf("GetString: got %q, want %q", v, "bar")
		}
		if v := fs.Get("missing"); v != nil {
			t.Errorf("Get missing key: expected nil, got %v", v)
		}
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)
}
