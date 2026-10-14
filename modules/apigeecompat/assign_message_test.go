package apigeecompat_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestAssignMessage_SetRequestHeader(t *testing.T) {
	am := &apigeecompat.AssignMessage{
		SetHeaders: map[string]string{"X-Custom": "hello"},
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	var gotHeader string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotHeader = r.Header.Get("X-Custom")
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(am, next))

	if gotHeader != "hello" {
		t.Errorf("X-Custom: got %q, want %q", gotHeader, "hello")
	}
}

func TestAssignMessage_RemoveRequestHeader(t *testing.T) {
	am := &apigeecompat.AssignMessage{
		RemoveHeaders: []string{"Authorization"},
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	var gotAuth string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotAuth = r.Header.Get("Authorization")
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token")
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(am, next))

	if gotAuth != "" {
		t.Errorf("Authorization should be removed, got %q", gotAuth)
	}
}

func TestAssignMessage_FlowVarSubstitution(t *testing.T) {
	am := &apigeecompat.AssignMessage{
		SetHeaders: map[string]string{"X-Auth-Status": "{flowvar.auth.statusCode}"},
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	var gotStatus string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotStatus = r.Header.Get("X-Auth-Status")
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set the flow var first, then run assign_message
	setThenAssign := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		fs.Set("auth.statusCode", "200")
		return am.ServeHTTP(w, r, next)
	})
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, setThenAssign)

	if gotStatus != "200" {
		t.Errorf("X-Auth-Status: got %q, want %q", gotStatus, "200")
	}
}

func TestAssignMessage_ResponsePhase(t *testing.T) {
	am := &apigeecompat.AssignMessage{
		SetHeaders: map[string]string{"X-Processed": "true"},
		Phase:      "response",
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	writeBody := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w, req, wrapMiddleware(am, writeBody))

	if w.Header().Get("X-Processed") != "true" {
		t.Errorf("X-Processed: got %q, want %q", w.Header().Get("X-Processed"), "true")
	}
	if w.Body.String() != "body" {
		t.Errorf("body: got %q, want %q", w.Body.String(), "body")
	}
}

func TestAssignMessage_InvalidPhase(t *testing.T) {
	am := &apigeecompat.AssignMessage{Phase: "invalid"}
	if err := am.Provision(apigeecompat.ZeroContext()); err == nil {
		t.Error("expected error for invalid phase")
	}
}

func TestAssignMessage_SetBody_Request(t *testing.T) {
	am := &apigeecompat.AssignMessage{
		SetBody: "replacement body",
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	var gotBody string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		gotBody = string(b)
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("original body"))
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(am, next))

	if gotBody != "replacement body" {
		t.Errorf("body: got %q, want %q", gotBody, "replacement body")
	}
}

func TestAssignMessage_DefaultPhaseIsRequest(t *testing.T) {
	// An AssignMessage with no Phase should default to "request".
	am := &apigeecompat.AssignMessage{
		SetHeaders: map[string]string{"X-Phase-Check": "yes"},
	}
	if err := am.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var gotHeader string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotHeader = r.Header.Get("X-Phase-Check")
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(am, next))

	if gotHeader != "yes" {
		t.Errorf("X-Phase-Check: got %q, want %q", gotHeader, "yes")
	}
}

func TestAssignMessage_ResponsePhase_StatusCode(t *testing.T) {
	// Regression test for C2 defect 1: non-200 upstream status must be preserved.
	am := &apigeecompat.AssignMessage{
		Phase: "response",
	}
	_ = am.Provision(apigeecompat.ZeroContext())

	// Upstream returns 404.
	writeNotFound := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w, req, wrapMiddleware(am, writeNotFound))

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
	if w.Body.String() != "not found" {
		t.Errorf("body: got %q, want %q", w.Body.String(), "not found")
	}
}
