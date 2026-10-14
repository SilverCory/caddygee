package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
)

func TestIsDebug_FalseByDefault(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if apigeecompat.IsDebug(req) {
		t.Error("expected IsDebug=false for plain request")
	}
}

func TestIsDebug_TrueWhenFlagSet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = apigeecompat.WithDebugRequest(req)
	if !apigeecompat.IsDebug(req) {
		t.Error("expected IsDebug=true after WithDebugRequest")
	}
}

func TestIsDebug_SetByHeaderViaFlowStateManager(t *testing.T) {
	// Debug mode requires the header value to match the configured token.
	const token = "secret-debug-token"
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithDebugToken(token)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", token)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if !gotDebug {
		t.Error("expected IsDebug=true when X-Apigee-Debug header matches token")
	}
}

func TestIsDebug_NotSetWhenHeaderTokenWrong(t *testing.T) {
	const token = "secret-debug-token"
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithDebugToken(token)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", "wrong-token")
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when X-Apigee-Debug header has wrong token")
	}
}

func TestIsDebug_NotSetWhenNoDebugToken(t *testing.T) {
	// When FlowStateManager has no debug token, debug mode is always off.
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithDebugToken("") // no token = disabled
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", "anything")
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when no DEBUG_TOKEN is configured")
	}
}

func TestIsDebug_SetByQueryParamViaFlowStateManager(t *testing.T) {
	const token = "secret-debug-token"
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithDebugToken(token)
	req := httptest.NewRequest(http.MethodGet, "/?_debug="+token, nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if !gotDebug {
		t.Error("expected IsDebug=true when ?_debug= query param matches token")
	}
}

func TestIsDebug_NotSetWhenNoHeaderOrParam(t *testing.T) {
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithDebugToken("some-token")
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when no debug header or param")
	}
}
