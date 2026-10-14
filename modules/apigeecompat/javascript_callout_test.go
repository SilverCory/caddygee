package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestJavaScriptCallout_SetsFlowVar(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("foo", "bar");`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(jsc, next)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if capturedFS == nil {
		t.Fatal("flow state is nil")
	}
	if v, ok := capturedFS.Get("foo").(string); !ok || v != "bar" {
		t.Errorf("foo: got %v, want %q", capturedFS.Get("foo"), "bar")
	}
}

func TestJavaScriptCallout_GetsFlowVar(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `
			var user = context.getVariable("request.user");
			context.setVariable("greeting", "hello " + user);
		`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Pre-populate flow state before the JS callout runs.
	setThenRun := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fs, _ := apigeecompat.GetFlowState(r.Context())
		fs.Set("request.user", "alice")
		return jsc.ServeHTTP(w, r, next)
	})
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, setThenRun); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if capturedFS == nil {
		t.Fatal("flow state is nil")
	}
	if v := capturedFS.GetString("greeting"); v != "hello alice" {
		t.Errorf("greeting: got %q, want %q", v, "hello alice")
	}
}

func TestJavaScriptCallout_SyntaxError(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `this is not valid javascript }{`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err == nil {
		t.Error("expected Provision to return error for invalid JS, got nil")
	}
}

func TestJavaScriptCallout_Timeout(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source:    `while(true){}`,
		TimeoutMs: 50, // short timeout so test runs fast
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	start := time.Now()
	var gotErr error
	runScript := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotErr = jsc.ServeHTTP(w, r, terminal)
		return gotErr
	})
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, runScript)
	elapsed := time.Since(start)

	if gotErr == nil {
		t.Error("expected timeout error, got nil")
	}
	// Should not take much longer than the timeout itself.
	if elapsed > 2*time.Second {
		t.Errorf("script took too long to time out: %v", elapsed)
	}
}

func TestJavaScriptCallout_NoFlowState(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("x", "1");`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	// No FlowStateManager — no flow state in context.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := jsc.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected next handler to be called when no flow state")
	}
}

func TestJavaScriptCallout_RequestContext(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `
			context.setVariable("method", context.requestMethod);
			context.setVariable("path",   context.requestPath);
			context.setVariable("host",   context.requestHost);
			context.setVariable("ua",     context.requestHeaders["User-Agent"]);
			context.setVariable("q",      context.queryParams["q"]);
		`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1?q=hello", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "test-agent/1.0")
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(jsc, next)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	checks := map[string]string{
		"method": "POST",
		"path":   "/api/v1",
		"host":   "example.com",
		"ua":     "test-agent/1.0",
		"q":      "hello",
	}
	for k, want := range checks {
		if got := capturedFS.GetString(k); got != want {
			t.Errorf("%s: got %q, want %q", k, got, want)
		}
	}
}

func TestJavaScriptCallout_LibDir(t *testing.T) {
	// Write a small library file into a temp dir.
	dir := t.TempDir()
	libJS := `function greet(name) { return "hello " + name; }`
	if err := os.WriteFile(dir+"/utils.js", []byte(libJS), 0o644); err != nil {
		t.Fatalf("write lib: %v", err)
	}

	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("greeting", greet("world"));`,
		LibDir: dir,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(jsc, next)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if got := capturedFS.GetString("greeting"); got != "hello world" {
		t.Errorf("greeting: got %q, want %q", got, "hello world")
	}
}

func TestJavaScriptCallout_LibDir_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	// Two library files — load order is alphabetical.
	if err := os.WriteFile(dir+"/a_constants.js", []byte(`var PREFIX = "greet:";`), 0o644); err != nil {
		t.Fatalf("write a_constants.js: %v", err)
	}
	if err := os.WriteFile(dir+"/b_utils.js", []byte(`function tag(s) { return PREFIX + s; }`), 0o644); err != nil {
		t.Fatalf("write b_utils.js: %v", err)
	}

	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("out", tag("world"));`,
		LibDir: dir,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(jsc, next)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if got := capturedFS.GetString("out"); got != "greet:world" {
		t.Errorf("out: got %q, want %q", got, "greet:world")
	}
}

func TestJavaScriptCallout_LibDir_InvalidDir(t *testing.T) {
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("x", "1");`,
		LibDir: "/this/path/does/not/exist",
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err == nil {
		t.Error("expected Provision to return error for nonexistent lib_dir, got nil")
	}
}

func TestJavaScriptCallout_LibDir_SyntaxError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/bad.js", []byte(`}{this is not valid`), 0o644); err != nil {
		t.Fatalf("write bad.js: %v", err)
	}

	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("x", "1");`,
		LibDir: dir,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err == nil {
		t.Error("expected Provision to return error for invalid JS in lib_dir, got nil")
	}
}

func TestJavaScriptCallout_LibDir_FlowStateIsolation(t *testing.T) {
	// Library function should be available but the FlowState (per-request data)
	// must not bleed between requests. Use the library to produce a value from
	// request-scoped input, ensuring each request sees only its own flow vars.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/utils.js", []byte(`function echo(v) { return "echo:" + v; }`), 0o644); err != nil {
		t.Fatalf("write utils.js: %v", err)
	}

	jsc := &apigeecompat.JavaScriptCallout{
		Source: `context.setVariable("out", echo(context.getVariable("in")));`,
		LibDir: dir,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	inputs := []string{"alpha", "beta", "gamma"}
	for _, input := range inputs {
		input := input
		var capturedFS *apigeecompat.FlowState
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			capturedFS, _ = apigeecompat.GetFlowState(r.Context())
			return nil
		})
		setThenRun := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			fs, _ := apigeecompat.GetFlowState(r.Context())
			fs.Set("in", input)
			return jsc.ServeHTTP(w, r, next)
		})

		mgr := apigeecompat.FlowStateManager{}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := mgr.ServeHTTP(httptest.NewRecorder(), req, setThenRun); err != nil {
			t.Fatalf("input %q: %v", input, err)
		}
		want := "echo:" + input
		if got := capturedFS.GetString("out"); got != want {
			t.Errorf("input %q: out = %q, want %q", input, got, want)
		}
	}
}

func TestJavaScriptCallout_RuntimeReuse_NoLeakage(t *testing.T) {
	// First script sets "leaky" variable. Second script should NOT see it.
	jsc := &apigeecompat.JavaScriptCallout{
		Source: `
			var prev = context.getVariable("leaky");
			if (prev !== null) {
				context.setVariable("leaked", "true");
			}
			context.setVariable("leaky", "yes");
		`,
	}
	if err := jsc.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Run the script twice; the second run should not see "leaky" from the first.
	for i := 0; i < 2; i++ {
		var capturedFS *apigeecompat.FlowState
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			capturedFS, _ = apigeecompat.GetFlowState(r.Context())
			return nil
		})

		mgr := apigeecompat.FlowStateManager{}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := mgr.ServeHTTP(httptest.NewRecorder(), req, wrapMiddleware(jsc, next)); err != nil {
			t.Fatalf("iteration %d ServeHTTP: %v", i, err)
		}

		if capturedFS.GetString("leaked") == "true" {
			t.Errorf("iteration %d: flow variable leaked between requests", i)
		}
	}
}
