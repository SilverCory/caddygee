//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestE2E_FullFlow exercises the complete lifecycle:
//  1. Transpile a multi-policy proxy bundle
//  2. Deploy the fragment via the caddygee-server /deploy endpoint
//  3. Send a real HTTP request through Caddy
//  4. Assert the upstream receives the headers set by all three policies
//
// Bundle: testdata/integration/e2e/apiproxy
//   - ExtractClientID: extracts X-Client-ID header → variable client.id
//   - ForwardClientID: sets X-Forwarded-Client-ID: {client.id} on request
//   - SetGatewayHeader: sets X-Gateway: caddygee on request
func TestE2E_FullFlow(t *testing.T) {
	var (
		gotForwardedClientID string
		gotGateway           string
		gotOriginalClientID  string
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotForwardedClientID = r.Header.Get("X-Forwarded-Client-ID")
		gotGateway = r.Header.Get("X-Gateway")
		gotOriginalClientID = r.Header.Get("X-Client-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e/apiproxy", "e2e", upstream.URL)

	resp := gw.GET("/test/e2e/", "X-Client-ID", "client-abc123")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// ExtractClientID extracts "abc123" from "client-abc123" using pattern "client-{id}"
	// No wait: the proxy test bundle uses pattern "{id}" directly so client.id = "client-abc123".
	// ForwardClientID: X-Forwarded-Client-ID should equal X-Client-ID (no transformation).
	if gotForwardedClientID != gotOriginalClientID {
		t.Errorf("X-Forwarded-Client-ID: got %q, want same as X-Client-ID (%q)",
			gotForwardedClientID, gotOriginalClientID)
	}
	if gotForwardedClientID == "" {
		t.Error("X-Forwarded-Client-ID is empty — ExtractClientID/ForwardClientID did not run")
	}

	// SetGatewayHeader: X-Gateway must be "caddygee".
	if gotGateway != "caddygee" {
		t.Errorf("X-Gateway: got %q, want %q", gotGateway, "caddygee")
	}
}

// TestE2E_MultiDeploy verifies that deploying two independent services results
// in both routes being active simultaneously.
func TestE2E_MultiDeploy(t *testing.T) {
	var (
		svc1Called bool
		svc2Called bool
	)

	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc1Called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc2Called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream2.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/assign_message/apiproxy", "svc1-assign", upstream1.URL)
	gw.Deploy("testdata/integration/raise_fault/apiproxy", "svc2-raise", upstream2.URL)

	// Hit service 1 — assign_message sets header, upstream returns 200.
	resp1 := gw.GET("/test/assign-message/")
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("svc1: expected 200, got %d", resp1.StatusCode)
	}
	if !svc1Called {
		t.Error("svc1 upstream was not called")
	}

	// Hit service 2 — raise_fault returns 403 without hitting upstream.
	resp2 := gw.GET("/test/raise-fault/")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("svc2: expected 403, got %d", resp2.StatusCode)
	}
	if svc2Called {
		t.Error("svc2 upstream should not have been called (raise_fault)")
	}
}

// TestE2E_DeployReplace verifies that re-deploying a service with a different
// upstream replaces the previous route rather than duplicating it.
func TestE2E_DeployReplace(t *testing.T) {
	var calledV1, calledV2 int

	upstreamV1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledV1++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamV1.Close()

	upstreamV2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledV2++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamV2.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/assign_message/apiproxy", "replace-svc", upstreamV1.URL)

	resp1 := gw.GET("/test/assign-message/")
	resp1.Body.Close()
	if calledV1 != 1 {
		t.Errorf("after first deploy: v1 called %d times, want 1", calledV1)
	}

	// Re-deploy the same service name pointing to v2.
	gw.Deploy("testdata/integration/assign_message/apiproxy", "replace-svc", upstreamV2.URL)

	resp2 := gw.GET("/test/assign-message/")
	resp2.Body.Close()
	if calledV2 != 1 {
		t.Errorf("after redeploy: v2 called %d times, want 1", calledV2)
	}
	if calledV1 != 1 {
		t.Errorf("after redeploy: v1 was called again (total %d), route not replaced", calledV1)
	}
}
