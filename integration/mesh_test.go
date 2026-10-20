//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMesh_VerifyGoogleIDToken_Accepts verifies that verify_google_idtoken
// passes a request with a valid bearer token and populates flow state, which
// an assign_message policy then forwards to the upstream as a header.
//
// With CADDYGEE_BYPASS_IDTOKEN=1 the validator accepts any non-empty token and
// uses the raw token value as the email claim — so the upstream receives
// X-Caller-Email: svc@proj.iam.gserviceaccount.com.
func TestMesh_VerifyGoogleIDToken_Accepts(t *testing.T) {
	var gotEmail string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEmail = r.Header.Get("X-Caller-Email")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")

	// Fragment: verify_google_idtoken then forward the resolved email header.
	fragment := fmt.Sprintf(`
	route /mesh/inbound/* {
		flow_state
		verify_google_idtoken {
			policy_name MeshAuth
			audience    https://service-b.run.app
		}
		assign_message {
			set_header X-Caller-Email "{google_idtoken.MeshAuth.email}"
		}
		reverse_proxy %s
	}
`, upstream.URL)

	gw.DeployFragment("mesh-inbound", fragment)

	resp := gw.GET("/mesh/inbound/data",
		"Authorization", "Bearer svc@proj.iam.gserviceaccount.com")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if gotEmail != "svc@proj.iam.gserviceaccount.com" {
		t.Errorf("X-Caller-Email: got %q, want %q", gotEmail, "svc@proj.iam.gserviceaccount.com")
	}
}

// TestMesh_VerifyGoogleIDToken_Rejects verifies that a request with no
// Authorization header is rejected with 401.
func TestMesh_VerifyGoogleIDToken_Rejects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when verify_google_idtoken rejects")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")

	fragment := fmt.Sprintf(`
	route /mesh/secure/* {
		flow_state
		verify_google_idtoken {
			policy_name MeshAuth
			audience    https://service-b.run.app
		}
		reverse_proxy %s
	}
`, upstream.URL)

	gw.DeployFragment("mesh-secure", fragment)

	// No Authorization header — should be rejected.
	resp := gw.GET("/mesh/secure/data")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestMesh_VerifyGoogleIDToken_AllowedEmails verifies that the allowlist blocks
// a caller whose email is not in the list with 403.
func TestMesh_VerifyGoogleIDToken_AllowedEmails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called — caller not in allowlist")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")

	// Only allowed@proj is permitted; we'll send other@proj.
	fragment := fmt.Sprintf(`
	route /mesh/restricted/* {
		flow_state
		verify_google_idtoken {
			policy_name   MeshAuth
			audience      https://service-b.run.app
			allowed_emails allowed@proj.iam.gserviceaccount.com
		}
		reverse_proxy %s
	}
`, upstream.URL)

	gw.DeployFragment("mesh-restricted", fragment)

	resp := gw.GET("/mesh/restricted/data",
		"Authorization", "Bearer other@proj.iam.gserviceaccount.com")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestMesh_ServiceCallout_WithAudience verifies that a service_callout with an
// audience attaches an Authorization: Bearer header on the outbound request.
//
// With CADDYGEE_BYPASS_IDTOKEN=1 + CADDYGEE_STATIC_OUTBOUND_TOKEN=test-mesh-token
// the token source yields "test-mesh-token" without real ADC.
func TestMesh_ServiceCallout_WithAudience(t *testing.T) {
	var gotCalloutAuth string
	// Fake callout target — records the Authorization header it received.
	callout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCalloutAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer callout.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")

	fragment := fmt.Sprintf(`
	route /mesh/callout/* {
		flow_state
		service_callout {
			target_url %s
			audience   https://service-b.run.app
			response_var enrichResult
		}
		reverse_proxy %s
	}
`, callout.URL, upstream.URL)

	gw.DeployFragment("mesh-callout", fragment)

	resp := gw.GET("/mesh/callout/go")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if gotCalloutAuth != "Bearer test-mesh-token" {
		t.Errorf("callout Authorization: got %q, want %q", gotCalloutAuth, "Bearer test-mesh-token")
	}
}
