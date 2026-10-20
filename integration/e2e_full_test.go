//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestE2EFull_AuthChain deploys a JWT-verify + forward-claim chain and verifies
// that a valid JWT results in the decoded claim being forwarded to upstream,
// while a missing/invalid JWT is rejected at the gateway.
func TestE2EFull_AuthChain(t *testing.T) {
	var receivedSub string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSub = r.Header.Get("X-User-Sub")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/auth_chain/apiproxy", "auth-chain", upstream.URL)

	t.Run("valid JWT forwards sub claim", func(t *testing.T) {
		receivedSub = ""
		resp := gw.GET("/test/auth-chain/", "Authorization", "Bearer "+testJWT)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedSub != "test-subject" {
			t.Errorf("X-User-Sub: got %q, want %q", receivedSub, "test-subject")
		}
	})

	t.Run("missing JWT is rejected", func(t *testing.T) {
		resp := gw.GET("/test/auth-chain/")
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected non-200 when JWT is missing, got 200")
		}
	})

	t.Run("invalid JWT is rejected", func(t *testing.T) {
		resp := gw.GET("/test/auth-chain/", "Authorization", "Bearer not.a.valid.jwt")
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected non-200 for invalid JWT, got 200")
		}
	})
}

// TestE2EFull_RateLimitedAuth deploys a JWT-verify + spike-arrest chain.
// A valid JWT must pass auth first; rapid successive requests then hit the rate
// limit even though they carry a valid token.
func TestE2EFull_RateLimitedAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/rate_limited_auth/apiproxy", "rate-limited-auth", upstream.URL)

	t.Run("missing JWT blocked before rate limit", func(t *testing.T) {
		resp := gw.GET("/test/rate-limited-auth/")
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("expected non-200 for missing JWT")
		}
	})

	t.Run("valid JWT passes auth", func(t *testing.T) {
		resp := gw.GET("/test/rate-limited-auth/", "Authorization", "Bearer "+testJWT)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first authenticated request: expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("rapid requests hit spike arrest", func(t *testing.T) {
		// SpikeArrest at 2pm = one per 30s.
		// First request passes; second consecutive request must get 429.
		resp1 := gw.GET("/test/rate-limited-auth/", "Authorization", "Bearer "+testJWT)
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
		}
		resp2 := gw.GET("/test/rate-limited-auth/", "Authorization", "Bearer "+testJWT)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusTooManyRequests {
			t.Errorf("second request: expected 429 from spike arrest, got %d", resp2.StatusCode)
		}
	})
}

// TestE2EFull_ConditionalTransform deploys a proxy where AssignMessage only
// fires when the X-Tier request header equals "premium".
func TestE2EFull_ConditionalTransform(t *testing.T) {
	var receivedEnv string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedEnv = r.Header.Get("X-Env")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/conditional_transform/apiproxy", "conditional-transform", upstream.URL)

	t.Run("header set when condition matches", func(t *testing.T) {
		receivedEnv = ""
		resp := gw.GET("/test/conditional-transform/", "X-Tier", "premium")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedEnv != "premium" {
			t.Errorf("X-Env: got %q, want %q", receivedEnv, "premium")
		}
	})

	t.Run("header not set when condition does not match", func(t *testing.T) {
		receivedEnv = ""
		resp := gw.GET("/test/conditional-transform/", "X-Tier", "free")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedEnv != "" {
			t.Errorf("X-Env should be empty when tier is not premium, got %q", receivedEnv)
		}
	})

	t.Run("header not set when header absent", func(t *testing.T) {
		receivedEnv = ""
		resp := gw.GET("/test/conditional-transform/")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedEnv != "" {
			t.Errorf("X-Env should be empty when X-Tier absent, got %q", receivedEnv)
		}
	})
}

// TestE2EFull_KVMAssignChain deploys a proxy that loads a value from a KVM
// and forwards it to upstream via AssignMessage.
func TestE2EFull_KVMAssignChain(t *testing.T) {
	var receivedFlag string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedFlag = r.Header.Get("X-Feature-Flag")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/kvm_assign_chain/apiproxy", "kvm-assign-chain", upstream.URL)

	resp := gw.GET("/test/kvm-assign-chain/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// KVM seeded with flag.name → "new-checkout"; AssignMessage forwards it.
	if receivedFlag != "new-checkout" {
		t.Errorf("X-Feature-Flag: got %q, want %q", receivedFlag, "new-checkout")
	}
}

// TestE2EFull_MultiServiceIsolation deploys two independent services and verifies
// that each route is served independently with no cross-contamination.
func TestE2EFull_MultiServiceIsolation(t *testing.T) {
	var receivedServiceA, receivedServiceB string

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedServiceA = r.Header.Get("X-Service")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedServiceB = r.Header.Get("X-Service")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamB.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/multi_service_a/apiproxy", "multi-svc-a", upstreamA.URL)
	gw.Deploy("testdata/integration/e2e_full/multi_service_b/apiproxy", "multi-svc-b", upstreamB.URL)

	t.Run("service A route", func(t *testing.T) {
		receivedServiceA = ""
		resp := gw.GET("/test/multi-a/")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedServiceA != "service-a" {
			t.Errorf("X-Service: got %q, want %q", receivedServiceA, "service-a")
		}
	})

	t.Run("service B route", func(t *testing.T) {
		receivedServiceB = ""
		resp := gw.GET("/test/multi-b/")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if receivedServiceB != "service-b" {
			t.Errorf("X-Service: got %q, want %q", receivedServiceB, "service-b")
		}
	})

	t.Run("service A does not bleed into service B upstream", func(t *testing.T) {
		// Hit A, then B. A upstream must not have been called by the B request.
		receivedServiceA = ""
		resp := gw.GET("/test/multi-b/")
		defer resp.Body.Close()
		if receivedServiceA != "" {
			t.Error("service A upstream was called by a /test/multi-b/ request")
		}
	})

	t.Run("service A path not routed to service B", func(t *testing.T) {
		// Verify /test/multi-a/ does not trigger service B's upstream.
		receivedServiceB = ""
		resp := gw.GET("/test/multi-a/")
		defer resp.Body.Close()
		if receivedServiceB != "" {
			t.Errorf("service B upstream was triggered by /test/multi-a/ request (got X-Service=%q)", receivedServiceB)
		}
	})
}

// TestE2EFull_JSEnrichRequest deploys a proxy where JavaScript sets a variable
// and AssignMessage forwards it as a request header to upstream.
func TestE2EFull_JSEnrichRequest(t *testing.T) {
	var receivedRequestID string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/js_enrich_response/apiproxy", "js-enrich", upstream.URL)

	resp := gw.GET("/test/js-enrich/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// JS sets js.request.id = "req-12345"; AssignMessage forwards it.
	if receivedRequestID != "req-12345" {
		t.Errorf("X-Request-ID: got %q, want %q", receivedRequestID, "req-12345")
	}
}

// TestE2EFull_AllServicesCoexist deploys all six e2e_full services on a single
// gateway instance and verifies that every route responds independently without
// interference after all deployments.
func TestE2EFull_AllServicesCoexist(t *testing.T) {
	var (
		subFromAuth  string
		flagFromKVM  string
		idFromJS     string
		envFromCond  string
		tagFromA     string
		tagFromB     string
	)

	mkUpstream := func(recv *string, header string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*recv = r.Header.Get(header)
			w.WriteHeader(http.StatusOK)
		}))
	}

	uAuth := mkUpstream(&subFromAuth, "X-User-Sub")
	defer uAuth.Close()
	uKVM := mkUpstream(&flagFromKVM, "X-Feature-Flag")
	defer uKVM.Close()
	uJS := mkUpstream(&idFromJS, "X-Request-ID")
	defer uJS.Close()
	uCond := mkUpstream(&envFromCond, "X-Env")
	defer uCond.Close()
	uA := mkUpstream(&tagFromA, "X-Service")
	defer uA.Close()
	uB := mkUpstream(&tagFromB, "X-Service")
	defer uB.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/e2e_full/auth_chain/apiproxy", "full-auth-chain", uAuth.URL)
	gw.Deploy("testdata/integration/e2e_full/kvm_assign_chain/apiproxy", "full-kvm-chain", uKVM.URL)
	gw.Deploy("testdata/integration/e2e_full/js_enrich_response/apiproxy", "full-js-enrich", uJS.URL)
	gw.Deploy("testdata/integration/e2e_full/conditional_transform/apiproxy", "full-cond-transform", uCond.URL)
	gw.Deploy("testdata/integration/e2e_full/multi_service_a/apiproxy", "full-multi-a", uA.URL)
	gw.Deploy("testdata/integration/e2e_full/multi_service_b/apiproxy", "full-multi-b", uB.URL)

	t.Run("auth chain: valid JWT", func(t *testing.T) {
		subFromAuth = ""
		resp := gw.GET("/test/auth-chain/", "Authorization", "Bearer "+testJWT)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if subFromAuth != "test-subject" {
			t.Errorf("X-User-Sub: got %q, want %q", subFromAuth, "test-subject")
		}
	})

	t.Run("kvm chain: feature flag forwarded", func(t *testing.T) {
		flagFromKVM = ""
		resp := gw.GET("/test/kvm-assign-chain/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if flagFromKVM != "new-checkout" {
			t.Errorf("X-Feature-Flag: got %q, want %q", flagFromKVM, "new-checkout")
		}
	})

	t.Run("js enrich: request id forwarded", func(t *testing.T) {
		idFromJS = ""
		resp := gw.GET("/test/js-enrich/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if idFromJS != "req-12345" {
			t.Errorf("X-Request-ID: got %q, want %q", idFromJS, "req-12345")
		}
	})

	t.Run("conditional transform: fires on premium", func(t *testing.T) {
		envFromCond = ""
		resp := gw.GET("/test/conditional-transform/", "X-Tier", "premium")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if envFromCond != "premium" {
			t.Errorf("X-Env: got %q, want %q", envFromCond, "premium")
		}
	})

	t.Run("conditional transform: skips on non-premium", func(t *testing.T) {
		envFromCond = ""
		resp := gw.GET("/test/conditional-transform/", "X-Tier", "standard")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if envFromCond != "" {
			t.Errorf("X-Env should be empty for non-premium tier, got %q", envFromCond)
		}
	})

	t.Run("multi service A independent", func(t *testing.T) {
		tagFromA = ""
		resp := gw.GET("/test/multi-a/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if tagFromA != "service-a" {
			t.Errorf("X-Service: got %q, want %q", tagFromA, "service-a")
		}
	})

	t.Run("multi service B independent", func(t *testing.T) {
		tagFromB = ""
		resp := gw.GET("/test/multi-b/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if tagFromB != "service-b" {
			t.Errorf("X-Service: got %q, want %q", tagFromB, "service-b")
		}
	})

	t.Run("auth chain rejects invalid JWT after all deploys", func(t *testing.T) {
		resp := gw.GET("/test/auth-chain/", "Authorization", "Bearer tampered.jwt.here")
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("expected non-200 for invalid JWT after all services deployed")
		}
	})
}
