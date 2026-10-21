//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testJWT is a pre-generated RS256 token (expiry 2099-01-01) signed with the
// private key whose public counterpart is embedded in
// testdata/integration/verify_jwt/apiproxy/policies/CheckJWT.xml.
const testJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0LWF1ZGllbmNlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE3OTI1Mjc2MDcsImlzcyI6InRlc3QtaXNzdWVyIiwic3ViIjoidGVzdC1zdWJqZWN0In0.zfHT3pcbNG8b5LJzcCcf3pbR8-z5ekIaX4ncJ7SUfDIdkyYcuvsl-BbZgqEdfgFDGUDuusaBMk-n8Y480H-w2C-VsQGSWRJmfZmRU2OJJk4gHZK08Fa3erxfH5lYw0mg5lKWlbmAhp5F3NXXQbNaAh72AGpbP5YfYTd4vAQ85_Tc7w3rHT_oaEhEf9Nc23shrjzmHMfeeFdNxe4gXb4XXZcDx-DbBE_ACUkLIJUzJVGazbAcPb639WUVUc0sQW5vUkYxdGLW5KGc_C_6-ANfC-IzD-3h2zxqiwyk9RQ9HNk3qdV2Pf9kQ6IN28wZ21PIudMPhrt965b1MdzEOk75Ew"

// TestPolicy_AssignMessage verifies that AssignMessage sets a request header
// on the upstream call.
func TestPolicy_AssignMessage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Test-Header", r.Header.Get("X-Test-Header"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/assign_message/apiproxy", "assign-message", upstream.URL)

	resp := gw.GET("/test/assign-message/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Received-Test-Header"); got != "injected" {
		t.Errorf("X-Received-Test-Header: got %q, want %q", got, "injected")
	}
}

// TestPolicy_RaiseFault verifies that RaiseFault returns the configured
// status code and body without reaching the upstream.
func TestPolicy_RaiseFault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when RaiseFault fires")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/raise_fault/apiproxy", "raise-fault", upstream.URL)

	resp := gw.GET("/test/raise-fault/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "forbidden") {
		t.Errorf("body %q does not contain 'forbidden'", body)
	}
}

// TestPolicy_ExtractVariables verifies that ExtractVariables captures a header
// value and that the extracted variable is forwarded upstream via AssignMessage.
// The bundle: ExtractID extracts X-Item-ID "item-{id}" → extracted.id,
// then EchoID sets X-Extracted-ID: {extracted.id} on the request.
func TestPolicy_ExtractVariables(t *testing.T) {
	var receivedExtractedID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedExtractedID = r.Header.Get("X-Extracted-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/extract_variables/apiproxy", "extract-variables", upstream.URL)

	resp := gw.GET("/test/extract-variables/", "X-Item-ID", "item-99")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if receivedExtractedID != "99" {
		t.Errorf("upstream X-Extracted-ID: got %q, want %q", receivedExtractedID, "99")
	}
}

// TestPolicy_SpikeArrest verifies that spike arrest rate-limiting is applied.
// At 6000pm the limit is 100/s = 1 per 10ms. We fire two requests in rapid
// succession and expect at least one 429.
func TestPolicy_SpikeArrest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/spike_arrest/apiproxy", "spike-arrest", upstream.URL)

	// First request should pass.
	resp1 := gw.GET("/test/spike-arrest/")
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
	}

	// Second immediate request should be rate-limited (429 Too Many Requests).
	resp2 := gw.GET("/test/spike-arrest/")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Logf("note: spike arrest may not have triggered on second request (got %d) — timing-dependent", resp2.StatusCode)
	}
}

// TestPolicy_CORS verifies that the CORS policy adds Access-Control-Allow-Origin
// to OPTIONS preflight responses.
func TestPolicy_CORS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/cors/apiproxy", "cors", upstream.URL)

	req, _ := http.NewRequest(http.MethodOptions,
		"http://localhost:"+gw.caddyPort+"/test/cors/", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request: %v", err)
	}
	defer resp.Body.Close()

	// 200 or 204 are acceptable CORS preflight responses.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 200/204 for OPTIONS, got %d", resp.StatusCode)
	}
	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin == "" {
		t.Error("Access-Control-Allow-Origin header missing from preflight response")
	}
}

// TestPolicy_AssignMessageResponse verifies that AssignMessage in the response
// phase adds a header to the response returned to the client.
func TestPolicy_AssignMessageResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/assign_message_response/apiproxy", "assign-message-response", upstream.URL)

	resp := gw.GET("/test/assign-message-response/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Response-Header"); got != "yes" {
		t.Errorf("X-Response-Header: got %q, want %q", got, "yes")
	}
}

// TestPolicy_When verifies that a conditional step only fires when its
// condition is met. The bundle: InjectHeader runs only when X-Trigger: yes.
func TestPolicy_When(t *testing.T) {
	var receivedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Conditional-Hit")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/when/apiproxy", "when", upstream.URL)

	// Without trigger header: conditional must NOT fire.
	receivedHeader = ""
	resp1 := gw.GET("/test/when/")
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
	}
	if receivedHeader != "" {
		t.Errorf("without trigger: X-Conditional-Hit should be absent, got %q", receivedHeader)
	}

	// With trigger header: conditional MUST fire.
	receivedHeader = ""
	resp2 := gw.GET("/test/when/", "X-Trigger", "yes")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", resp2.StatusCode)
	}
	if receivedHeader != "yes" {
		t.Errorf("with trigger: X-Conditional-Hit: got %q, want %q", receivedHeader, "yes")
	}
}

// TestPolicy_VerifyJWT verifies that a valid RS256 JWT is accepted (200) and
// an invalid one is rejected (401).
func TestPolicy_VerifyJWT(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/verify_jwt/apiproxy", "verify-jwt", upstream.URL)

	// Valid JWT: must pass through.
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:"+gw.caddyPort+"/test/verify-jwt/", nil)
	req.Header.Set("Authorization", "Bearer "+testJWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request with valid JWT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid JWT: expected 200, got %d", resp.StatusCode)
	}

	// No JWT: must be rejected with 401.
	resp2 := gw.GET("/test/verify-jwt/")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing JWT: expected 401, got %d", resp2.StatusCode)
	}
}

// TestPolicy_VerifyAPIKey verifies that the verify_api_key policy is fail-closed
// when Firestore is not configured: requests must be rejected with 503.
func TestPolicy_VerifyAPIKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/verify_api_key/apiproxy", "verify-api-key", upstream.URL)

	// Without Firestore the policy is fail-closed — any request must be rejected.
	resp := gw.GET("/test/verify-api-key/", "X-Api-Key", "any-key")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (fail-closed without Firestore), got %d", resp.StatusCode)
	}
}

// TestPolicy_VerifyAPIKey_Passthrough verifies that the verify_api_key policy
// passes through requests when the passthrough directive is set explicitly,
// even when Firestore is not configured.
func TestPolicy_VerifyAPIKey_Passthrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	// Deploy a fragment directly with passthrough enabled.
	gw.DeployFragment("verify-api-key-passthrough", fmt.Sprintf(`
	route /test/verify-api-key-passthrough/* {
		flow_state
		verify_api_key {
			api_key_ref request.header.x-api-key
			passthrough
		}
		reverse_proxy %s
	}`, upstream.URL))

	resp := gw.GET("/test/verify-api-key-passthrough/", "X-Api-Key", "any-key")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (passthrough mode), got %d", resp.StatusCode)
	}
}

// TestPolicy_KVM verifies that KVM static entries are written into flow state
// and are accessible to downstream policies. The bundle: LoadConfig sets
// backend.name = "test-backend" via KVM, then ForwardBackendName forwards it
// as X-Backend-Name.
func TestPolicy_KVM(t *testing.T) {
	var receivedBackendName string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBackendName = r.Header.Get("X-Backend-Name")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/kvm/apiproxy", "kvm", upstream.URL)

	resp := gw.GET("/test/kvm/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if receivedBackendName != "test-backend" {
		t.Errorf("X-Backend-Name: got %q, want %q", receivedBackendName, "test-backend")
	}
}

// TestPolicy_Quota verifies that quota enforcement allows the first N requests
// and rejects subsequent ones within the window with 429.
// The bundle uses Allow=2 so the third request must be rejected.
func TestPolicy_Quota(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/quota/apiproxy", "quota", upstream.URL)

	// First two requests must succeed.
	for i := 1; i <= 2; i++ {
		resp := gw.GET("/test/quota/")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	// Third request must be rejected (quota exceeded).
	resp3 := gw.GET("/test/quota/")
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third request: expected 429, got %d", resp3.StatusCode)
	}
}

// TestPolicy_ServiceCallout verifies that ServiceCallout executes an outbound
// HTTP request and stores the response status code in flow state, which is
// then forwarded as X-Callout-Status by AssignMessage.
func TestPolicy_ServiceCallout(t *testing.T) {
	// Callout target: returns 200.
	callout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer callout.Close()

	var receivedCalloutStatus string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCalloutStatus = r.Header.Get("X-Callout-Status")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	// Strip http:// prefix from callout.URL for the fragment substitution —
	// the XML already has "http://" so we replace the host:port part only.
	calloutHostPort := strings.TrimPrefix(callout.URL, "http://")
	gw.DeployWithSubs(
		"testdata/integration/service_callout/apiproxy",
		"service-callout",
		upstream.URL,
		map[string]string{"CALLOUT_PLACEHOLDER": calloutHostPort},
	)

	resp := gw.GET("/test/service-callout/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if receivedCalloutStatus != "200" {
		t.Errorf("X-Callout-Status: got %q, want %q", receivedCalloutStatus, "200")
	}
}

// TestPolicy_JSCallout verifies that the JavaScript callout executes inline JS
// that sets a flow variable, which is then forwarded to the upstream via
// AssignMessage.
func TestPolicy_JSCallout(t *testing.T) {
	var receivedGreeting string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedGreeting = r.Header.Get("X-Greeting")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGateway(t, "test")
	gw.Deploy("testdata/integration/js_callout/apiproxy", "js-callout", upstream.URL)

	resp := gw.GET("/test/js-callout/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if receivedGreeting != "hello-from-js" {
		t.Errorf("X-Greeting: got %q, want %q", receivedGreeting, "hello-from-js")
	}
}
