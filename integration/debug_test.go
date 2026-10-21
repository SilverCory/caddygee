//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testDebugSigningKey = "integration-test-signing-key"

// TestDebugToken_IssueAndUse verifies the full token lifecycle on a live gateway:
//  1. POST /debug-token returns a valid token
//  2. A request carrying the token in X-Apigee-Debug passes through normally (200)
//  3. A request carrying a tampered token also passes through (debug silently disabled)
//  4. A request with no token passes through (no debug)
func TestDebugToken_IssueAndUse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGatewayWithOpts(t, "test", []string{
		"DEBUG_SIGNING_KEY=" + testDebugSigningKey,
	})
	gw.Deploy("testdata/integration/assign_message/apiproxy", "debug-issue-test", upstream.URL)

	t.Run("issue token returns valid format", func(t *testing.T) {
		token := gw.IssueDebugToken()
		// Format: <id>.<b64url(sub)>.<hmac> — three dot-separated segments.
		parts := strings.SplitN(token, ".", 3)
		if len(parts) != 3 {
			t.Fatalf("expected token with 3 dot-separated parts, got %q (parts: %d)", token, len(parts))
		}
		for i, p := range parts {
			if p == "" {
				t.Errorf("token segment %d is empty in token %q", i, token)
			}
		}
		t.Logf("issued token: %s", token)
	})

	t.Run("request with valid debug token returns 200", func(t *testing.T) {
		token := gw.IssueDebugToken()
		resp := gw.GET("/test/assign-message/", "X-Apigee-Debug", token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 with valid debug token, got %d", resp.StatusCode)
		}
	})

	t.Run("request with tampered token still returns 200 (debug silently disabled)", func(t *testing.T) {
		// A tampered HMAC means debug mode is not activated — but the request
		// passes through normally, just without debug logging.
		resp := gw.GET("/test/assign-message/", "X-Apigee-Debug", "FAKEID.FAKESUB.FAKEHMAC")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 with tampered debug token, got %d", resp.StatusCode)
		}
	})

	t.Run("request with no debug token returns 200", func(t *testing.T) {
		resp := gw.GET("/test/assign-message/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 without debug token, got %d", resp.StatusCode)
		}
	})

	t.Run("debug-token endpoint disabled when signing key not set", func(t *testing.T) {
		// Use a gateway started without DEBUG_SIGNING_KEY.
		gwNoKey := startGateway(t, "test")
		req, _ := http.NewRequest(http.MethodPost,
			"http://localhost:"+gwNoKey.deployPort+"/debug-token", nil)
		req.Header.Set("Authorization", "Bearer "+gwNoKey.projectID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /debug-token: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("expected 503 when DEBUG_SIGNING_KEY not set, got %d", resp.StatusCode)
		}
	})
}

// TestDebugToken_E2EWithDebugLogging verifies the full end-to-end debug flow:
//  1. Deploy a service with an upstream
//  2. Issue a debug token from the gateway
//  3. Send a request carrying the token — assert Caddy emits a debug log line
//     tagged with the token's ID (debug_id field)
//  4. Send the same request without the token — no debug_id line emitted
func TestDebugToken_E2EWithDebugLogging(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gw := startGatewayWithOpts(t, "test", []string{
		"DEBUG_SIGNING_KEY=" + testDebugSigningKey,
		"CADDY_LOG_LEVEL=DEBUG", // enable debug-level logs so debugLog lines are emitted
	})
	gw.Deploy("testdata/integration/assign_message/apiproxy", "debug-e2e", upstream.URL)

	token := gw.IssueDebugToken()
	// The token ID is the first segment.
	tokenID := token[:strings.IndexByte(token, '.')]
	t.Logf("using debug token id=%s", tokenID)

	t.Run("debug log line with debug_id emitted for request with valid token", func(t *testing.T) {
		// Watch for a log line that contains BOTH "debug_id" (field name from debugLog)
		// AND the specific token ID. Register before the request to avoid races.
		debugLineCh := gw.caddyLog.Watch(`"debug_id":"` + tokenID + `"`)

		resp := gw.GET("/test/assign-message/", "X-Apigee-Debug", token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		select {
		case line := <-debugLineCh:
			t.Logf("found debug log line: %s", line)
			if !strings.Contains(line, `"debug_sub"`) {
				t.Errorf("debug log line missing debug_sub field: %s", line)
			}
		case <-time.After(3 * time.Second):
			t.Error("timeout waiting for debug log line with debug_id — debug logging did not fire")
		}
	})

	t.Run("no debug_id log line emitted for request without token", func(t *testing.T) {
		// Watch specifically for a line containing the debug_id field with our token ID.
		// This should NOT fire for an unauthenticated request.
		noDebugCh := gw.caddyLog.Watch(`"debug_id":"` + tokenID + `"`)

		resp := gw.GET("/test/assign-message/")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		// Allow a short window for stray log lines.
		select {
		case line := <-noDebugCh:
			t.Errorf("unexpected debug log line without token: %s", line)
		case <-time.After(500 * time.Millisecond):
			// Good — no debug_id line fired.
		}
	})
}
