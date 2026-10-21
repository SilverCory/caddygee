package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
)

var testSigningKey = []byte("test-signing-key")

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
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithSigningKey(testSigningKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", token)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if !gotDebug {
		t.Error("expected IsDebug=true when X-Apigee-Debug header has valid token")
	}
}

func TestIsDebug_NotSetWhenTokenWrongHMAC(t *testing.T) {
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	// Tamper with the HMAC portion (last segment).
	parts := splitDots(token)
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithSigningKey(testSigningKey)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", tampered)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when HMAC is wrong")
	}
}

func TestIsDebug_NotSetWhenNoSigningKey(t *testing.T) {
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithSigningKey(nil) // no key = disabled
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", token)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when no signing key is configured")
	}
}

func TestIsDebug_SetByQueryParamViaFlowStateManager(t *testing.T) {
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithSigningKey(testSigningKey)
	req := httptest.NewRequest(http.MethodGet, "/?_debug="+token, nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if !gotDebug {
		t.Error("expected IsDebug=true when ?_debug= query param has valid token")
	}
}

func TestIsDebug_NotSetWhenNoHeaderOrParam(t *testing.T) {
	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithSigningKey(testSigningKey)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when no debug header or param")
	}
}

func TestIsDebug_NotSetWhenTokenIDBlocked(t *testing.T) {
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	id, _, ok := apigeecompat.VerifyDebugToken(testSigningKey, token)
	if !ok {
		t.Fatal("VerifyDebugToken failed for freshly issued token")
	}

	var gotDebug bool
	next := makeCapturingHandler(func(r *http.Request) {
		gotDebug = apigeecompat.IsDebug(r)
	})

	mgr := apigeecompat.NewFlowStateManagerWithBlocklist(testSigningKey, []string{id})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Apigee-Debug", token)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), req, next)

	if gotDebug {
		t.Error("expected IsDebug=false when token ID is in blocklist")
	}
}

func TestVerifyDebugToken_RoundTrip(t *testing.T) {
	sub := "123456789@project.iam.gserviceaccount.com"
	token, err := apigeecompat.IssueDebugToken(testSigningKey, sub)
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	id, gotSub, ok := apigeecompat.VerifyDebugToken(testSigningKey, token)
	if !ok {
		t.Fatal("VerifyDebugToken returned ok=false for valid token")
	}
	if id == "" {
		t.Error("expected non-empty id")
	}
	if gotSub != sub {
		t.Errorf("sub mismatch: got %q want %q", gotSub, sub)
	}
}

func TestVerifyDebugToken_WrongKey(t *testing.T) {
	token, err := apigeecompat.IssueDebugToken(testSigningKey, "user@example.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("IssueDebugToken: %v", err)
	}
	_, _, ok := apigeecompat.VerifyDebugToken([]byte("different-key"), token)
	if ok {
		t.Error("expected VerifyDebugToken=false with wrong signing key")
	}
}

// splitDots splits a token string on "." into exactly 3 parts.
func splitDots(s string) [3]string {
	var out [3]string
	i := 0
	for part := range splitN(s, ".", 3) {
		out[i] = part
		i++
	}
	return out
}

func splitN(s, sep string, n int) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		count := 0
		for count < n-1 {
			idx := -1
			for j := 0; j < len(s); j++ {
				if s[j] == sep[0] {
					idx = j
					break
				}
			}
			if idx < 0 {
				break
			}
			if !yield(s[:idx]) {
				return
			}
			s = s[idx+1:]
			count++
		}
		yield(s)
	}
}
