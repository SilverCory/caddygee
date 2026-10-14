package apigeecompat_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ---------------------------------------------------------------------------
// checkMemory (white-box via export)
// ---------------------------------------------------------------------------

func TestQuotaMemory_AllowsUpToLimit(t *testing.T) {
	q := apigeecompat.NewQuotaMemory(3, 60)
	for i := 0; i < 3; i++ {
		if exceeded := q.CheckMemory("user1", 3, 60); exceeded {
			t.Fatalf("request %d should be allowed, got exceeded=true", i+1)
		}
	}
}

func TestQuotaMemory_ExceedsAfterLimit(t *testing.T) {
	q := apigeecompat.NewQuotaMemory(2, 60)
	q.CheckMemory("u", 2, 60) // 1
	q.CheckMemory("u", 2, 60) // 2 — at limit
	exceeded := q.CheckMemory("u", 2, 60) // 3 — over limit
	if !exceeded {
		t.Error("expected exceeded=true on 3rd request with limit=2")
	}
}

func TestQuotaMemory_WindowReset(t *testing.T) {
	// Use a 1-nanosecond window so it expires immediately.
	q := apigeecompat.NewQuotaMemory(1, 0) // interval=0 → defaults to 60s in ServeHTTP, but checkMemory uses the arg
	// Check once to fill the "window" with interval=0 effectively meaning immediate expiry.
	// We call CheckMemory directly with intervalSecs=0 — a zero-second window resets every call.
	q.CheckMemory("u", 1, 0) // count=1, windowEnd=now+0

	// Tiny sleep to ensure time advances past the window end.
	time.Sleep(time.Millisecond)

	// Second check should start a fresh window: count=1, not exceeded.
	exceeded := q.CheckMemory("u", 1, 0)
	if exceeded {
		t.Error("expected exceeded=false after window reset")
	}
}

func TestQuotaMemory_PerKeyIsolation(t *testing.T) {
	q := apigeecompat.NewQuotaMemory(1, 60)
	// "userA" hits limit.
	q.CheckMemory("userA", 1, 60)
	exceededA := q.CheckMemory("userA", 1, 60)
	if !exceededA {
		t.Error("userA should be exceeded")
	}

	// "userB" is independent — first request must be allowed.
	exceededB := q.CheckMemory("userB", 1, 60)
	if exceededB {
		t.Error("userB should NOT be exceeded on first request")
	}
}

func TestQuotaMemory_EmptyIDGlobal(t *testing.T) {
	// An empty id counts against a global bucket.
	q := apigeecompat.NewQuotaMemory(1, 60)
	q.CheckMemory("", 1, 60) // 1st
	exceeded := q.CheckMemory("", 1, 60) // 2nd
	if !exceeded {
		t.Error("expected exceeded=true for empty-id global bucket on 2nd request")
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — integration through FlowStateManager
// ---------------------------------------------------------------------------

func TestQuota_ServeHTTP_AllowsUnderLimit(t *testing.T) {
	q := apigeecompat.NewQuotaMemory(5, 60)

	w := httptest.NewRecorder()
	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(w, req, wrapMiddleware(q, terminal))

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestQuota_ServeHTTP_Returns429WhenExceeded(t *testing.T) {
	q := apigeecompat.NewQuotaMemory(1, 60)

	mgr := apigeecompat.FlowStateManager{}

	// First request: allowed.
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = mgr.ServeHTTP(httptest.NewRecorder(), r1, wrapMiddleware(q, terminal))

	// Second request: exceeded.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w2, r2, wrapMiddleware(q, terminal))

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("status: got %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
}

func TestQuota_ServeHTTP_DynamicLimitFromFlowVar(t *testing.T) {
	// LimitRef overrides the static Allow at request time.
	// Build a quota with LimitRef and an in-memory bucket store.
	q := apigeecompat.NewQuotaWithLimitRef("my.quota.limit", "my.quota.interval")

	mgr := apigeecompat.FlowStateManager{}
	// Chain: FlowStateManager → varSettingHandler (sets flow vars) → Quota → terminal
	varHandler := &varSettingHandler{
		vars:  map[string]string{"my.quota.limit": "1", "my.quota.interval": "60"},
		inner: wrapMiddleware(q, terminal),
	}

	// First request: count=1, limit=1 → allowed.
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w1, r1, varHandler)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: got %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request: count=2, limit=1 → exceeded.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w2, r2, varHandler)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: got %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
}

// varSettingHandler is a test helper that sets flow vars then delegates to inner.
// It implements caddyhttp.Handler so it can be used directly as a `next` argument.
type varSettingHandler struct {
	vars  map[string]string
	inner caddyhttp.Handler
}

func (v *varSettingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if fs, ok := apigeecompat.GetFlowState(r.Context()); ok {
		for key, val := range v.vars {
			fs.Set(key, val)
		}
	}
	return v.inner.ServeHTTP(w, r)
}

func TestQuota_ServeHTTP_LimitRefMissing_Passthrough(t *testing.T) {
	// When LimitRef is set but the flow var is absent (resolves to ""),
	// limit stays <= 0 and the handler should pass through.
	q := apigeecompat.NewQuotaWithLimitRef("missing.var", "missing.interval")

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	_ = mgr.ServeHTTP(w, req, wrapMiddleware(q, terminal))
	if w.Code != http.StatusOK {
		t.Errorf("passthrough status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestQuota_ServeHTTP_NoFlowState_UsesGlobalBucket(t *testing.T) {
	// Without a FlowStateManager, identifierRef resolves to "".
	// The global bucket should still be tracked.
	q := apigeecompat.NewQuotaMemory(1, 60)

	// First request: allowed.
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = apigeecompat.FlowStateManager{}.ServeHTTP(httptest.NewRecorder(), r1, wrapMiddleware(q, terminal))

	// Second request: exceeded.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	_ = apigeecompat.FlowStateManager{}.ServeHTTP(w2, r2, wrapMiddleware(q, terminal))

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on 2nd global request, got %d", w2.Code)
	}
}

// ---------------------------------------------------------------------------
// sanitizeDocID
// ---------------------------------------------------------------------------

func TestSanitizeDocID_EmptyReturnsGlobal(t *testing.T) {
	if got := apigeecompat.SanitizeDocID(""); got != "_global_" {
		t.Errorf("got %q, want %q", got, "_global_")
	}
}

func TestSanitizeDocID_AlphanumericPassthrough(t *testing.T) {
	if got := apigeecompat.SanitizeDocID("abc123"); got != "abc123" {
		t.Errorf("got %q, want %q", got, "abc123")
	}
}

func TestSanitizeDocID_SpecialCharsReplaced(t *testing.T) {
	got := apigeecompat.SanitizeDocID("user@example.com")
	for _, r := range got {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			t.Errorf("unexpected character %q in sanitized docID %q", r, got)
		}
	}
}
