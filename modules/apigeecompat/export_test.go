// export_test.go exposes internal helpers for use in external (_test) test packages.
package apigeecompat

import (
	"context"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/oauth2"
)

// ZeroContext returns a zero-value caddy.Context for use in unit tests where
// a full Caddy context is not needed (e.g. testing Provision with no side effects).
func ZeroContext() caddy.Context {
	return caddy.Context{}
}

// Client returns the shared *http.Client stored on the ServiceCallout.
// It is used by tests to verify that C1 (client reuse) is working.
func (s *ServiceCallout) Client() *http.Client {
	return s.client
}

// NewFlowStateManagerWithEnv creates a FlowStateManager pre-seeded with envName.
// Used by tests to inject an environment name without going through os.Setenv.
func NewFlowStateManagerWithEnv(envName string) FlowStateManager {
	return FlowStateManager{envName: envName}
}

// NewFlowStateManagerWithSigningKey creates a FlowStateManager pre-seeded with
// an HMAC signing key. Used by tests to verify token-gated debug mode.
func NewFlowStateManagerWithSigningKey(key []byte) FlowStateManager {
	return FlowStateManager{signingKey: key}
}

// NewFlowStateManagerWithBlocklist creates a FlowStateManager pre-seeded with
// a signing key and a static blocklist of token IDs.
func NewFlowStateManagerWithBlocklist(key []byte, blocklist []string) FlowStateManager {
	bl := make(map[string]struct{}, len(blocklist))
	for _, id := range blocklist {
		bl[id] = struct{}{}
	}
	return FlowStateManager{signingKey: key, staticBlocklist: bl}
}

// VerifyDebugToken exposes verifyDebugToken for use in tests.
func VerifyDebugToken(signingKey []byte, token string) (id, sub string, ok bool) {
	return verifyDebugToken(signingKey, token)
}

// MatchPattern exposes matchPattern for white-box unit tests.
func MatchPattern(pattern, s string) map[string]string {
	return matchPattern(pattern, s)
}

// EvalCondition exposes evalCondition for white-box unit tests.
func EvalCondition(expr string, r *http.Request, fs *FlowState) bool {
	return evalCondition(expr, r, fs)
}

// IsDebug exposes isDebug for white-box unit tests.
func IsDebug(r *http.Request) bool {
	return isDebug(r)
}

// WithDebug exposes withDebug so tests can construct a debug request context.
func WithDebugRequest(r *http.Request) *http.Request {
	return r.WithContext(withDebug(r.Context()))
}

// SanitizeDocID exposes sanitizeDocID for white-box unit tests.
func SanitizeDocID(s string) string {
	return sanitizeDocID(s)
}

// NewQuotaMemory creates a Quota configured for in-memory use (no Firestore),
// pre-initialised for use in unit tests without going through Caddy's Provision.
func NewQuotaMemory(allow, interval int) *Quota {
	return &Quota{
		Allow:    allow,
		Interval: interval,
		buckets:  make(map[string]*quotaBucket),
	}
}

// CheckMemory exposes Quota.checkMemory for direct unit testing.
func (q *Quota) CheckMemory(id string, limit, intervalSecs int) bool {
	return q.checkMemory(id, limit, intervalSecs)
}

// NewTTLCacheString creates a ttlCache[string] with the given TTL for testing.
func NewTTLCacheString(ttl time.Duration) *ttlCache[string] {
	return newTTLCache[string](ttl)
}

// NewQuotaWithLimitRef creates a Quota configured for in-memory use with
// LimitRef and IntervalRef support, for dynamic-limit unit tests.
func NewQuotaWithLimitRef(limitRef, intervalRef string) *Quota {
	return &Quota{
		LimitRef:    limitRef,
		IntervalRef: intervalRef,
		buckets:     make(map[string]*quotaBucket),
	}
}

// SetGoogleIDTokenValidate replaces the package-level token validation function
// for use in unit tests. Returns a cleanup function that restores the original.
func SetGoogleIDTokenValidate(fn func(ctx context.Context, token, audience string) (email, sub, hd string, err error)) func() {
	orig := googleIDTokenValidate
	googleIDTokenValidate = fn
	return func() { googleIDTokenValidate = orig }
}

// SetServiceCalloutTokenSource injects a fixed token source into a ServiceCallout
// for unit tests, bypassing idtoken.NewTokenSource in Provision.
func (s *ServiceCallout) SetTokenSource(ts oauth2.TokenSource) {
	s.tokenSource = ts
}
