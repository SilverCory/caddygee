// export_test.go exposes internal helpers for use in external (_test) test packages.
package apigeecompat

import (
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
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

// NewFlowStateManagerWithDebugToken creates a FlowStateManager pre-seeded with
// a debug token. Used by tests to verify token-gated debug mode.
func NewFlowStateManagerWithDebugToken(token string) FlowStateManager {
	return FlowStateManager{debugToken: token}
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
