package apigeecompat

import (
	"context"
	"net/http"

	"go.uber.org/zap"
)

// debugContextKey is the context key for the per-request debug flag.
type debugContextKey struct{}

// withDebug returns a copy of ctx with the debug flag set to enabled.
func withDebug(ctx context.Context) context.Context {
	return context.WithValue(ctx, debugContextKey{}, true)
}

// isDebug reports whether the request has the debug flag set.
// Debug mode is activated by:
//   - Header:      X-Apigee-Debug: 1  (or any non-empty value)
//   - Query param: ?_debug=1           (or any non-empty value)
//
// The flag is set by apigee_state on every request so all downstream handlers
// can check it without re-inspecting the request.
func isDebug(r *http.Request) bool {
	v, ok := r.Context().Value(debugContextKey{}).(bool)
	return ok && v
}

// debugLog emits a DEBUG-level log line only when the request has debug mode
// enabled. It is a no-op on normal requests, so it is safe to call on every
// request without impacting production performance.
func debugLog(r *http.Request, logger *zap.Logger, msg string, fields ...zap.Field) {
	if logger == nil || !isDebug(r) {
		return
	}
	logger.Debug(msg, fields...)
}
