package apigeecompat_test

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// terminal is a caddyhttp.Handler that writes nothing and returns nil.
var terminal caddyhttp.Handler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	return nil
})

// captureNext wraps a MiddlewareHandler + next terminal for use as a caddyhttp.Handler.
func wrapMiddleware(mw caddyhttp.MiddlewareHandler, next caddyhttp.Handler) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return mw.ServeHTTP(w, r, next)
	})
}
