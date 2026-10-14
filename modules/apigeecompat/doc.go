// Package apigeecompat provides custom Caddy HTTP middleware modules that
// replicate Apigee's "Flow Variables" execution model, enabling migration of
// Apigee API proxy bundles to Caddy.
//
// Modules registered by this package:
//
//   - http.handlers.apigee_state        — initialises per-request flow state
//   - http.handlers.apigee_service_callout — executes a synchronous HTTP callout
//   - http.handlers.apigee_assign_message  — mutates request/response headers and body
//
// To register all modules, add a blank import to your main package or xcaddy shim:
//
//	import _ "caddygee/modules/apigeecompat"
package apigeecompat
