// Package apigeecompat provides custom Caddy HTTP middleware modules that
// replicate Apigee's "Flow Variables" execution model, enabling migration of
// Apigee API proxy bundles to Caddy.
//
// Modules registered by this package:
//
//   - http.handlers.flow_state      (flow_state)      — initialises per-request flow state
//   - http.handlers.when            (when)             — evaluates an Apigee condition, runs inner handler
//   - http.handlers.assign_message  (assign_message)   — mutates request/response headers and body
//   - http.handlers.raise_fault     (raise_fault)      — short-circuits with a fixed error response
//   - http.handlers.google_auth     (google_auth)      — injects Google OIDC ID Token as Bearer
//   - http.handlers.verify_jwt      (verify_jwt)       — validates RS256/RS512 Bearer JWT
//   - http.handlers.js_callout      (js_callout)       — executes inline JavaScript against flow variables
//   - http.handlers.service_callout (service_callout)  — synchronous HTTP sub-request
//   - http.handlers.spike_arrest    (spike_arrest)     — token-bucket rate limiting
//   - http.handlers.cors            (cors)             — CORS headers and OPTIONS preflight
//   - http.handlers.verify_api_key  (verify_api_key)   — API key validation via Firestore
//   - http.handlers.extract_vars    (extract_vars)     — extract request values into flow variables
//   - http.handlers.quota           (quota)            — per-key quota enforcement
//   - http.handlers.kvm             (kvm)              — Key-Value Map: static entries + live Firestore
//
// To register all modules, add a blank import to your main package or xcaddy shim:
//
//	import _ "caddygee/modules/apigeecompat"
package apigeecompat
