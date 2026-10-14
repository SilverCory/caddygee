// export_test.go exposes internal helpers for use in external (_test) test packages.
package apigeecompat

import (
	"net/http"

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
