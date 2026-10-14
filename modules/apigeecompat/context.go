// Package apigeecompat provides custom Caddy HTTP middleware modules that
// replicate Apigee's "Flow Variables" execution model.
//
// Use a blank import to register all modules:
//
//	import _ "caddygee/modules/apigeecompat"
package apigeecompat

import (
	"context"
	"sync"
)

// contextKey is an unexported type for context keys in this package.
// Using a distinct type prevents collisions with keys from other packages.
type contextKey string

const flowStateKey contextKey = "apigee_flow_state"

// FlowState is a concurrency-safe map of Apigee flow variables.
// All custom modules read and write variables through this struct.
type FlowState struct {
	mu   sync.RWMutex
	vars map[string]interface{}
}

// Get retrieves a flow variable by name. Returns nil if not found.
func (s *FlowState) Get(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vars[key]
}

// GetString retrieves a flow variable as a string. Returns "" if not found or not a string.
func (s *FlowState) GetString(key string) string {
	v := s.Get(key)
	if v == nil {
		return ""
	}
	str, _ := v.(string)
	return str
}

// Set stores a flow variable by name.
func (s *FlowState) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vars[key] = value
}

// GetFlowState retrieves the FlowState from a request context.
// Returns nil, false if not present (apigee_state middleware was not in the chain).
func GetFlowState(ctx context.Context) (*FlowState, bool) {
	fs, ok := ctx.Value(flowStateKey).(*FlowState)
	return fs, ok
}
