package apigeecompat

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(AssignMessage{})
	httpcaddyfile.RegisterHandlerDirective("assign_message", parseAssignMessageCaddyfile)
}

// AssignMessage is the assign_message Caddy module.
// It reads flow state variables and applies them to the HTTP request or response.
type AssignMessage struct {
	// SetHeaders maps header name → value. Values support {flowvar.X} substitution.
	SetHeaders map[string]string `json:"set_headers,omitempty"`
	// RemoveHeaders lists header names to remove.
	RemoveHeaders []string `json:"remove_headers,omitempty"`
	// AddHeaders maps header name → value to add (append, not replace).
	AddHeaders map[string]string `json:"add_headers,omitempty"`
	// SetBody replaces the request/response body. Supports {flowvar.X} substitution.
	SetBody string `json:"set_body,omitempty"`
	// Phase is "request" (default) or "response".
	Phase string `json:"phase,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (AssignMessage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.assign_message",
		New: func() caddy.Module { return new(AssignMessage) },
	}
}

// Provision validates and sets defaults.
func (a *AssignMessage) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.Phase == "" {
		a.Phase = "request"
	}
	if a.Phase != "request" && a.Phase != "response" {
		return fmt.Errorf("assign_message: phase must be 'request' or 'response', got %q", a.Phase)
	}
	return nil
}

// ServeHTTP applies mutations to the request or response.
func (a AssignMessage) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, _ := GetFlowState(r.Context()) // nil-safe: resolve functions check for nil

	debugLog(r, a.logger, "assign_message",
		zap.String("phase", a.Phase),
		zap.Any("set_headers", a.SetHeaders),
		zap.Strings("remove_headers", a.RemoveHeaders),
		zap.Any("add_headers", a.AddHeaders),
	)

	if a.Phase == "request" {
		a.applyToRequest(r, fs)
		return next.ServeHTTP(w, r)
	}

	// Response phase: wrap the ResponseWriter to intercept the response.
	rec := newResponseRecorder(w)
	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}
	a.applyToResponse(rec, fs)
	return rec.flush()
}

func (a AssignMessage) applyToRequest(r *http.Request, fs *FlowState) {
	for name, val := range a.SetHeaders {
		r.Header.Set(name, resolveValue(val, fs))
	}
	for name, val := range a.AddHeaders {
		r.Header.Add(name, resolveValue(val, fs))
	}
	for _, name := range a.RemoveHeaders {
		r.Header.Del(name)
	}
	if a.SetBody != "" {
		body := resolveValue(a.SetBody, fs)
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
	}
}

func (a AssignMessage) applyToResponse(rec *responseRecorder, fs *FlowState) {
	for name, val := range a.SetHeaders {
		rec.Header().Set(name, resolveValue(val, fs))
	}
	for name, val := range a.AddHeaders {
		rec.Header().Add(name, resolveValue(val, fs))
	}
	for _, name := range a.RemoveHeaders {
		rec.Header().Del(name)
	}
	if a.SetBody != "" {
		rec.body.Reset()
		rec.body.WriteString(resolveValue(a.SetBody, fs))
	}
}

// resolveValue substitutes {flowvar.X} placeholders. Safe when fs is nil.
func resolveValue(s string, fs *FlowState) string {
	if fs == nil || !strings.Contains(s, "{flowvar.") {
		return s
	}
	return resolveFlowVars(s, fs)
}

// responseRecorder buffers a response so the assign_message module can mutate it.
type responseRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w}
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// flush writes the buffered status and body to the real ResponseWriter.
func (r *responseRecorder) flush() error {
	// Always write a status — default to 200 OK when none was recorded.
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	r.ResponseWriter.WriteHeader(status)
	_, err := r.ResponseWriter.Write(r.body.Bytes())
	return err
}

// Flush forwards flush calls to the underlying ResponseWriter if it supports it.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func parseAssignMessageCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a AssignMessage
	for h.Next() {
		// First arg is the policy name (informational).
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "phase":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				a.Phase = h.Val()
			case "set_header":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				name := h.Val()
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if a.SetHeaders == nil {
					a.SetHeaders = make(map[string]string)
				}
				a.SetHeaders[name] = h.Val()
			case "remove_header":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				a.RemoveHeaders = append(a.RemoveHeaders, h.Val())
			case "add_header":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				name := h.Val()
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if a.AddHeaders == nil {
					a.AddHeaders = make(map[string]string)
				}
				a.AddHeaders[name] = h.Val()
			case "set_body":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				a.SetBody = h.Val()
			}
		}
	}
	return &a, nil
}

// Interface guards.
var (
	_ caddy.Module                = AssignMessage{}
	_ caddy.Provisioner           = (*AssignMessage)(nil)
	_ caddyhttp.MiddlewareHandler = AssignMessage{}
	_ caddyfile.Unmarshaler       = (*AssignMessage)(nil)
)

// UnmarshalCaddyfile satisfies the interface (parsing is handled by the directive helper).
func (a *AssignMessage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
