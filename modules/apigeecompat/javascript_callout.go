package apigeecompat

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JavaScriptCallout{})
	httpcaddyfile.RegisterHandlerDirective("js_callout", parseJavaScriptCalloutCaddyfile)
}

// JavaScriptCallout is the js_callout Caddy module.
// It executes an inline JavaScript snippet that can read and write Apigee
// flow variables via the context.getVariable / context.setVariable API.
//
// The JS runtime is goja (pure-Go ECMAScript 5.1). goja.Runtime is not
// goroutine-safe, so a sync.Pool of runtimes is used — one per concurrent
// request. The script source is compiled once at Provision time into a
// *goja.Program that is shared (read-only) across all pool runtimes.
//
// If LibDir is set, all .js files in that directory are compiled and run in
// each new runtime before it enters the pool. This pre-populates shared
// utility functions and variables that the main script can call.
type JavaScriptCallout struct {
	// Source is the inline JavaScript source to execute.
	Source string `json:"source"`
	// TimeoutMs is the maximum script execution time in milliseconds (default: 200).
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// LibDir is an optional path to a directory of .js files that are loaded
	// into every runtime at creation time, providing shared utility functions.
	LibDir string `json:"lib_dir,omitempty"`

	program  *goja.Program   // compiled once at Provision; read-only afterwards
	libProgs []*goja.Program // library programs run in each new runtime
	pool     sync.Pool       // pool of *goja.Runtime
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (JavaScriptCallout) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.js_callout",
		New: func() caddy.Module { return new(JavaScriptCallout) },
	}
}

// Provision compiles the script source, loads library files, and initialises the runtime pool.
func (j *JavaScriptCallout) Provision(ctx caddy.Context) error {
	j.logger = ctx.Logger()
	if j.Source == "" {
		return fmt.Errorf("js_callout: source is required")
	}
	if j.TimeoutMs <= 0 {
		j.TimeoutMs = 200
	}
	prog, err := goja.Compile("apigee_script", j.Source, false)
	if err != nil {
		return fmt.Errorf("js_callout: compile error: %w", err)
	}
	j.program = prog

	if j.LibDir != "" {
		libProgs, err := compileLibDir(j.LibDir)
		if err != nil {
			return fmt.Errorf("js_callout: lib_dir: %w", err)
		}
		j.libProgs = libProgs
	}

	libProgs := j.libProgs // capture for closure
	j.pool = sync.Pool{
		New: func() any {
			vm := goja.New()
			for _, lp := range libProgs {
				if _, err := vm.RunProgram(lp); err != nil {
					// Library errors at runtime are not actionable here;
					// they will surface when the main script tries to call
					// the missing function. Log nothing — keep pool.New simple.
					_ = err
				}
			}
			return vm
		},
	}
	return nil
}

// compileLibDir reads all .js files from dir (sorted by name) and compiles
// each to a *goja.Program. Returns error if the directory can't be read or
// any file fails to compile.
func compileLibDir(dir string) ([]*goja.Program, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", dir, err)
	}

	var progs []*goja.Program
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".js") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic load order

	for _, name := range names {
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", name, err)
		}
		prog, err := goja.Compile(name, string(src), false)
		if err != nil {
			return nil, fmt.Errorf("compiling %q: %w", name, err)
		}
		progs = append(progs, prog)
	}
	return progs, nil
}

// ServeHTTP executes the compiled script and then calls the next handler.
func (j *JavaScriptCallout) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, ok := GetFlowState(r.Context())
	if !ok {
		// flow_state was not in the chain — skip execution and continue.
		return next.ServeHTTP(w, r)
	}

	vm := j.pool.Get().(*goja.Runtime)
	defer func() {
		// Clear interrupt state and the context binding before returning to pool,
		// preventing leakage between requests.
		vm.ClearInterrupt()
		vm.GlobalObject().Delete("context")
		j.pool.Put(vm)
	}()

	// Build the Apigee-compatible context object backed by the request's FlowState.
	ctx := vm.NewObject()
	if err := ctx.Set("getVariable", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		val := fs.GetString(name)
		if val == "" {
			return goja.Null()
		}
		return vm.ToValue(val)
	}); err != nil {
		return fmt.Errorf("js_callout: setting getVariable: %w", err)
	}
	if err := ctx.Set("setVariable", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		val := call.Argument(1).Export()
		fs.Set(name, val)
		return goja.Undefined()
	}); err != nil {
		return fmt.Errorf("js_callout: setting setVariable: %w", err)
	}
	if err := ctx.Set("flow", "PROXY_REQ_FLOW"); err != nil {
		return fmt.Errorf("js_callout: setting flow: %w", err)
	}

	// Expose request metadata on context for convenience.
	if err := ctx.Set("requestMethod", r.Method); err != nil {
		return fmt.Errorf("js_callout: setting requestMethod: %w", err)
	}
	if err := ctx.Set("requestPath", r.URL.Path); err != nil {
		return fmt.Errorf("js_callout: setting requestPath: %w", err)
	}
	if err := ctx.Set("requestHost", r.Host); err != nil {
		return fmt.Errorf("js_callout: setting requestHost: %w", err)
	}

	// Build a read-only headers map: context.requestHeaders["Header-Name"] -> first value.
	hdrs := vm.NewObject()
	for name, vals := range r.Header {
		if len(vals) > 0 {
			if err := hdrs.Set(name, vals[0]); err != nil {
				return fmt.Errorf("js_callout: setting header %q: %w", name, err)
			}
		}
	}
	if err := ctx.Set("requestHeaders", hdrs); err != nil {
		return fmt.Errorf("js_callout: setting requestHeaders: %w", err)
	}

	// Build a query params map: context.queryParams["param"] -> first value.
	qp := vm.NewObject()
	for name, vals := range r.URL.Query() {
		if len(vals) > 0 {
			if err := qp.Set(name, vals[0]); err != nil {
				return fmt.Errorf("js_callout: setting query param %q: %w", name, err)
			}
		}
	}
	if err := ctx.Set("queryParams", qp); err != nil {
		return fmt.Errorf("js_callout: setting queryParams: %w", err)
	}

	if err := vm.Set("context", ctx); err != nil {
		return fmt.Errorf("js_callout: setting context: %w", err)
	}

	debugLog(r, j.logger, "js_callout: executing",
		zap.Int("timeout_ms", j.TimeoutMs),
	)

	// Run the script in a separate goroutine so we can interrupt it on timeout.
	// goja.Runtime.Interrupt() is safe to call from a different goroutine.
	done := make(chan error, 1)
	go func() {
		_, err := vm.RunProgram(j.program)
		done <- err
	}()

	timeout := time.Duration(j.TimeoutMs) * time.Millisecond
	select {
	case err := <-done:
		if err != nil {
			debugLog(r, j.logger, "js_callout: script error",
				zap.Error(err),
			)
			return fmt.Errorf("js_callout: script error: %w", err)
		}
		debugLog(r, j.logger, "js_callout: script completed")
	case <-time.After(timeout):
		vm.Interrupt(fmt.Errorf("script exceeded timeout of %dms", j.TimeoutMs))
		<-done // drain the goroutine
		debugLog(r, j.logger, "js_callout: script timed out",
			zap.Int("timeout_ms", j.TimeoutMs),
		)
		return fmt.Errorf("js_callout: script timed out after %dms", j.TimeoutMs)
	}

	return next.ServeHTTP(w, r)
}

func parseJavaScriptCalloutCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var j JavaScriptCallout
	for h.Next() {
		// First arg is the policy name (informational).
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "source":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				j.Source = h.Val()
			case "timeout_ms":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if _, err := fmt.Sscanf(h.Val(), "%d", &j.TimeoutMs); err != nil {
					return nil, h.Errf("invalid timeout_ms value %q: %v", h.Val(), err)
				}
			case "lib_dir":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				j.LibDir = h.Val()
			}
		}
	}
	return &j, nil
}

// Interface guards.
var (
	_ caddy.Module                = JavaScriptCallout{}
	_ caddy.Provisioner           = (*JavaScriptCallout)(nil)
	_ caddyhttp.MiddlewareHandler = (*JavaScriptCallout)(nil)
	_ caddyfile.Unmarshaler       = (*JavaScriptCallout)(nil)
)

// UnmarshalCaddyfile satisfies the interface (parsing handled by the directive helper).
func (j *JavaScriptCallout) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
