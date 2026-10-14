package apigeecompat

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(SpikeArrest))
	httpcaddyfile.RegisterHandlerDirective("spike_arrest", parseSpikeArrestCaddyfile)
}

// SpikeArrest is the spike_arrest Caddy module.
// It implements per-server rate limiting using a token bucket algorithm,
// equivalent to Apigee's SpikeArrest policy. Excess requests are rejected
// with 429 Too Many Requests.
type SpikeArrest struct {
	// Rate is the allowed rate, e.g. "30ps" (30 per second) or "10pm" (10 per minute).
	Rate string `json:"rate"`

	// Parsed fields.
	count    int
	interval time.Duration
	logger   *zap.Logger

	mu          sync.Mutex
	tokens      float64
	lastRefill  time.Time
}

// CaddyModule returns the Caddy module metadata.
func (*SpikeArrest) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.spike_arrest",
		New: func() caddy.Module { return new(SpikeArrest) },
	}
}

// Provision parses the rate string and initialises the token bucket.
func (sa *SpikeArrest) Provision(ctx caddy.Context) error {
	sa.logger = ctx.Logger()

	if sa.Rate == "" {
		return fmt.Errorf("spike_arrest: rate is required")
	}

	rate := strings.TrimSpace(strings.ToLower(sa.Rate))
	if strings.HasSuffix(rate, "ps") {
		n, err := strconv.Atoi(strings.TrimSuffix(rate, "ps"))
		if err != nil || n <= 0 {
			return fmt.Errorf("spike_arrest: invalid rate %q", sa.Rate)
		}
		sa.count = n
		sa.interval = time.Second
	} else if strings.HasSuffix(rate, "pm") {
		n, err := strconv.Atoi(strings.TrimSuffix(rate, "pm"))
		if err != nil || n <= 0 {
			return fmt.Errorf("spike_arrest: invalid rate %q", sa.Rate)
		}
		sa.count = n
		sa.interval = time.Minute
	} else {
		return fmt.Errorf("spike_arrest: rate must end with 'ps' or 'pm', got %q", sa.Rate)
	}

	sa.tokens = float64(sa.count)
	sa.lastRefill = time.Now()

	sa.logger.Info("spike_arrest configured",
		zap.String("rate", sa.Rate),
		zap.Int("count", sa.count),
		zap.Duration("interval", sa.interval))

	return nil
}

// ServeHTTP checks the rate limit and either passes the request through or
// returns 429 Too Many Requests.
func (sa *SpikeArrest) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	sa.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(sa.lastRefill)
	// Refill tokens based on elapsed time.
	refill := elapsed.Seconds() / sa.interval.Seconds() * float64(sa.count)
	sa.tokens += refill
	if sa.tokens > float64(sa.count) {
		sa.tokens = float64(sa.count)
	}
	sa.lastRefill = now

	if sa.tokens < 1 {
		sa.mu.Unlock()
		debugLog(r, sa.logger, "spike_arrest: rejected",
			zap.String("rate", sa.Rate),
		)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"fault":{"faultstring":"Spike arrest violation","detail":{"errorcode":"policies.ratelimit.SpikeArrestViolation"}}}`)
		return nil
	}

	sa.tokens--
	sa.mu.Unlock()

	debugLog(r, sa.logger, "spike_arrest: allowed",
		zap.String("rate", sa.Rate),
	)
	return next.ServeHTTP(w, r)
}

func parseSpikeArrestCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var sa SpikeArrest
	for h.Next() {
		args := h.RemainingArgs()
		if len(args) == 1 {
			sa.Rate = args[0]
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "rate":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				sa.Rate = h.Val()
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	if sa.Rate == "" {
		return nil, fmt.Errorf("spike_arrest: rate is required")
	}
	return &sa, nil
}

// Interface guards.
var (
	_ caddy.Module                = (*SpikeArrest)(nil)
	_ caddy.Provisioner           = (*SpikeArrest)(nil)
	_ caddyhttp.MiddlewareHandler = (*SpikeArrest)(nil)
	_ caddyfile.Unmarshaler       = (*SpikeArrest)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (sa *SpikeArrest) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
