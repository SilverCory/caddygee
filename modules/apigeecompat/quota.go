package apigeecompat

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func init() {
	caddy.RegisterModule(Quota{})
	httpcaddyfile.RegisterHandlerDirective("apigee_quota", parseQuotaCaddyfile)
}

// Quota is the apigee_quota Caddy module.
// It implements per-key quota enforcement using a sliding window counter.
//
// When the apigee_firestore app is configured, the counter is stored in Firestore
// for distributed enforcement across multiple replicas. Without Firestore, it
// falls back to an in-memory per-process counter.
//
// The identifier is resolved from a flow variable at request time. Each unique
// identifier gets its own counter. When the quota is exceeded, returns 429.
//
// Firestore document structure (collection: "quotas"):
//
//	Document ID: <identifier>_<window_key>
//	{
//	    "count":      42,
//	    "window_end": <timestamp>
//	}
//
// The allow/interval values can also be read from flow variables set by
// apigee_verify_api_key (verifyapikey.<policy>.apiproduct.developer.quota.*).
// When IdentifierRef is "identifier", the value of the "identifier" flow variable is used.
type Quota struct {
	// Allow is the maximum number of requests allowed per interval.
	// If zero and LimitRef is set, the limit is read from a flow variable at request time.
	Allow int `json:"allow,omitempty"`

	// LimitRef is a flow variable name whose integer value overrides Allow.
	LimitRef string `json:"limit_ref,omitempty"`

	// Interval is the quota window length in seconds.
	// If zero and IntervalRef is set, the interval is read from a flow variable.
	Interval int `json:"interval,omitempty"`

	// IntervalRef is a flow variable name whose integer value overrides Interval.
	IntervalRef string `json:"interval_ref,omitempty"`

	// IdentifierRef is the flow variable name used as the per-key identifier.
	// If empty or the variable resolves to "", the quota is applied globally.
	IdentifierRef string `json:"identifier_ref,omitempty"`

	// Collection is the Firestore collection name for quota counters (default: "quotas").
	Collection string `json:"collection,omitempty"`

	logger   *zap.Logger
	fsClient *firestore.Client

	// In-memory fallback (used when Firestore is not configured).
	mu      sync.Mutex
	buckets map[string]*quotaBucket
}

type quotaBucket struct {
	count     int
	windowEnd time.Time
}

// CaddyModule returns the Caddy module metadata.
func (Quota) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_quota",
		New: func() caddy.Module { return new(Quota) },
	}
}

// Provision validates config and wires up the Firestore client if available.
func (q *Quota) Provision(ctx caddy.Context) error {
	q.logger = ctx.Logger()
	if q.Collection == "" {
		q.Collection = "quotas"
	}

	if q.Allow <= 0 && q.LimitRef == "" {
		return fmt.Errorf("apigee_quota: allow or limit_ref is required")
	}
	if q.Interval <= 0 && q.IntervalRef == "" {
		return fmt.Errorf("apigee_quota: interval or interval_ref is required")
	}

	if app, ok := GetFirestoreApp(ctx); ok {
		q.fsClient = app.Client()
		q.logger.Info("apigee_quota: Firestore distributed counter enabled",
			zap.String("collection", q.Collection))
	} else {
		q.buckets = make(map[string]*quotaBucket)
		q.logger.Info("apigee_quota: using in-memory counter (not distributed)")
	}
	return nil
}

// ServeHTTP checks the quota and either passes through or returns 429.
func (q *Quota) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, _ := GetFlowState(r.Context())

	// Resolve identifier.
	id := ""
	if q.IdentifierRef != "" && fs != nil {
		id = fs.GetString(q.IdentifierRef)
	}

	// Resolve limit.
	limit := q.Allow
	if q.LimitRef != "" && fs != nil {
		if v := fs.GetString(q.LimitRef); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = n
			}
		}
	}
	if limit <= 0 {
		// No limit configured or resolved — pass through.
		return next.ServeHTTP(w, r)
	}

	// Resolve interval.
	interval := q.Interval
	if q.IntervalRef != "" && fs != nil {
		if v := fs.GetString(q.IntervalRef); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				interval = n
			}
		}
	}
	if interval <= 0 {
		interval = 60 // default: per-minute
	}

	var exceeded bool
	var err error
	if q.fsClient != nil {
		exceeded, err = q.checkFirestore(r.Context(), id, limit, interval)
		if err != nil {
			q.logger.Error("apigee_quota: Firestore check failed, falling back to pass-through",
				zap.Error(err))
			return next.ServeHTTP(w, r)
		}
	} else {
		exceeded = q.checkMemory(id, limit, interval)
	}

	if exceeded {
		debugLog(r, q.logger, "apigee_quota: exceeded",
			zap.String("id", id),
			zap.Int("limit", limit),
			zap.Int("interval_secs", interval),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"fault":{"faultstring":"Quota Exceeded","detail":{"errorcode":"policies.ratelimit.QuotaViolation"}}}`)
		return nil
	}

	debugLog(r, q.logger, "apigee_quota: allowed",
		zap.String("id", id),
		zap.Int("limit", limit),
		zap.Int("interval_secs", interval),
	)
	return next.ServeHTTP(w, r)
}

// checkFirestore increments the quota counter in Firestore atomically.
// Returns true if the quota is exceeded.
func (q *Quota) checkFirestore(ctx context.Context, id string, limit, intervalSecs int) (bool, error) {
	now := time.Now()
	window := now.Truncate(time.Duration(intervalSecs) * time.Second)
	docID := fmt.Sprintf("%s_%d", sanitizeDocID(id), window.Unix())
	ref := q.fsClient.Collection(q.Collection).Doc(docID)

	var count int64
	err := q.fsClient.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(ref)
		if err != nil && status.Code(err) != codes.NotFound {
			return err
		}

		windowEnd := window.Add(time.Duration(intervalSecs) * time.Second)
		if status.Code(err) == codes.NotFound || snap == nil {
			count = 1
			return tx.Set(ref, map[string]interface{}{
				"count":      count,
				"window_end": windowEnd,
			})
		}

		var data struct {
			Count     int64     `firestore:"count"`
			WindowEnd time.Time `firestore:"window_end"`
		}
		if err := snap.DataTo(&data); err != nil {
			count = 1
			return tx.Set(ref, map[string]interface{}{
				"count":      count,
				"window_end": windowEnd,
			})
		}
		count = data.Count + 1
		return tx.Update(ref, []firestore.Update{
			{Path: "count", Value: count},
		})
	})
	if err != nil {
		return false, err
	}
	return count > int64(limit), nil
}

// checkMemory increments the in-memory counter.
// Returns true if the quota is exceeded.
func (q *Quota) checkMemory(id string, limit, intervalSecs int) bool {
	now := time.Now()
	window := time.Duration(intervalSecs) * time.Second

	q.mu.Lock()
	b, exists := q.buckets[id]
	if !exists || now.After(b.windowEnd) {
		b = &quotaBucket{count: 0, windowEnd: now.Add(window)}
		q.buckets[id] = b
	}
	b.count++
	count := b.count
	q.mu.Unlock()

	return count > limit
}

// sanitizeDocID replaces characters not allowed in Firestore document IDs.
func sanitizeDocID(s string) string {
	if s == "" {
		return "_global_"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

func parseQuotaCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var q Quota
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "allow":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if _, err := fmt.Sscanf(h.Val(), "%d", &q.Allow); err != nil {
					return nil, h.Errf("invalid allow value: %v", err)
				}
			case "limit_ref":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				q.LimitRef = h.Val()
			case "interval":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				if _, err := fmt.Sscanf(h.Val(), "%d", &q.Interval); err != nil {
					return nil, h.Errf("invalid interval value: %v", err)
				}
			case "interval_ref":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				q.IntervalRef = h.Val()
			case "identifier_ref":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				q.IdentifierRef = h.Val()
			case "collection":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				q.Collection = h.Val()
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &q, nil
}

// Interface guards.
var (
	_ caddy.Module                = Quota{}
	_ caddy.Provisioner           = (*Quota)(nil)
	_ caddyhttp.MiddlewareHandler = (*Quota)(nil)
	_ caddyfile.Unmarshaler       = (*Quota)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (q *Quota) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
