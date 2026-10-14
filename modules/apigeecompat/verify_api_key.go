package apigeecompat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
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
	caddy.RegisterModule(VerifyAPIKey{})
	httpcaddyfile.RegisterHandlerDirective("verify_api_key", parseVerifyAPIKeyCaddyfile)
}

// VerifyAPIKey is the verify_api_key Caddy module.
//
// When the firestore app is configured, it enforces API key validation
// by looking up the key in Firestore collection "api_keys". A valid key document
// must exist and have enabled=true. Quota metadata from the document is written
// into flow variables for downstream quota handlers.
//
// Without Firestore configured, it falls back to passthrough mode (logs a warning).
//
// Firestore document structure (collection: "api_keys", document ID: <key value>):
//
//	{
//	    "enabled":        true,
//	    "app_id":         "my-app",
//	    "quota_limit":    200,
//	    "quota_interval": 1,
//	    "quota_timeunit": "minute"
//	}
//
// Flow variables set on success:
//   - verifyapikey.<policy_name>.app_id
//   - verifyapikey.<policy_name>.apiproduct.developer.quota.limit
//   - verifyapikey.<policy_name>.apiproduct.developer.quota.interval  (in seconds)
//   - verifyapikey.<policy_name>.apiproduct.developer.quota.timeunit
type VerifyAPIKey struct {
	// APIKeyRef is the Apigee variable reference for the API key source,
	// e.g. "request.header.authorization".
	APIKeyRef string `json:"api_key_ref,omitempty"`

	// PolicyName is used to namespace the flow variables set on success.
	// Defaults to "VerifyAPIKey" if empty.
	PolicyName string `json:"policy_name,omitempty"`

	// Collection is the Firestore collection name for API keys (default: "api_keys").
	Collection string `json:"collection,omitempty"`

	logger    *zap.Logger
	fsClient  *firestore.Client
	keyCache  *ttlCache[apiKeyDoc]
}

type apiKeyDoc struct {
	AppID         string `firestore:"app_id"`
	Enabled       bool   `firestore:"enabled"`
	QuotaLimit    int64  `firestore:"quota_limit"`
	QuotaInterval int64  `firestore:"quota_interval"`
	QuotaTimeUnit string `firestore:"quota_timeunit"`
}

// CaddyModule returns the Caddy module metadata.
func (VerifyAPIKey) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.verify_api_key",
		New: func() caddy.Module { return new(VerifyAPIKey) },
	}
}

// Provision wires up the Firestore client from the shared app, if configured.
func (v *VerifyAPIKey) Provision(ctx caddy.Context) error {
	v.logger = ctx.Logger()
	if v.Collection == "" {
		v.Collection = "api_keys"
	}
	if v.PolicyName == "" {
		v.PolicyName = "VerifyAPIKey"
	}

	if app, ok := GetFirestoreApp(ctx); ok {
		v.fsClient = app.Client()
		v.keyCache = newTTLCache[apiKeyDoc](5 * time.Minute)
		v.logger.Info("verify_api_key: Firestore enforcement enabled",
			zap.String("collection", v.Collection))
	} else {
		v.logger.Warn("verify_api_key: Firestore not configured — passthrough mode (not enforced)",
			zap.String("api_key_ref", v.APIKeyRef))
	}
	return nil
}

// ServeHTTP validates the API key when Firestore is configured, otherwise passes through.
func (v *VerifyAPIKey) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if v.fsClient == nil {
		// Passthrough mode.
		return next.ServeHTTP(w, r)
	}

	key := v.resolveKey(r)
	if key == "" {
		debugLog(r, v.logger, "verify_api_key: rejected — missing key",
			zap.String("policy", v.PolicyName),
		)
		return v.reject(w, http.StatusUnauthorized, "MissingAPIKey", "API key is required")
	}

	doc, err := v.lookupKey(r.Context(), key)
	if err != nil {
		v.logger.Error("verify_api_key: Firestore lookup failed",
			zap.String("error", err.Error()))
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "API key validation failed")
	}
	if doc == nil || !doc.Enabled {
		debugLog(r, v.logger, "verify_api_key: rejected — invalid or disabled key",
			zap.String("policy", v.PolicyName),
		)
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "Invalid or disabled API key")
	}

	// Write quota metadata into flow state for downstream quota.
	if fs, ok := GetFlowState(r.Context()); ok {
		prefix := "verifyapikey." + v.PolicyName
		fs.Set(prefix+".app_id", doc.AppID)
		if doc.QuotaLimit > 0 {
			intervalSecs := quotaIntervalSecs(doc.QuotaInterval, doc.QuotaTimeUnit)
			fs.Set(prefix+".apiproduct.developer.quota.limit", fmt.Sprintf("%d", doc.QuotaLimit))
			fs.Set(prefix+".apiproduct.developer.quota.interval", fmt.Sprintf("%d", intervalSecs))
			fs.Set(prefix+".apiproduct.developer.quota.timeunit", doc.QuotaTimeUnit)
		}
	}

	debugLog(r, v.logger, "verify_api_key: accepted",
		zap.String("policy", v.PolicyName),
		zap.String("app_id", doc.AppID),
	)
	return next.ServeHTTP(w, r)
}

func (v *VerifyAPIKey) resolveKey(r *http.Request) string {
	ref := strings.ToLower(strings.TrimSpace(v.APIKeyRef))
	if strings.HasPrefix(ref, "request.header.") {
		headerName := v.APIKeyRef[len("request.header."):]
		return r.Header.Get(headerName)
	}
	// Flow variable reference — read from flow state.
	if fs, ok := GetFlowState(r.Context()); ok {
		return fs.GetString(v.APIKeyRef)
	}
	return ""
}

// hashKey returns a safe Firestore document ID for the given API key.
// The raw key is hashed with SHA-256 to avoid path traversal via '/' characters
// and to keep document IDs within Firestore's 1500-byte limit.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (v *VerifyAPIKey) lookupKey(ctx context.Context, key string) (*apiKeyDoc, error) {
	// Use a hashed key as the cache key to avoid issues with special characters.
	cacheKey := hashKey(key)
	if cached, ok := v.keyCache.Get(cacheKey); ok {
		// Cached nil sentinel means a known-absent key — return nil doc, no error.
		return cached, nil
	}

	snap, err := v.fsClient.Collection(v.Collection).Doc(cacheKey).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// Cache the negative result so repeated probes don't hit Firestore.
			v.keyCache.Set(cacheKey, nil)
			return nil, nil
		}
		return nil, err
	}

	var doc apiKeyDoc
	if err := snap.DataTo(&doc); err != nil {
		return nil, fmt.Errorf("parsing key document: %w", err)
	}
	v.keyCache.Set(cacheKey, &doc)
	return &doc, nil
}

func (v *VerifyAPIKey) reject(w http.ResponseWriter, code int, errorCode, message string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"fault":{"faultstring":%q,"detail":{"errorcode":"oauth.v2.%s"}}}`, message, errorCode)
	return nil
}

// quotaIntervalSecs converts Apigee's interval+timeunit to seconds.
func quotaIntervalSecs(interval int64, timeUnit string) int64 {
	switch strings.ToLower(strings.TrimSpace(timeUnit)) {
	case "minute":
		return interval * 60
	case "hour":
		return interval * 3600
	case "day":
		return interval * 86400
	default:
		return interval
	}
}

func parseVerifyAPIKeyCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var v VerifyAPIKey
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "api_key_ref":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.APIKeyRef = h.Val()
			case "policy_name":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.PolicyName = h.Val()
			case "collection":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.Collection = h.Val()
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &v, nil
}

// Interface guards.
var (
	_ caddy.Module                = VerifyAPIKey{}
	_ caddy.Provisioner           = (*VerifyAPIKey)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyAPIKey)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyAPIKey)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (v *VerifyAPIKey) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
