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

// VerifyAPIKey enforces API key validation using a three-tier Apigee-compatible
// data model: api_keys → apps → api_products.
//
// Resolution chain:
//  1. Resolve raw key from the request via APIKeyRef
//  2. Lookup api_keys/{sha256(key)} → app_id, enabled
//  3. Lookup apps/{app_id} → status, product_ids, developer_id
//  4. Find first api_products/{product_id} whose base_paths cover the request path
//  5. Write flow variables and call next handler
//
// Without Firestore configured the module is fail-closed by default (503).
// Set passthrough = true in the Caddyfile to revert to pass-through mode.
//
// Flow variables set on success:
//   - verifyapikey.<policy>.app_id
//   - verifyapikey.<policy>.app_name
//   - verifyapikey.<policy>.developer_id
//   - verifyapikey.<policy>.developer.app.name
//   - verifyapikey.<policy>.apiproduct.name
//   - verifyapikey.<policy>.apiproduct.developer.quota.limit
//   - verifyapikey.<policy>.apiproduct.developer.quota.interval  (in seconds)
//   - verifyapikey.<policy>.apiproduct.developer.quota.timeunit
type VerifyAPIKey struct {
	// APIKeyRef is the Apigee variable reference for the API key source,
	// e.g. "request.header.x-api-key".
	APIKeyRef string `json:"api_key_ref,omitempty"`

	// PolicyName namespaces the flow variables set on success.
	// Defaults to "VerifyAPIKey" if empty.
	PolicyName string `json:"policy_name,omitempty"`

	// Collection is the Firestore collection name for the api_keys index (default: "api_keys").
	Collection string `json:"collection,omitempty"`

	// Passthrough, when true, allows requests through when Firestore is not configured.
	// Default is false (fail-closed: returns 503 when Firestore is unavailable).
	Passthrough bool `json:"passthrough,omitempty"`

	logger       *zap.Logger
	fsClient     *firestore.Client
	keyCache     *ttlCache[apiKeyDoc]
	appCache     *ttlCache[appDoc]
	productCache *ttlCache[productDoc]
}

// apiKeyDoc is the lookup index stored in api_keys/{sha256(rawKey)}.
type apiKeyDoc struct {
	AppID   string `firestore:"app_id"`
	Enabled bool   `firestore:"enabled"`
}

// appDoc is stored in apps/{app_id}.
type appDoc struct {
	Name        string   `firestore:"name"`
	DeveloperID string   `firestore:"developer_id"`
	Status      string   `firestore:"status"`
	ProductIDs  []string `firestore:"product_ids"`
}

// productDoc is stored in api_products/{product_id}.
type productDoc struct {
	Name          string   `firestore:"name"`
	QuotaLimit    int64    `firestore:"quota_limit"`
	QuotaInterval int64    `firestore:"quota_interval"`
	QuotaTimeUnit string   `firestore:"quota_timeunit"`
	BasePaths     []string `firestore:"base_paths"`
}

// CaddyModule returns the Caddy module metadata.
func (VerifyAPIKey) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.verify_api_key",
		New: func() caddy.Module { return new(VerifyAPIKey) },
	}
}

// Provision wires up the Firestore client and caches from the shared app.
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
		v.appCache = newTTLCache[appDoc](5 * time.Minute)
		v.productCache = newTTLCache[productDoc](5 * time.Minute)
		v.logger.Info("verify_api_key: Firestore enforcement enabled",
			zap.String("collection", v.Collection))
	} else if v.Passthrough {
		v.logger.Warn("verify_api_key: Firestore not configured — passthrough mode (not enforced)",
			zap.String("api_key_ref", v.APIKeyRef))
	} else {
		v.logger.Warn("verify_api_key: Firestore not configured — fail-closed (will return 503)",
			zap.String("api_key_ref", v.APIKeyRef))
	}
	return nil
}

// ServeHTTP validates the API key via the key→app→product chain.
func (v *VerifyAPIKey) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if v.fsClient == nil {
		if v.Passthrough {
			return next.ServeHTTP(w, r)
		}
		return v.reject(w, http.StatusServiceUnavailable, "system.FailedToResolveAPIKey", "API key enforcement unavailable")
	}

	key := v.resolveKey(r)
	if key == "" {
		debugLog(r, v.logger, "verify_api_key: rejected — missing key",
			zap.String("policy", v.PolicyName),
		)
		return v.reject(w, http.StatusUnauthorized, "MissingAPIKey", "API key is required")
	}

	// Step 1: key lookup.
	keyDoc, err := v.lookupKey(r.Context(), key)
	if err != nil {
		v.logger.Error("verify_api_key: key Firestore lookup failed",
			zap.String("error", err.Error()))
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "API key validation failed")
	}
	if keyDoc == nil || !keyDoc.Enabled {
		debugLog(r, v.logger, "verify_api_key: rejected — invalid or disabled key",
			zap.String("policy", v.PolicyName),
		)
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "Invalid or disabled API key")
	}

	// Step 2: app lookup.
	app, err := v.lookupApp(r.Context(), keyDoc.AppID)
	if err != nil {
		v.logger.Error("verify_api_key: app Firestore lookup failed",
			zap.String("app_id", keyDoc.AppID),
			zap.String("error", err.Error()))
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "API key validation failed")
	}
	if app == nil || app.Status != "approved" {
		debugLog(r, v.logger, "verify_api_key: rejected — app not found or not approved",
			zap.String("policy", v.PolicyName),
			zap.String("app_id", keyDoc.AppID),
		)
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "App is not approved")
	}

	// Step 3: product lookup — find first product whose base_paths cover this request.
	product, productID, err := v.findMatchingProduct(r.Context(), app.ProductIDs, r.URL.Path)
	if err != nil {
		v.logger.Error("verify_api_key: product Firestore lookup failed",
			zap.String("error", err.Error()))
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "API key validation failed")
	}
	if product == nil {
		debugLog(r, v.logger, "verify_api_key: rejected — no matching product for request path",
			zap.String("policy", v.PolicyName),
			zap.String("path", r.URL.Path),
		)
		return v.reject(w, http.StatusUnauthorized, "InvalidAPIKey", "No matching API product for request path")
	}

	// Write flow variables for downstream policies (quota, etc.).
	if fs, ok := GetFlowState(r.Context()); ok {
		prefix := "verifyapikey." + v.PolicyName
		fs.Set(prefix+".app_id", keyDoc.AppID)
		fs.Set(prefix+".app_name", app.Name)
		fs.Set(prefix+".developer_id", app.DeveloperID)
		fs.Set(prefix+".developer.app.name", app.Name)
		fs.Set(prefix+".apiproduct.name", productID)
		if product.QuotaLimit > 0 {
			intervalSecs := quotaIntervalSecs(product.QuotaInterval, product.QuotaTimeUnit)
			fs.Set(prefix+".apiproduct.developer.quota.limit", fmt.Sprintf("%d", product.QuotaLimit))
			fs.Set(prefix+".apiproduct.developer.quota.interval", fmt.Sprintf("%d", intervalSecs))
			fs.Set(prefix+".apiproduct.developer.quota.timeunit", product.QuotaTimeUnit)
		}
	}

	debugLog(r, v.logger, "verify_api_key: accepted",
		zap.String("policy", v.PolicyName),
		zap.String("app_id", keyDoc.AppID),
		zap.String("product", productID),
	)
	return next.ServeHTTP(w, r)
}

func (v *VerifyAPIKey) resolveKey(r *http.Request) string {
	ref := strings.ToLower(strings.TrimSpace(v.APIKeyRef))
	if strings.HasPrefix(ref, "request.header.") {
		headerName := v.APIKeyRef[len("request.header."):]
		return r.Header.Get(headerName)
	}
	// Flow variable reference.
	if fs, ok := GetFlowState(r.Context()); ok {
		return fs.GetString(v.APIKeyRef)
	}
	return ""
}

// hashKey returns a safe Firestore document ID for the given API key.
func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// HashKey is the exported version of hashKey for use by caddygee-server.
func HashKey(key string) string { return hashKey(key) }

func (v *VerifyAPIKey) lookupKey(ctx context.Context, key string) (*apiKeyDoc, error) {
	cacheKey := hashKey(key)
	if cached, ok := v.keyCache.Get(cacheKey); ok {
		return cached, nil
	}
	snap, err := v.fsClient.Collection(v.Collection).Doc(cacheKey).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
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

func (v *VerifyAPIKey) lookupApp(ctx context.Context, appID string) (*appDoc, error) {
	if cached, ok := v.appCache.Get(appID); ok {
		return cached, nil
	}
	snap, err := v.fsClient.Collection("apps").Doc(appID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			v.appCache.Set(appID, nil)
			return nil, nil
		}
		return nil, err
	}
	var doc appDoc
	if err := snap.DataTo(&doc); err != nil {
		return nil, fmt.Errorf("parsing app document: %w", err)
	}
	v.appCache.Set(appID, &doc)
	return &doc, nil
}

func (v *VerifyAPIKey) lookupProduct(ctx context.Context, productID string) (*productDoc, error) {
	if cached, ok := v.productCache.Get(productID); ok {
		return cached, nil
	}
	snap, err := v.fsClient.Collection("api_products").Doc(productID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			v.productCache.Set(productID, nil)
			return nil, nil
		}
		return nil, err
	}
	var doc productDoc
	if err := snap.DataTo(&doc); err != nil {
		return nil, fmt.Errorf("parsing product document: %w", err)
	}
	v.productCache.Set(productID, &doc)
	return &doc, nil
}

// findMatchingProduct returns the first product in productIDs whose base_paths
// cover requestPath, plus the matching product ID. Empty base_paths means any path.
func (v *VerifyAPIKey) findMatchingProduct(ctx context.Context, productIDs []string, requestPath string) (*productDoc, string, error) {
	for _, id := range productIDs {
		prod, err := v.lookupProduct(ctx, id)
		if err != nil {
			return nil, "", err
		}
		if prod == nil {
			continue
		}
		if len(prod.BasePaths) == 0 {
			return prod, id, nil
		}
		for _, bp := range prod.BasePaths {
			if strings.HasPrefix(requestPath, bp) {
				return prod, id, nil
			}
		}
	}
	return nil, "", nil
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
			case "passthrough":
				v.Passthrough = true
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
