package apigeecompat

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(KVM{})
	httpcaddyfile.RegisterHandlerDirective("apigee_kvm", parseKVMCaddyfile)
}

// KVM is the apigee_kvm Caddy module.
// Equivalent to Apigee's KeyValueMapOperations policy.
//
// Static mode (default): baked-in key-value entries from the policy's
// <InitialEntries> are written into flow state at request time.
//
// Live mode (when apigee_firestore is configured and MapName is set):
// values are read from Firestore at request time with a 5-minute TTL cache.
// Firestore collection: "kvm", document ID: <map_name>.
// Document fields map directly to flow variable names.
//
//	kvm/{map_name}  →  { "authApiBaseUrl": "auth.example.com", ... }
//
// Live values override static entries when both are present.
type KVM struct {
	// Entries maps flow variable name → static value.
	// Written into flow state at every request.
	Entries map[string]string `json:"entries,omitempty"`

	// MapName is the Firestore document ID in the "kvm" collection.
	// When set and Firestore is configured, live values are fetched and cached.
	MapName string `json:"map_name,omitempty"`

	// Collection is the Firestore collection name (default: "kvm").
	Collection string `json:"collection,omitempty"`

	logger   *zap.Logger
	fsClient *firestore.Client
	kvCache  *ttlCache[map[string]string]
}

// CaddyModule returns the Caddy module metadata.
func (KVM) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_kvm",
		New: func() caddy.Module { return new(KVM) },
	}
}

// Provision sets up logging and optionally the Firestore client.
func (k *KVM) Provision(ctx caddy.Context) error {
	k.logger = ctx.Logger()
	if k.Collection == "" {
		k.Collection = "kvm"
	}
	if len(k.Entries) == 0 && k.MapName == "" {
		k.logger.Warn("apigee_kvm: no entries and no map_name — this handler is a no-op")
	}
	if app, ok := GetFirestoreApp(ctx); ok && k.MapName != "" {
		k.fsClient = app.Client()
		k.kvCache = newTTLCache[map[string]string](5 * time.Minute)
		k.logger.Info("apigee_kvm: Firestore live mode enabled",
			zap.String("map", k.MapName),
			zap.String("collection", k.Collection))
	}
	return nil
}

// ServeHTTP writes KVM entries into the request flow state.
// Static entries are applied first; live Firestore values overlay them.
func (k *KVM) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fs, ok := GetFlowState(r.Context())
	if !ok {
		return next.ServeHTTP(w, r)
	}

	// Static entries first.
	for key, val := range k.Entries {
		fs.Set(key, val)
	}

	// Live Firestore overlay.
	if k.fsClient != nil {
		if live, err := k.fetchLive(r.Context()); err != nil {
			k.logger.Warn("apigee_kvm: Firestore read failed, using static values",
				zap.String("map", k.MapName), zap.Error(err))
		} else {
			for key, val := range live {
				fs.Set(key, val)
			}
			debugLog(r, k.logger, "apigee_kvm: live entries applied",
				zap.String("map", k.MapName),
				zap.Int("count", len(live)),
			)
		}
	} else if len(k.Entries) > 0 {
		debugLog(r, k.logger, "apigee_kvm: static entries applied",
			zap.Int("count", len(k.Entries)),
		)
	}

	return next.ServeHTTP(w, r)
}

func (k *KVM) fetchLive(ctx context.Context) (map[string]string, error) {
	if cached, ok := k.kvCache.Get(k.MapName); ok {
		return *cached, nil
	}

	snap, err := k.fsClient.Collection(k.Collection).Doc(k.MapName).Get(ctx)
	if err != nil {
		return nil, err
	}

	raw := snap.Data()
	result := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	k.kvCache.Set(k.MapName, &result)
	return result, nil
}

func parseKVMCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var k KVM
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "entry":
				args := h.RemainingArgs()
				if len(args) < 2 {
					return nil, h.ArgErr()
				}
				if k.Entries == nil {
					k.Entries = make(map[string]string)
				}
				k.Entries[args[0]] = args[1]
			case "map_name":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				k.MapName = h.Val()
			case "collection":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				k.Collection = h.Val()
			default:
				return nil, h.Errf("unrecognised subdirective %q", h.Val())
			}
		}
	}
	return &k, nil
}

// Interface guards.
var (
	_ caddy.Module                = KVM{}
	_ caddy.Provisioner           = (*KVM)(nil)
	_ caddyhttp.MiddlewareHandler = (*KVM)(nil)
	_ caddyfile.Unmarshaler       = (*KVM)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (k *KVM) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// Compile-time check that fmt is used.
var _ = fmt.Sprintf

// Compile-time check that firestore is used.
var _ *firestore.Client
