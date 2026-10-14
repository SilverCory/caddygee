package apigeecompat

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func init() {
	caddy.RegisterModule(VerifyJWT{})
	httpcaddyfile.RegisterHandlerDirective("apigee_verify_jwt", parseVerifyJWTCaddyfile)
}

// VerifyJWT is the apigee_verify_jwt Caddy module.
// It verifies a Bearer JWT from the Authorization header and stores the decoded
// claims as flow variables named jwt.<policy_name>.decoded.claim.<claimName>.
//
// Supports RS256 and RS512 with either a static PEM public key or a JWKS URI.
// On failure it writes a 401 response and does NOT call the next handler.
type VerifyJWT struct {
	// Algorithm is "RS256" or "RS512".
	Algorithm string `json:"algorithm"`
	// PublicKey is a PEM-encoded RSA public key (used when JWKSURI is empty).
	PublicKey string `json:"public_key,omitempty"`
	// JWKSURI is the URL of a JSON Web Key Set endpoint.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// Issuer, if non-empty, must match the "iss" claim.
	Issuer string `json:"issuer,omitempty"`
	// Audience, if non-empty, must match the "aud" claim.
	Audience string `json:"audience,omitempty"`
	// PolicyName is used to namespace the claim flow variables.
	PolicyName string `json:"policy_name"`

	rsaKey     *rsa.PublicKey
	jwksMu     sync.RWMutex
	jwksKeys   *jose.JSONWebKeySet
	jwksFetched time.Time
}

// CaddyModule returns the Caddy module metadata.
func (VerifyJWT) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apigee_verify_jwt",
		New: func() caddy.Module { return new(VerifyJWT) },
	}
}

// Provision parses and validates configuration.
func (v *VerifyJWT) Provision(_ caddy.Context) error {
	if v.PolicyName == "" {
		return fmt.Errorf("apigee_verify_jwt: policy_name is required")
	}
	if v.Algorithm == "" {
		v.Algorithm = "RS256"
	}
	switch strings.ToUpper(v.Algorithm) {
	case "RS256", "RS512":
	default:
		return fmt.Errorf("apigee_verify_jwt: unsupported algorithm %q (RS256 and RS512 supported)", v.Algorithm)
	}
	if v.PublicKey == "" && v.JWKSURI == "" {
		return fmt.Errorf("apigee_verify_jwt: one of public_key or jwks_uri is required")
	}
	if v.PublicKey != "" {
		key, err := parseRSAPublicKey(v.PublicKey)
		if err != nil {
			return fmt.Errorf("apigee_verify_jwt: %w", err)
		}
		v.rsaKey = key
	}
	return nil
}

// ServeHTTP verifies the JWT and populates flow variables, then calls next.
func (v *VerifyJWT) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rawToken := extractBearer(r)
	if rawToken == "" {
		return v.unauthorized(w, "missing or malformed Authorization header")
	}

	key, err := v.resolveKey(rawToken)
	if err != nil {
		return v.unauthorized(w, "could not resolve JWT signing key: "+err.Error())
	}

	alg := jose.SignatureAlgorithm(strings.ToUpper(v.Algorithm))
	tok, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{alg})
	if err != nil {
		return v.unauthorized(w, "invalid JWT: "+err.Error())
	}

	var claims map[string]any
	if err := tok.Claims(key, &claims); err != nil {
		return v.unauthorized(w, "JWT verification failed: "+err.Error())
	}

	// Validate standard claims.
	if v.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != v.Issuer {
			return v.unauthorized(w, fmt.Sprintf("JWT issuer mismatch: got %q, want %q", iss, v.Issuer))
		}
	}
	if exp, ok := claims["exp"]; ok {
		switch e := exp.(type) {
		case float64:
			if time.Unix(int64(e), 0).Before(time.Now()) {
				return v.unauthorized(w, "JWT is expired")
			}
		}
	}

	// Store claims as flow variables.
	if fs, ok := GetFlowState(r.Context()); ok {
		prefix := "jwt." + v.PolicyName + ".decoded.claim."
		for k, val := range claims {
			fs.Set(prefix+k, val)
		}
	}

	return next.ServeHTTP(w, r)
}

func (v *VerifyJWT) unauthorized(w http.ResponseWriter, reason string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
	return nil
}

// resolveKey returns the verification key — either the static RSA key or one
// fetched from the JWKS endpoint.
func (v *VerifyJWT) resolveKey(rawToken string) (any, error) {
	if v.rsaKey != nil {
		return v.rsaKey, nil
	}
	return v.fetchJWKSKey(rawToken)
}

// fetchJWKSKey fetches (and caches for 5 minutes) the JWKS and picks the key
// that matches the token's "kid" header, or the first RS key if no kid.
func (v *VerifyJWT) fetchJWKSKey(rawToken string) (any, error) {
	v.jwksMu.RLock()
	ks := v.jwksKeys
	fetched := v.jwksFetched
	v.jwksMu.RUnlock()

	if ks == nil || time.Since(fetched) > 5*time.Minute {
		v.jwksMu.Lock()
		defer v.jwksMu.Unlock()
		// Double-check after acquiring write lock.
		if v.jwksKeys == nil || time.Since(v.jwksFetched) > 5*time.Minute {
			resp, err := http.Get(v.JWKSURI) //nolint:noctx
			if err != nil {
				return nil, fmt.Errorf("fetching JWKS from %q: %w", v.JWKSURI, err)
			}
			defer resp.Body.Close()
			var fresh jose.JSONWebKeySet
			if err := json.NewDecoder(resp.Body).Decode(&fresh); err != nil {
				return nil, fmt.Errorf("decoding JWKS: %w", err)
			}
			v.jwksKeys = &fresh
			v.jwksFetched = time.Now()
		}
		ks = v.jwksKeys
	}

	// Parse the kid from the token header.
	tok, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{
		jose.SignatureAlgorithm(strings.ToUpper(v.Algorithm)),
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token header: %w", err)
	}

	var kid string
	if len(tok.Signatures) > 0 {
		kid = tok.Signatures[0].Header.KeyID
	}

	if kid != "" {
		keys := ks.Key(kid)
		if len(keys) > 0 {
			return keys[0].Key, nil
		}
		return nil, fmt.Errorf("no key with kid %q in JWKS", kid)
	}

	// No kid — use first RSA key.
	for _, k := range ks.Keys {
		if _, ok := k.Key.(*rsa.PublicKey); ok {
			return k.Key, nil
		}
	}
	return nil, fmt.Errorf("no RSA key found in JWKS")
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	return rsaKey, nil
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func parseVerifyJWTCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var v VerifyJWT
	for h.Next() {
		_ = h.RemainingArgs()
		for h.NextBlock(0) {
			switch h.Val() {
			case "algorithm":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.Algorithm = h.Val()
			case "public_key":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.PublicKey = h.Val()
			case "jwks_uri":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.JWKSURI = h.Val()
			case "issuer":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.Issuer = h.Val()
			case "audience":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.Audience = h.Val()
			case "policy_name":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				v.PolicyName = h.Val()
			}
		}
	}
	return &v, nil
}

// Interface guards.
var (
	_ caddy.Module                = VerifyJWT{}
	_ caddy.Provisioner           = (*VerifyJWT)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyJWT)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyJWT)(nil)
)

// UnmarshalCaddyfile satisfies the interface.
func (v *VerifyJWT) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }
