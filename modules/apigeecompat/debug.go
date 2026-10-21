package apigeecompat

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// debugContextKey is the context key for the per-request debug flag.
type debugContextKey struct{}

// debugIDContextKey is the context key for the per-request debug token ID and subject.
type debugIDContextKey struct{}

type debugIDValue struct {
	id  string
	sub string
}

// withDebug returns a copy of ctx with the debug flag set to enabled.
func withDebug(ctx context.Context) context.Context {
	return context.WithValue(ctx, debugContextKey{}, true)
}

// withDebugID returns a copy of ctx with the debug ID and subject stored.
func withDebugID(ctx context.Context, id, sub string) context.Context {
	return context.WithValue(ctx, debugIDContextKey{}, debugIDValue{id: id, sub: sub})
}

// isDebug reports whether the request has the debug flag set.
func isDebug(r *http.Request) bool {
	v, ok := r.Context().Value(debugContextKey{}).(bool)
	return ok && v
}

// debugID returns the token ID and subject bound to this debug session, if any.
func debugID(r *http.Request) (id, sub string) {
	v, ok := r.Context().Value(debugIDContextKey{}).(debugIDValue)
	if !ok {
		return "", ""
	}
	return v.id, v.sub
}

// debugLog emits a DEBUG-level log line only when the request has debug mode
// enabled. It automatically appends the debug_id and debug_sub fields if present.
// It is a no-op on normal requests, so it is safe to call on every request
// without impacting production performance.
func debugLog(r *http.Request, logger *zap.Logger, msg string, fields ...zap.Field) {
	if logger == nil || !isDebug(r) {
		return
	}
	if id, sub := debugID(r); id != "" {
		fields = append(fields, zap.String("debug_id", id), zap.String("debug_sub", sub))
	}
	logger.Debug(msg, fields...)
}

// debugTokenRandBytes is the number of random bytes used for the token ID.
const debugTokenRandBytes = 8

// IssueDebugToken generates a new HMAC-signed debug token for the given subject.
// Format: <id>.<b64url(sub)>.<hmac>
// where id = base32(8 random bytes), hmac = HMAC-SHA256(signingKey, id+"."+sub).
func IssueDebugToken(signingKey []byte, sub string) (string, error) {
	raw := make([]byte, debugTokenRandBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	encodedSub := base64.RawURLEncoding.EncodeToString([]byte(sub))
	mac := computeHMAC(signingKey, id, sub)
	return id + "." + encodedSub + "." + mac, nil
}

// verifyDebugToken checks a debug token against the signing key.
// Returns the token ID and subject on success.
// Format expected: <id>.<b64url(sub)>.<hmac>
func verifyDebugToken(signingKey []byte, token string) (id, sub string, ok bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	id = parts[0]
	subBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(subBytes) == 0 {
		return "", "", false
	}
	sub = string(subBytes)
	expected := computeHMAC(signingKey, id, sub)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "", "", false
	}
	return id, sub, true
}

func computeHMAC(key []byte, id, sub string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id + "." + sub))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
