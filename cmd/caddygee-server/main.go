// Command caddygee-server is the caddygee deploy endpoint.
//
// It exposes a /deploy HTTP endpoint that accepts an authenticated Caddyfile
// fragment, validates it, stores it in GCS, merges all fragments, and hot-reloads
// the running Caddy instance via its local admin API.
//
// On startup it fetches all stored fragments from GCS, merges them, and writes
// the merged Caddyfile to disk before starting Caddy as a subprocess.
//
// Environment variables:
//
//	CONFIG_BUCKET       GCS bucket name holding fragment files (required)
//	DEPLOY_PORT         HTTP port for the deploy endpoint (default: 9090)
//	CADDY_ADMIN         Caddy admin API address (default: localhost:2019)
//	CADDYFILE_PATH      Path to write the merged Caddyfile (default: /etc/caddy/Caddyfile)
//	LISTEN_ADDRESS      Caddy listen address passed to the merger (default: :8080)
//	TRUSTED_PROXIES     Space-separated CIDR ranges for trusted_proxies (default: GCP LB ranges)
//	DEBUG_SIGNING_KEY   HMAC signing key for debug token issuance/verification (optional)
//	DEBUG_ALLOWED_EMAIL If set, only this OIDC email may call /debug-token endpoints (optional)
//
// API key management endpoints (/developers, /apps, /products) require Firestore
// (initialised automatically when CONFIG_BUCKET is set).
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/storage"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/iterator"

	"caddygee/internal/transpiler"
	"caddygee/modules/apigeecompat"
)

func main() {
	bucket := os.Getenv("CONFIG_BUCKET")
	audience := os.Getenv("CADDYGEE_AUDIENCE")
	port := envOr("DEPLOY_PORT", "9090")
	adminAddr := envOr("CADDY_ADMIN", "localhost:2019")
	caddyfilePath := envOr("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
	listenAddr := envOr("LISTEN_ADDRESS", ":8080")
	caddyBinPath := envOr("CADDY_BIN", "caddy")

	var trustedProxies []string
	if raw := os.Getenv("TRUSTED_PROXIES"); raw != "" {
		for _, cidr := range strings.Fields(raw) {
			trustedProxies = append(trustedProxies, cidr)
		}
	}

	srv := &deployServer{
		bucket:            bucket,
		audience:          audience,
		adminAddr:         adminAddr,
		caddyfilePath:     caddyfilePath,
		listenAddr:        listenAddr,
		trustedProxies:    trustedProxies,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		caddyBin:          caddyBinPath,
		debugAllowedEmail: os.Getenv("DEBUG_ALLOWED_EMAIL"),
	}

	if key := os.Getenv("DEBUG_SIGNING_KEY"); key != "" {
		srv.debugSigningKey = []byte(key)
	}

	// CADDYGEE_BYPASS_AUTH=1 skips OIDC verification; the project ID is taken
	// from the X-Project-ID header instead. Only for integration testing.
	if os.Getenv("CADDYGEE_BYPASS_AUTH") == "1" {
		log.Printf("WARNING: auth bypass enabled (CADDYGEE_BYPASS_AUTH=1) — testing only")
		srv.verifyToken = bypassAuth
	}

	ctx := context.Background()

	// Initialise Firestore client when CONFIG_BUCKET is set (needed for API key
	// management and debug blocklist). Falls back to env-var-only blocklist on error.
	if bucket != "" {
		if fsClient, err := firestore.NewClient(ctx, firestore.DetectProjectID); err != nil {
			log.Printf("WARNING: Firestore client unavailable — API key management disabled, debug blocklist will use DEBUG_BLOCKLIST only: %v", err)
		} else {
			srv.fsClient = fsClient
		}
	} else if len(srv.debugSigningKey) > 0 {
		// No CONFIG_BUCKET but signing key is set — still try Firestore for blocklist.
		if fsClient, err := firestore.NewClient(ctx, firestore.DetectProjectID); err != nil {
			log.Printf("WARNING: Firestore client unavailable — debug blocklist will use DEBUG_BLOCKLIST env var only: %v", err)
		} else {
			srv.fsClient = fsClient
		}
	}

	if bucket == "" {
		log.Printf("WARNING: CONFIG_BUCKET not set — running in fallback mode (no GCS, /deploy disabled)")
		srv.writeFallbackCaddyfile()
	} else {
		gcs, err := storage.NewClient(ctx)
		if err != nil {
			log.Printf("WARNING: creating GCS client failed: %v — running in fallback mode", err)
			srv.writeFallbackCaddyfile()
		} else {
			srv.gcs = gcs
			// Cold start: fetch fragments from GCS and write initial Caddyfile.
			if err := srv.buildAndWriteCaddyfile(ctx); err != nil {
				log.Printf("WARNING: cold-start merge failed (no fragments yet?): %v", err)
				srv.writeFallbackCaddyfile()
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/deploy", srv.handleDeploy)
	mux.HandleFunc("/debug-token", srv.handleDebugToken)
	mux.HandleFunc("/debug-token/revoke", srv.handleRevokeDebugToken)
	srv.registerAPIKeyRoutes(mux)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("caddygee-server listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// serviceNameRE allows only lowercase alphanumeric, hyphens, and underscores,
// 1–63 characters, starting with a letter or digit (MEDIUM-1).
var serviceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// verifyTokenFunc validates an OIDC Bearer token and returns the caller's GCP project ID.
// It mirrors the signature of idtoken.Validate for testability.
type verifyTokenFunc func(ctx context.Context, token, audience string) (projectID string, err error)

// bypassAuth skips OIDC validation and uses the raw token value as the project ID.
// Only used when CADDYGEE_BYPASS_AUTH=1 (integration testing).
func bypassAuth(_ context.Context, token, _ string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("bypass auth: token (project ID) is empty")
	}
	return token, nil
}

type deployServer struct {
	bucket         string
	audience       string          // SEC-1: expected OIDC audience (Cloud Run service URL)
	adminAddr      string
	caddyfilePath  string
	listenAddr     string
	trustedProxies []string
	gcs            *storage.Client
	httpClient     *http.Client    // HIGH-1: shared client with timeout for admin API calls
	verifyToken    verifyTokenFunc // nil → uses idtoken.Validate
	caddyBin       string          // path to caddy binary; defaults to "caddy"
	mu             sync.Mutex      // serialises concurrent deploys

	// Debug token issuance.
	debugSigningKey  []byte          // from DEBUG_SIGNING_KEY; nil = endpoint disabled
	debugAllowedEmail string         // from DEBUG_ALLOWED_EMAIL; empty = any authenticated caller
	fsClient         *firestore.Client // nil when Firestore not available
}

func (s *deployServer) caddy() string {
	if s.caddyBin != "" {
		return s.caddyBin
	}
	return "caddy"
}

// handleDeploy handles POST /deploy.
//
// Request:
//
//	Authorization: Bearer <Google OIDC ID token>
//	X-Service-Name: <service-name>   (e.g. "profile-api-v2")
//	Body: <Caddyfile fragment>
//
// The caller's project is extracted from the OIDC token's service account email.
// The fragment is stored at gs://<bucket>/<project-id>/<service-name>.caddyfile.
func (s *deployServer) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.gcs == nil || s.bucket == "" {
		http.Error(w, "deploy endpoint disabled: CONFIG_BUCKET not configured", http.StatusServiceUnavailable)
		return
	}
	if s.audience == "" {
		http.Error(w, "deploy endpoint disabled: CADDYGEE_AUDIENCE not configured", http.StatusServiceUnavailable)
		return
	}

	// --- Auth: verify Google OIDC ID token ---
	projectID, err := s.verifyIDToken(r)
	if err != nil {
		log.Printf("deploy auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	serviceName := r.Header.Get("X-Service-Name")
	if serviceName == "" {
		http.Error(w, "X-Service-Name header required", http.StatusBadRequest)
		return
	}
	// MEDIUM-1: Strict allowlist — prevents path traversal and injection.
	if !serviceNameRE.MatchString(serviceName) {
		http.Error(w, "X-Service-Name must match [a-z0-9][a-z0-9_-]{0,62}", http.StatusBadRequest)
		return
	}

	fragment, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(fragment)) == 0 {
		http.Error(w, "empty fragment", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := r.Context()

	// --- Gate 1: validate fragment in isolation ---
	if err := s.validateFragment(string(fragment), s.listenAddr); err != nil {
		log.Printf("gate1 validation failed for %s/%s: %v", projectID, serviceName, err)
		http.Error(w, fmt.Sprintf("fragment validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// --- Gate 2: validate merged config ---
	merged, err := s.buildMergedCaddyfile(ctx, projectID, serviceName, string(fragment))
	if err != nil {
		log.Printf("gate2 merge failed for %s/%s: %v", projectID, serviceName, err)
		http.Error(w, fmt.Sprintf("merge validation failed: %v", err), http.StatusUnprocessableEntity)
		return
	}
	if err := s.validateCaddyfile(merged); err != nil {
		log.Printf("gate2 validation failed for %s/%s: %v", projectID, serviceName, err)
		http.Error(w, fmt.Sprintf("merged config validation failed: %v", err), http.StatusUnprocessableEntity)
		return
	}

	// --- Gate 3: hot-reload Caddy ---
	if err := s.caddyLoad(merged); err != nil {
		log.Printf("gate3 caddy reload failed for %s/%s: %v", projectID, serviceName, err)
		http.Error(w, fmt.Sprintf("caddy reload failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	// --- Persist to GCS only after successful reload ---
	objName := fmt.Sprintf("%s/%s.caddyfile", projectID, serviceName)
	if err := s.putGCS(ctx, objName, fragment); err != nil {
		// Non-fatal: config is live but GCS is stale. Log and continue.
		log.Printf("WARNING: GCS write failed for %s: %v (config is live but not persisted)", objName, err)
	}

	// Update the on-disk Caddyfile to match what's running.
	if err := os.WriteFile(s.caddyfilePath, []byte(merged), 0o644); err != nil {
		log.Printf("WARNING: could not update Caddyfile on disk: %v", err)
	}

	log.Printf("deployed %s/%s successfully", projectID, serviceName)
	w.WriteHeader(http.StatusOK)
}

// handleDebugToken handles POST /debug-token.
// Requires the same Google OIDC auth as /deploy.
// Returns a new HMAC-signed debug token bound to the caller's OIDC subject.
func (s *deployServer) handleDebugToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.debugSigningKey) == 0 {
		http.Error(w, "debug token issuance not configured (DEBUG_SIGNING_KEY not set)", http.StatusServiceUnavailable)
		return
	}
	email, sub, err := s.verifyDebugCaller(r)
	if err != nil {
		log.Printf("debug-token auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := apigeecompat.IssueDebugToken(s.debugSigningKey, sub)
	if err != nil {
		log.Printf("debug-token issue failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Extract just the ID portion (first segment) for logging.
	id := token[:strings.IndexByte(token, '.')]
	log.Printf("issued debug token id=%s caller=%s", id, email)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, token)
}

// handleRevokeDebugToken handles POST /debug-token/revoke.
// Requires the same Google OIDC auth as /deploy.
// Adds the given token ID to the Firestore debug_blocklist collection.
func (s *deployServer) handleRevokeDebugToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.debugSigningKey) == 0 {
		http.Error(w, "debug token management not configured (DEBUG_SIGNING_KEY not set)", http.StatusServiceUnavailable)
		return
	}
	email, _, err := s.verifyDebugCaller(r)
	if err != nil {
		log.Printf("debug-token/revoke auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		http.Error(w, "id field required", http.StatusBadRequest)
		return
	}
	if s.fsClient == nil {
		http.Error(w, "Firestore not configured — set DEBUG_BLOCKLIST env var and restart to revoke tokens", http.StatusServiceUnavailable)
		return
	}
	_, err = s.fsClient.Collection("debug_blocklist").Doc(id).Set(r.Context(), map[string]interface{}{
		"revoked_by": email,
		"revoked_at": time.Now().UTC(),
	})
	if err != nil {
		log.Printf("debug-token/revoke Firestore write failed id=%s: %v", id, err)
		http.Error(w, "failed to revoke token", http.StatusInternalServerError)
		return
	}
	log.Printf("revoked debug token id=%s by=%s", id, email)
	w.WriteHeader(http.StatusNoContent)
}

// verifyDebugCaller authenticates a /debug-token or /debug-token/revoke request
// using the same OIDC flow as /deploy. Returns the caller's email and OIDC subject.
// If DEBUG_ALLOWED_EMAIL is set, the email must match.
func (s *deployServer) verifyDebugCaller(r *http.Request) (email, sub string, err error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", "", fmt.Errorf("missing Bearer token")
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	if s.verifyToken != nil {
		// In bypass mode, verifyToken returns a project ID, not sub/email.
		// Treat the project ID as both email and sub for testing purposes.
		projectID, verifyErr := s.verifyToken(r.Context(), token, s.audience)
		if verifyErr != nil {
			return "", "", verifyErr
		}
		return projectID, projectID, nil
	}

	p, verifyErr := idtoken.Validate(r.Context(), token, s.audience)
	if verifyErr != nil {
		return "", "", fmt.Errorf("OIDC token validation: %w", verifyErr)
	}

	email, _ = p.Claims["email"].(string)
	sub, _ = p.Claims["sub"].(string)
	if email == "" || sub == "" {
		return "", "", fmt.Errorf("missing email or sub claim in token")
	}
	if s.debugAllowedEmail != "" && email != s.debugAllowedEmail {
		return "", "", fmt.Errorf("caller %q is not in DEBUG_ALLOWED_EMAIL", email)
	}
	return email, sub, nil
}

// verifyIDToken validates the Bearer token in Authorization, verifies its
// audience matches s.audience (SEC-1/SEC-3), and returns the caller's GCP
// project ID extracted from the service account email.
func (s *deployServer) verifyIDToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("missing Bearer token")
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	if s.verifyToken != nil {
		return s.verifyToken(r.Context(), token, s.audience)
	}

	// idtoken.Validate fetches Google's public keys and verifies signature,
	// expiry, issuer (accounts.google.com), AND audience — no SSRF possible.
	payload, err := idtoken.Validate(r.Context(), token, s.audience)
	if err != nil {
		return "", fmt.Errorf("OIDC token validation: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return "", fmt.Errorf("no email claim in token")
	}

	// Service account email format: name@project-id.iam.gserviceaccount.com
	projectID := extractProjectFromEmail(email)
	if projectID == "" {
		return "", fmt.Errorf("could not extract project from email %q", email)
	}
	return projectID, nil
}

// extractProjectFromEmail parses the project ID from a service account email.
// Format: <name>@<project-id>.iam.gserviceaccount.com
func extractProjectFromEmail(email string) string {
	at := strings.Index(email, "@")
	if at < 0 {
		return ""
	}
	domain := email[at+1:]
	const suffix = ".iam.gserviceaccount.com"
	if !strings.HasSuffix(domain, suffix) {
		return ""
	}
	return strings.TrimSuffix(domain, suffix)
}

// validateFragment wraps the fragment in a minimal server block and runs
// `caddy adapt --adapter caddyfile --validate` to check syntax and provisioning.
func (s *deployServer) validateFragment(fragment, listenAddr string) error {
	wrapped := fmt.Sprintf("%s {\n%s\n}\n", listenAddr, fragment)
	return s.validateCaddyfile(wrapped)
}

// validateCaddyfile runs `caddy adapt --adapter caddyfile --validate` on content.
func (s *deployServer) validateCaddyfile(content string) error {
	cmd := exec.Command(s.caddy(), "adapt", "--config", "-", "--adapter", "caddyfile", "--validate")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildMergedCaddyfile downloads all existing fragments from GCS, substitutes
// the fragment for projectID/serviceName with the new content, and returns
// the merged Caddyfile string.
func (s *deployServer) buildMergedCaddyfile(ctx context.Context, projectID, serviceName, newFragment string) (string, error) {
	fragments, err := s.listGCSFragments(ctx)
	if err != nil {
		return "", fmt.Errorf("listing GCS fragments: %w", err)
	}

	// Build a map of objName → content, replacing the target fragment.
	targetKey := fmt.Sprintf("%s/%s.caddyfile", projectID, serviceName)
	fragments[targetKey] = newFragment

	// Write fragments to a temp dir and call MergeFragments.
	tmpDir, err := os.MkdirTemp("", "caddygee-merge-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	for objName, content := range fragments {
		// Flatten the path: "project/service.caddyfile" → "project__service.caddyfile"
		safeName := strings.ReplaceAll(objName, "/", "__")
		if err := os.WriteFile(filepath.Join(tmpDir, safeName), []byte(content), 0o600); err != nil {
			return "", err
		}
	}

	return transpiler.MergeFragments(tmpDir, transpiler.Options{
		CloudRun:       true,
		ListenAddress:  s.listenAddr,
		TrustedProxies: s.trustedProxies,
		AdminAddress:   s.adminAddr,
		LogLevel:       os.Getenv("CADDY_LOG_LEVEL"),
	})
}

// buildAndWriteCaddyfile fetches all fragments from GCS, merges, and writes to disk.
func (s *deployServer) buildAndWriteCaddyfile(ctx context.Context) error {
	fragments, err := s.listGCSFragments(ctx)
	if err != nil {
		return fmt.Errorf("listing GCS fragments: %w", err)
	}
	if len(fragments) == 0 {
		return fmt.Errorf("no fragments in bucket")
	}

	tmpDir, err := os.MkdirTemp("", "caddygee-cold-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	for objName, content := range fragments {
		safeName := strings.ReplaceAll(objName, "/", "__")
		if err := os.WriteFile(filepath.Join(tmpDir, safeName), []byte(content), 0o600); err != nil {
			return err
		}
	}

	merged, err := transpiler.MergeFragments(tmpDir, transpiler.Options{
		CloudRun:      true,
		ListenAddress: s.listenAddr,
		AdminAddress:  s.adminAddr,
		LogLevel:      os.Getenv("CADDY_LOG_LEVEL"),
	})
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.caddyfilePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.caddyfilePath, []byte(merged), 0o644)
}

func (s *deployServer) writeFallbackCaddyfile() {
	content := fmt.Sprintf(`{
	admin %s
	auto_https off
}`, s.adminAddr) + fmt.Sprintf(`

%s {
	handle /health {
		respond 200
	}
	handle {
		respond "no routes configured" 503
	}
}
`, s.listenAddr)
	_ = os.MkdirAll(filepath.Dir(s.caddyfilePath), 0o755)
	_ = os.WriteFile(s.caddyfilePath, []byte(content), 0o644)
}

// caddyLoad sends a new Caddyfile to the Caddy admin API for hot reload.
// Caddy auto-rolls back if the config is rejected.
func (s *deployServer) caddyLoad(caddyfile string) error {
	// Convert Caddyfile to JSON first via caddy adapt.
	cmd := exec.Command(s.caddy(), "adapt", "--config", "-", "--adapter", "caddyfile")
	cmd.Stdin = strings.NewReader(caddyfile)
	jsonBytes, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("caddy adapt: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("caddy adapt: %w", err)
	}

	url := fmt.Sprintf("http://%s/load", s.adminAddr)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("building admin API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req) // HIGH-1: uses client with 30s timeout
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy /load returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// listGCSFragments returns all *.caddyfile objects in the bucket as a map of
// object name → content.
func (s *deployServer) listGCSFragments(ctx context.Context) (map[string]string, error) {
	bkt := s.gcs.Bucket(s.bucket)
	result := make(map[string]string)

	it := bkt.Objects(ctx, nil)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("listing objects: %w", err)
		}
		if !strings.HasSuffix(attrs.Name, ".caddyfile") {
			continue
		}
		rc, err := bkt.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", attrs.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", attrs.Name, err)
		}
		result[attrs.Name] = string(data)
	}
	return result, nil
}

// putGCS writes content to gs://<bucket>/<objName>.
func (s *deployServer) putGCS(ctx context.Context, objName string, content []byte) error {
	wc := s.gcs.Bucket(s.bucket).Object(objName).NewWriter(ctx)
	wc.ContentType = "text/plain"
	wc.Metadata = map[string]string{
		"updated": time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := wc.Write(content); err != nil {
		wc.Close()
		return err
	}
	return wc.Close()
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
