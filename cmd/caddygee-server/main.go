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
//	CONFIG_BUCKET   GCS bucket name holding fragment files (required)
//	PORT            HTTP port for the deploy endpoint (default: 9090)
//	CADDY_ADMIN     Caddy admin API address (default: localhost:2019)
//	CADDYFILE_PATH  Path to write the merged Caddyfile (default: /etc/caddy/Caddyfile)
//	LISTEN_ADDRESS  Caddy listen address passed to the merger (default: :8080)
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

	"cloud.google.com/go/storage"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/iterator"

	"caddygee/internal/transpiler"
)

func main() {
	bucket := mustEnv("CONFIG_BUCKET")
	audience := mustEnv("CADDYGEE_AUDIENCE") // SEC-1: Cloud Run service URL used as OIDC audience
	port := envOr("PORT", "9090")
	adminAddr := envOr("CADDY_ADMIN", "localhost:2019")
	caddyfilePath := envOr("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
	listenAddr := envOr("LISTEN_ADDRESS", ":8080")

	ctx := context.Background()
	gcs, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("creating GCS client: %v", err)
	}

	srv := &deployServer{
		bucket:        bucket,
		audience:      audience,
		adminAddr:     adminAddr,
		caddyfilePath: caddyfilePath,
		listenAddr:    listenAddr,
		gcs:           gcs,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}

	// Cold start: fetch fragments from GCS and write initial Caddyfile.
	if err := srv.buildAndWriteCaddyfile(ctx); err != nil {
		log.Printf("WARNING: cold-start merge failed (no fragments yet?): %v", err)
		// Write a minimal fallback Caddyfile so Caddy can start.
		srv.writeFallbackCaddyfile()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/deploy", srv.handleDeploy)
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

type deployServer struct {
	bucket        string
	audience      string       // SEC-1: expected OIDC audience (Cloud Run service URL)
	adminAddr     string
	caddyfilePath string
	listenAddr    string
	gcs           *storage.Client
	httpClient    *http.Client // HIGH-1: shared client with timeout for admin API calls
	mu            sync.Mutex   // serialises concurrent deploys
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
	if err := validateFragment(string(fragment), s.listenAddr); err != nil {
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
	if err := validateCaddyfile(merged); err != nil {
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

// verifyIDToken validates the Bearer token in Authorization, verifies its
// audience matches s.audience (SEC-1/SEC-3), and returns the caller's GCP
// project ID extracted from the service account email.
func (s *deployServer) verifyIDToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("missing Bearer token")
	}
	token := strings.TrimPrefix(auth, "Bearer ")

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
func validateFragment(fragment, listenAddr string) error {
	wrapped := fmt.Sprintf("%s {\n%s\n}\n", listenAddr, fragment)
	return validateCaddyfile(wrapped)
}

// validateCaddyfile runs `caddy adapt --adapter caddyfile --validate` on content.
func validateCaddyfile(content string) error {
	cmd := exec.Command("caddy", "adapt", "--adapter", "caddyfile", "--validate")
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
		CloudRun:      true,
		ListenAddress: s.listenAddr,
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
	admin localhost:2019
	auto_https off
}

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
	cmd := exec.Command("caddy", "adapt", "--adapter", "caddyfile")
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
