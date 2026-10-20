//go:build integration

package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// binaries built once per test run.
var (
	caddyBin       string
	caddygeeSrvBin string
	moduleRoot     string
	onceBuild      sync.Once
	buildErr       error
)

func buildBinaries(t *testing.T) {
	t.Helper()
	onceBuild.Do(func() {
		// Locate module root from the integration package directory.
		out, err := exec.Command("go", "env", "GOMOD").Output()
		if err != nil {
			buildErr = fmt.Errorf("finding module root: %w", err)
			return
		}
		moduleRoot = filepath.Dir(strings.TrimSpace(string(out)))

		tmp, err := os.MkdirTemp("", "caddygee-bins-*")
		if err != nil {
			buildErr = err
			return
		}
		t.Logf("building binaries into %s (module root: %s)", tmp, moduleRoot)

		caddyBin = filepath.Join(tmp, "caddy")
		buildCmd := exec.Command("go", "build", "-o", caddyBin, "./cmd/caddy")
		buildCmd.Dir = moduleRoot
		buildOut, err := buildCmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("building caddy: %w\n%s", err, buildOut)
			return
		}

		caddygeeSrvBin = filepath.Join(tmp, "caddygee-server")
		buildCmd = exec.Command("go", "build", "-o", caddygeeSrvBin, "./cmd/caddygee-server")
		buildCmd.Dir = moduleRoot
		buildOut, err = buildCmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("building caddygee-server: %w\n%s", err, buildOut)
			return
		}
		t.Logf("binaries built")
	})
	if buildErr != nil {
		t.Fatalf("build failed: %v", buildErr)
	}
}

// fakeGCS is an in-process fake Google Cloud Storage JSON API v1 server.
// It supports the minimal surface used by the GCS storage client:
//   - GET /storage/v1/b/{bucket}           — bucket exists
//   - GET /storage/v1/b/{bucket}/o         — list objects
//   - GET /storage/v1/b/{bucket}/o/{name}  — get object metadata
//   - GET /storage/v1/b/{bucket}/o/{name}?alt=media — download
//   - POST /upload/storage/v1/b/{bucket}/o?uploadType=multipart — upload
type fakeGCS struct {
	mu      sync.RWMutex
	objects map[string][]byte // key: "bucket/name"
	srv     *httptest.Server
	t       *testing.T
}

func newFakeGCS(t *testing.T) *fakeGCS {
	f := &fakeGCS{objects: make(map[string][]byte), t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	f.srv = httptest.NewServer(mux)
	return f
}

func (f *fakeGCS) URL() string { return f.srv.URL }

func (f *fakeGCS) Close() { f.srv.Close() }

// Put stores an object directly (used to pre-seed the bucket).
func (f *fakeGCS) Put(bucket, name, content string) {
	f.mu.Lock()
	f.objects[bucket+"/"+name] = []byte(content)
	f.mu.Unlock()
}

// Get retrieves an object directly (used for assertions).
func (f *fakeGCS) Get(bucket, name string) (string, bool) {
	f.mu.RLock()
	b, ok := f.objects[bucket+"/"+name]
	f.mu.RUnlock()
	return string(b), ok
}

func (f *fakeGCS) handle(w http.ResponseWriter, r *http.Request) {
	if f.t != nil {
		f.t.Logf("fakeGCS: %s %s %s", r.Method, r.URL.Path, r.URL.RawQuery)
	}
	path := r.URL.Path

	// Upload: POST /upload/storage/v1/b/{bucket}/o
	if strings.HasPrefix(path, "/upload/storage/v1/b/") && r.Method == http.MethodPost {
		f.handleUpload(w, r, strings.TrimPrefix(path, "/upload/storage/v1/b/"))
		return
	}

	// Storage API: /storage/v1/b/{bucket}[/o[/{name}]]
	rest := strings.TrimPrefix(path, "/storage/v1/b/")
	if rest != path {
		// JSON API path handled below.
	} else {
		// XML-API / emulator direct path: /{bucket}/{object...}
		// Used by the GCS client when STORAGE_EMULATOR_HOST is set for downloads.
		trimmed := strings.TrimPrefix(path, "/")
		slash := strings.IndexByte(trimmed, '/')
		if slash >= 0 && r.Method == http.MethodGet {
			bucket := trimmed[:slash]
			name := trimmed[slash+1:]
			f.handleDownload(w, r, bucket, name)
			return
		}
		http.NotFound(w, r)
		return
	}

	parts := strings.SplitN(rest, "/", 3)
	bucket := parts[0]

	switch {
	case len(parts) == 1:
		// GET /storage/v1/b/{bucket} — bucket metadata
		f.handleBucket(w, r, bucket)
	case len(parts) == 2 && parts[1] == "o":
		// GET /storage/v1/b/{bucket}/o — list objects
		f.handleList(w, r, bucket)
	case len(parts) == 3 && parts[1] == "o":
		name := parts[2]
		// URL-decode any %2F in name
		if decoded, err := decodePathSegment(name); err == nil {
			name = decoded
		}
		if r.URL.Query().Get("alt") == "media" {
			f.handleDownload(w, r, bucket, name)
		} else {
			f.handleMetadata(w, r, bucket, name)
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGCS) handleBucket(w http.ResponseWriter, _ *http.Request, bucket string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"kind":"storage#bucket","name":%q}`, bucket)
}

type gcsObject struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Bucket string `json:"bucket"`
	Size   string `json:"size"`
}

type gcsListResponse struct {
	Kind  string      `json:"kind"`
	Items []gcsObject `json:"items"`
}

func (f *fakeGCS) handleList(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	f.mu.RLock()
	var items []gcsObject
	for key, val := range f.objects {
		pfx := bucket + "/"
		if !strings.HasPrefix(key, pfx) {
			continue
		}
		name := strings.TrimPrefix(key, pfx)
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		items = append(items, gcsObject{
			Kind:   "storage#object",
			Name:   name,
			Bucket: bucket,
			Size:   fmt.Sprint(len(val)),
		})
	}
	f.mu.RUnlock()
	resp := gcsListResponse{Kind: "storage#objects", Items: items}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (f *fakeGCS) handleMetadata(w http.ResponseWriter, _ *http.Request, bucket, name string) {
	f.mu.RLock()
	val, ok := f.objects[bucket+"/"+name]
	f.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	obj := gcsObject{Kind: "storage#object", Name: name, Bucket: bucket, Size: fmt.Sprint(len(val))}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(obj)
}

func (f *fakeGCS) handleDownload(w http.ResponseWriter, _ *http.Request, bucket, name string) {
	f.mu.RLock()
	val, ok := f.objects[bucket+"/"+name]
	f.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(val)
}

func (f *fakeGCS) handleUpload(w http.ResponseWriter, r *http.Request, rest string) {
	// rest = "{bucket}/o"
	bucket := strings.TrimSuffix(rest, "/o")
	name := r.URL.Query().Get("name")

	uploadType := r.URL.Query().Get("uploadType")
	var content []byte

	switch uploadType {
	case "multipart":
		ct := r.Header.Get("Content-Type")
		_, params, err := mime.ParseMediaType(ct)
		if err != nil {
			http.Error(w, "bad content-type: "+err.Error(), http.StatusBadRequest)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		// First part: JSON metadata
		metaPart, err := mr.NextPart()
		if err != nil {
			http.Error(w, "reading metadata part: "+err.Error(), http.StatusBadRequest)
			return
		}
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(metaPart).Decode(&meta); err != nil {
			http.Error(w, "decoding metadata: "+err.Error(), http.StatusBadRequest)
			return
		}
		if name == "" {
			name = meta.Name
		}
		// Second part: object body
		dataPart, err := mr.NextPart()
		if err != nil {
			http.Error(w, "reading data part: "+err.Error(), http.StatusBadRequest)
			return
		}
		content, err = io.ReadAll(dataPart)
		if err != nil {
			http.Error(w, "reading data: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "media":
		var err error
		content, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		// resumable or unknown — try reading body directly
		var err error
		content, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading body: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if name == "" {
		http.Error(w, "object name required", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.objects[bucket+"/"+name] = content
	f.mu.Unlock()

	obj := gcsObject{Kind: "storage#object", Name: name, Bucket: bucket, Size: fmt.Sprint(len(content))}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(obj)
}

func decodePathSegment(s string) (string, error) {
	var buf strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			var b byte
			_, err := fmt.Sscanf(s[i+1:i+3], "%02X", &b)
			if err != nil {
				return "", err
			}
			buf.WriteByte(b)
			i += 3
		} else {
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.String(), nil
}

// gatewayHandle manages a running caddygee-server and caddy pair.
type gatewayHandle struct {
	t           *testing.T
	srvCmd      *exec.Cmd
	caddyCmd    *exec.Cmd
	deployPort  string
	caddyPort   string
	adminPort   string
	bucket      string
	workDir     string
	gcs         *fakeGCS
	projectID   string
}

// startGateway builds and starts caddygee-server + caddy for one test.
// envName sets ENVIRONMENT_NAME in the subprocess.
func startGateway(t *testing.T, envName string) *gatewayHandle {
	t.Helper()
	buildBinaries(t)

	gcs := newFakeGCS(t)
	t.Cleanup(gcs.Close)

	workDir := t.TempDir()
	caddyfilePath := filepath.Join(workDir, "Caddyfile")
	bucket := "test-bucket"
	projectID := "test-project"
	audience := "http://test-audience"

	deployPort := freePort(t)
	caddyPort := freePort(t)
	adminPort := freePort(t)

	env := append(os.Environ(),
		"STORAGE_EMULATOR_HOST="+strings.TrimPrefix(gcs.URL(), "http://"),
		"CONFIG_BUCKET="+bucket,
		"CADDYGEE_AUDIENCE="+audience,
		"CADDYGEE_BYPASS_AUTH=1",
		"DEPLOY_PORT="+deployPort,
		"CADDY_ADMIN=localhost:"+adminPort,
		"CADDY_BIN="+caddyBin,
		"CADDYFILE_PATH="+caddyfilePath,
		"LISTEN_ADDRESS=:"+caddyPort,
		"ENVIRONMENT_NAME="+envName,
		// Strip any ADC that might interfere with the emulator.
		"GOOGLE_APPLICATION_CREDENTIALS=",
	)

	srvCmd := exec.Command(caddygeeSrvBin)
	srvCmd.Env = env
	srvCmd.Dir = workDir
	srvCmd.Stdout = newTestLog(t, "[server] ")
	srvCmd.Stderr = newTestLog(t, "[server] ")
	if err := srvCmd.Start(); err != nil {
		t.Fatalf("starting caddygee-server: %v", err)
	}
	t.Cleanup(func() { srvCmd.Process.Kill(); srvCmd.Wait() })

	// Wait for caddygee-server to write initial Caddyfile.
	if err := waitForFile(caddyfilePath, 10*time.Second); err != nil {
		t.Fatalf("waiting for initial Caddyfile: %v", err)
	}

	// Start caddy with the generated Caddyfile.
	caddyCmd := exec.Command(caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	caddyCmd.Env = append(env, "CADDYFILE_PATH="+caddyfilePath)
	caddyCmd.Dir = workDir
	caddyCmd.Stdout = newTestLog(t, "[caddy] ")
	caddyCmd.Stderr = newTestLog(t, "[caddy] ")
	if err := caddyCmd.Start(); err != nil {
		t.Fatalf("starting caddy: %v", err)
	}
	t.Cleanup(func() { caddyCmd.Process.Kill(); caddyCmd.Wait() })

	h := &gatewayHandle{
		t:          t,
		srvCmd:     srvCmd,
		caddyCmd:   caddyCmd,
		deployPort: deployPort,
		caddyPort:  caddyPort,
		adminPort:  adminPort,
		bucket:     bucket,
		workDir:    workDir,
		gcs:        gcs,
		projectID:  projectID,
	}

	// Wait for caddy admin API to be ready.
	if err := waitForHTTP("http://localhost:"+adminPort+"/config/", 15*time.Second); err != nil {
		t.Fatalf("caddy admin not ready: %v", err)
	}
	// Wait for caddy to start serving.
	if err := waitForTCP("localhost:"+caddyPort, 10*time.Second); err != nil {
		t.Fatalf("caddy not listening: %v", err)
	}

	return h
}

// Deploy transpiles apiproxy at bundlePath, substitutes upstreamURL for
// UPSTREAM_PLACEHOLDER, and POSTs the fragment to caddygee-server.
func (h *gatewayHandle) Deploy(bundlePath, serviceName, upstreamURL string) {
	h.t.Helper()

	// Resolve bundlePath relative to module root if not absolute.
	if !filepath.IsAbs(bundlePath) {
		bundlePath = filepath.Join(moduleRoot, bundlePath)
	}

	// Transpile to fragment.
	fragPath := filepath.Join(h.t.TempDir(), serviceName+".caddyfile")
	transpileCmd := exec.Command(
		"go", "run", "./cmd/caddygee",
		"transpile", "--input", bundlePath, "--fragment", "--output", fragPath,
	)
	transpileCmd.Dir = moduleRoot
	out, err := transpileCmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("transpile %s: %v\n%s", serviceName, err, out)
	}

	frag, err := os.ReadFile(fragPath)
	if err != nil {
		h.t.Fatalf("reading fragment: %v", err)
	}

	// Substitute upstream placeholder.
	frag = bytes.ReplaceAll(frag, []byte("http://UPSTREAM_PLACEHOLDER"), []byte(upstreamURL))

	// POST to deploy endpoint. In bypass mode the Bearer token IS the project ID.
	req, err := http.NewRequest(http.MethodPost,
		"http://localhost:"+h.deployPort+"/deploy",
		bytes.NewReader(frag),
	)
	if err != nil {
		h.t.Fatalf("building deploy request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.projectID)
	req.Header.Set("X-Service-Name", serviceName)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("deploy request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("deploy returned %d: %s", resp.StatusCode, body)
	}

	// Give caddy a moment to apply the new config.
	time.Sleep(200 * time.Millisecond)
}

// DeployWithSubs is like Deploy but applies additional byte-level substitutions
// to the fragment before posting. subs maps old → new (both as byte slices).
func (h *gatewayHandle) DeployWithSubs(bundlePath, serviceName, upstreamURL string, subs map[string]string) {
	h.t.Helper()

	if !filepath.IsAbs(bundlePath) {
		bundlePath = filepath.Join(moduleRoot, bundlePath)
	}

	fragPath := filepath.Join(h.t.TempDir(), serviceName+".caddyfile")
	transpileCmd := exec.Command(
		"go", "run", "./cmd/caddygee",
		"transpile", "--input", bundlePath, "--fragment", "--output", fragPath,
	)
	transpileCmd.Dir = moduleRoot
	out, err := transpileCmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("transpile %s: %v\n%s", serviceName, err, out)
	}

	frag, err := os.ReadFile(fragPath)
	if err != nil {
		h.t.Fatalf("reading fragment: %v", err)
	}

	frag = bytes.ReplaceAll(frag, []byte("http://UPSTREAM_PLACEHOLDER"), []byte(upstreamURL))
	for old, new := range subs {
		frag = bytes.ReplaceAll(frag, []byte(old), []byte(new))
	}

	req, err := http.NewRequest(http.MethodPost,
		"http://localhost:"+h.deployPort+"/deploy",
		bytes.NewReader(frag),
	)
	if err != nil {
		h.t.Fatalf("building deploy request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.projectID)
	req.Header.Set("X-Service-Name", serviceName)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("deploy request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("deploy returned %d: %s", resp.StatusCode, body)
	}

	time.Sleep(200 * time.Millisecond)
}

// GET performs a GET request against caddy's listener.
func (h *gatewayHandle) GET(path string, headers ...string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		"http://localhost:"+h.caddyPort+path, nil)
	if err != nil {
		h.t.Fatalf("building request: %v", err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// helpers

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	_, port, _ := net.SplitHostPort(addr)
	return port
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", path)
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for TCP %s", addr)
}

func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for HTTP %s", url)
}

// testLog redirects subprocess output to t.Log.
type testLog struct {
	t      *testing.T
	prefix string
	buf    strings.Builder
}

func newTestLog(t *testing.T, prefix string) *testLog {
	return &testLog{t: t, prefix: prefix}
}

func (l *testLog) Write(p []byte) (int, error) {
	l.buf.Write(p)
	for {
		s := l.buf.String()
		idx := strings.IndexByte(s, '\n')
		if idx < 0 {
			break
		}
		l.t.Log(l.prefix + s[:idx])
		l.buf.Reset()
		l.buf.WriteString(s[idx+1:])
	}
	return len(p), nil
}
