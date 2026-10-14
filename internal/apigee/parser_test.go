package apigee_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"caddygee/internal/apigee"
)

func testdataPath(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "testdata")
	return filepath.Join(append([]string{root}, parts...)...)
}

func TestParseBundle_Simple(t *testing.T) {
	bundle, err := apigee.ParseBundle(testdataPath("simple"))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	// Proxy endpoints
	if len(bundle.ProxyEndpoints) != 1 {
		t.Fatalf("expected 1 proxy endpoint, got %d", len(bundle.ProxyEndpoints))
	}
	ep := bundle.ProxyEndpoints[0]
	if ep.Name != "default" {
		t.Errorf("proxy endpoint name: got %q, want %q", ep.Name, "default")
	}
	if ep.HTTPProxyConnection.BasePath != "/api/v1" {
		t.Errorf("base path: got %q, want %q", ep.HTTPProxyConnection.BasePath, "/api/v1")
	}

	// Flows
	if len(ep.Flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(ep.Flows))
	}
	if ep.Flows[0].Name != "GetUsers" {
		t.Errorf("flow[0] name: got %q, want %q", ep.Flows[0].Name, "GetUsers")
	}
	if ep.Flows[0].Condition == "" {
		t.Error("flow[0] condition should not be empty")
	}

	// Steps
	if len(ep.Flows[0].Request.Steps) != 1 {
		t.Fatalf("expected 1 step in GetUsers request, got %d", len(ep.Flows[0].Request.Steps))
	}
	if ep.Flows[0].Request.Steps[0].Name != "ExtractAuthToken" {
		t.Errorf("step name: got %q, want %q", ep.Flows[0].Request.Steps[0].Name, "ExtractAuthToken")
	}

	// Target endpoints
	if len(bundle.TargetEndpoints) != 1 {
		t.Fatalf("expected 1 target endpoint, got %d", len(bundle.TargetEndpoints))
	}
	te := bundle.TargetEndpoints[0]
	if te.HTTPTargetConnection.URL != "https://backend-service.internal:8080" {
		t.Errorf("target URL: got %q, want %q", te.HTTPTargetConnection.URL, "https://backend-service.internal:8080")
	}

	// Policies
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(bundle.Policies))
	}
	pol, ok := bundle.Policies["ExtractAuthToken"]
	if !ok {
		t.Fatal("policy ExtractAuthToken not found")
	}
	if pol.Type != "AssignMessage" {
		t.Errorf("policy type: got %q, want %q", pol.Type, "AssignMessage")
	}
	if pol.AssignMessage == nil {
		t.Fatal("AssignMessage config should not be nil")
	}
}

func TestParseBundle_MissingPoliciesDir(t *testing.T) {
	// A bundle with no policies/ dir should not error.
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "proxies", "default.xml"), `<ProxyEndpoint name="ep">
		<HTTPProxyConnection><BasePath>/v1</BasePath></HTTPProxyConnection>
		<PreFlow name="PreFlow"><Request/><Response/></PreFlow>
		<PostFlow name="PostFlow"><Request/><Response/></PostFlow>
		<Flows/>
	</ProxyEndpoint>`)
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "targets", "default.xml"), `<TargetEndpoint name="t">
		<HTTPTargetConnection><URL>http://backend</URL></HTTPTargetConnection>
		<PreFlow name="PreFlow"><Request/><Response/></PreFlow>
		<PostFlow name="PostFlow"><Request/><Response/></PostFlow>
		<Flows/>
	</TargetEndpoint>`)

	bundle, err := apigee.ParseBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bundle.Policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(bundle.Policies))
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestParseBundle_NonexistentPath(t *testing.T) {
	_, err := apigee.ParseBundle("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

func TestParseBundle_ServiceCalloutPolicy(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "policies", "CallAuthService.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<ServiceCallout name="CallAuthService">
    <Response>authResponse</Response>
    <HTTPTargetConnection>
        <URL>https://auth.internal/validate</URL>
    </HTTPTargetConnection>
</ServiceCallout>`)
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "proxies", "default.xml"), `<ProxyEndpoint name="ep">
		<HTTPProxyConnection><BasePath>/v1</BasePath></HTTPProxyConnection>
		<PreFlow name="PreFlow"><Request/><Response/></PreFlow>
		<PostFlow name="PostFlow"><Request/><Response/></PostFlow>
		<Flows/>
	</ProxyEndpoint>`)
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "targets", "default.xml"), `<TargetEndpoint name="t">
		<HTTPTargetConnection><URL>http://backend</URL></HTTPTargetConnection>
		<PreFlow name="PreFlow"><Request/><Response/></PreFlow>
		<PostFlow name="PostFlow"><Request/><Response/></PostFlow>
		<Flows/>
	</TargetEndpoint>`)

	bundle, err := apigee.ParseBundle(dir)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	pol, ok := bundle.Policies["CallAuthService"]
	if !ok {
		t.Fatal("policy CallAuthService not found")
	}
	if pol.Type != "ServiceCallout" {
		t.Errorf("policy type: got %q, want %q", pol.Type, "ServiceCallout")
	}
	if pol.ServiceCallout == nil {
		t.Fatal("ServiceCallout config should not be nil")
	}
	if pol.ServiceCallout.HTTPTargetConnection.URL != "https://auth.internal/validate" {
		t.Errorf("target URL: got %q, want %q", pol.ServiceCallout.HTTPTargetConnection.URL, "https://auth.internal/validate")
	}
	if pol.ServiceCallout.Response != "authResponse" {
		t.Errorf("response var: got %q, want %q", pol.ServiceCallout.Response, "authResponse")
	}
}

func TestParseBundle_UnknownPolicyType(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "policies", "VerifyOAuth.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<OAuthV2 name="VerifyOAuth">
    <Operation>VerifyAccessToken</Operation>
</OAuthV2>`)
	mustWriteFile(t, filepath.Join(dir, "apiproxy", "proxies", "default.xml"), `<ProxyEndpoint name="ep">
		<HTTPProxyConnection><BasePath>/v1</BasePath></HTTPProxyConnection>
		<PreFlow name="PreFlow"><Request/><Response/></PreFlow>
		<PostFlow name="PostFlow"><Request/><Response/></PostFlow>
		<Flows/>
	</ProxyEndpoint>`)

	bundle, err := apigee.ParseBundle(dir)
	if err != nil {
		t.Fatalf("ParseBundle unexpected error: %v", err)
	}
	pol, ok := bundle.Policies["VerifyOAuth"]
	if !ok {
		t.Fatal("policy VerifyOAuth not found")
	}
	if pol.Type != "OAuthV2" {
		t.Errorf("policy type: got %q, want %q", pol.Type, "OAuthV2")
	}
}
