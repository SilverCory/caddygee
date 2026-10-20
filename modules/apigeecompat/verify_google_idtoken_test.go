package apigeecompat_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"caddygee/modules/apigeecompat"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func stubIDTokenValidate(email, sub, hd string, err error) func(ctx context.Context, token, audience string) (string, string, string, error) {
	return func(_ context.Context, _, _ string) (string, string, string, error) {
		return email, sub, hd, err
	}
}

func TestVerifyGoogleIDToken_AcceptsValidToken(t *testing.T) {
	restore := apigeecompat.SetGoogleIDTokenValidate(stubIDTokenValidate("svc@proj.iam.gserviceaccount.com", "123", "proj.com", nil))
	defer restore()

	v := &apigeecompat.VerifyGoogleIDToken{
		PolicyName: "MeshAuth",
		Audience:   "https://service-b.run.app",
	}
	if err := v.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	var capturedFS *apigeecompat.FlowState
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedFS, _ = apigeecompat.GetFlowState(r.Context())
		return nil
	})

	mgr := apigeecompat.FlowStateManager{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer fake-token")
	w := httptest.NewRecorder()

	chain := wrapMiddleware(v, next)
	if err := mgr.ServeHTTP(w, req, chain); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedFS == nil {
		t.Fatal("no flow state")
	}
	if got := capturedFS.GetString("google_idtoken.MeshAuth.email"); got != "svc@proj.iam.gserviceaccount.com" {
		t.Errorf("email: got %q", got)
	}
	if got := capturedFS.GetString("google_idtoken.MeshAuth.sub"); got != "123" {
		t.Errorf("sub: got %q", got)
	}
	if got := capturedFS.GetString("google_idtoken.MeshAuth.hd"); got != "proj.com" {
		t.Errorf("hd: got %q", got)
	}
}

func TestVerifyGoogleIDToken_RejectsInvalidToken(t *testing.T) {
	restore := apigeecompat.SetGoogleIDTokenValidate(stubIDTokenValidate("", "", "", errors.New("bad token")))
	defer restore()

	v := &apigeecompat.VerifyGoogleIDToken{
		PolicyName: "MeshAuth",
		Audience:   "https://service-b.run.app",
	}
	if err := v.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()

	mgr := apigeecompat.FlowStateManager{}
	if err := mgr.ServeHTTP(w, req, wrapMiddleware(v, terminal)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestVerifyGoogleIDToken_RejectsMissingToken(t *testing.T) {
	restore := apigeecompat.SetGoogleIDTokenValidate(stubIDTokenValidate("svc@proj.iam.gserviceaccount.com", "123", "", nil))
	defer restore()

	v := &apigeecompat.VerifyGoogleIDToken{
		PolicyName: "MeshAuth",
		Audience:   "https://service-b.run.app",
	}
	if err := v.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no Authorization header
	w := httptest.NewRecorder()

	mgr := apigeecompat.FlowStateManager{}
	if err := mgr.ServeHTTP(w, req, wrapMiddleware(v, terminal)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestVerifyGoogleIDToken_AllowedEmailsPass(t *testing.T) {
	restore := apigeecompat.SetGoogleIDTokenValidate(stubIDTokenValidate("allowed@proj.iam.gserviceaccount.com", "x", "", nil))
	defer restore()

	v := &apigeecompat.VerifyGoogleIDToken{
		PolicyName:    "MeshAuth",
		Audience:      "https://service-b.run.app",
		AllowedEmails: []string{"allowed@proj.iam.gserviceaccount.com"},
	}
	if err := v.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer fake")
	w := httptest.NewRecorder()

	mgr := apigeecompat.FlowStateManager{}
	if err := mgr.ServeHTTP(w, req, wrapMiddleware(v, terminal)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestVerifyGoogleIDToken_AllowedEmailsBlock(t *testing.T) {
	restore := apigeecompat.SetGoogleIDTokenValidate(stubIDTokenValidate("other@proj.iam.gserviceaccount.com", "x", "", nil))
	defer restore()

	v := &apigeecompat.VerifyGoogleIDToken{
		PolicyName:    "MeshAuth",
		Audience:      "https://service-b.run.app",
		AllowedEmails: []string{"allowed@proj.iam.gserviceaccount.com"},
	}
	if err := v.Provision(apigeecompat.ZeroContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer fake")
	w := httptest.NewRecorder()

	mgr := apigeecompat.FlowStateManager{}
	if err := mgr.ServeHTTP(w, req, wrapMiddleware(v, terminal)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
