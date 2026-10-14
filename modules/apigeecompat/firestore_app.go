package apigeecompat

import (
	"context"
	"encoding/json"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

func init() {
	caddy.RegisterModule(FirestoreApp{})
}

// FirestoreApp is a Caddy app module that provides a shared Firestore client
// to apigeecompat handler modules (apigee_verify_api_key, apigee_quota, apigee_kvm).
//
// Configure it in the Caddyfile global options block or via JSON:
//
//	{
//	    "apps": {
//	        "firestore": {
//	            "project_id": "my-gcp-project"
//	        }
//	    }
//	}
//
// The client uses Application Default Credentials. No credentials config is
// needed on Cloud Run — the service account is picked up automatically.
type FirestoreApp struct {
	// ProjectID is the GCP project containing the Firestore database.
	ProjectID string `json:"project_id"`

	// DatabaseID is the Firestore database name (default: "(default)").
	DatabaseID string `json:"database_id,omitempty"`

	client *firestore.Client
	logger *zap.Logger
}

// CaddyModule returns the Caddy module metadata.
func (FirestoreApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "firestore",
		New: func() caddy.Module { return new(FirestoreApp) },
	}
}

// Provision creates the Firestore client.
func (f *FirestoreApp) Provision(ctx caddy.Context) error {
	f.logger = ctx.Logger()
	if f.ProjectID == "" {
		return fmt.Errorf("firestore: project_id is required")
	}
	dbID := f.DatabaseID
	if dbID == "" {
		dbID = "(default)"
	}

	var opts []option.ClientOption
	client, err := firestore.NewClientWithDatabase(context.Background(), f.ProjectID, dbID, opts...)
	if err != nil {
		return fmt.Errorf("firestore: creating client: %w", err)
	}
	f.client = client
	f.logger.Info("firestore: connected",
		zap.String("project", f.ProjectID),
		zap.String("database", dbID))
	return nil
}

// Start implements caddy.App. No-op; the client is ready after Provision.
func (f *FirestoreApp) Start() error { return nil }

// Stop closes the Firestore client.
func (f *FirestoreApp) Stop() error {
	if f.client != nil {
		return f.client.Close()
	}
	return nil
}

// Client returns the shared Firestore client.
func (f *FirestoreApp) Client() *firestore.Client {
	return f.client
}

// GetFirestoreApp retrieves the FirestoreApp from the Caddy context, if configured.
// Returns nil, false when the app is not configured (Firestore features disabled).
func GetFirestoreApp(ctx caddy.Context) (*FirestoreApp, bool) {
	val, err := ctx.AppIfConfigured("firestore")
	if err != nil {
		return nil, false
	}
	app, ok := val.(*FirestoreApp)
	return app, ok
}

// Interface guards.
var (
	_ caddy.Module      = FirestoreApp{}
	_ caddy.Provisioner = (*FirestoreApp)(nil)
	_ caddy.App         = (*FirestoreApp)(nil)
)

// UnmarshalJSON supports JSON configuration.
func (f *FirestoreApp) UnmarshalJSON(b []byte) error {
	type plain FirestoreApp
	return json.Unmarshal(b, (*plain)(f))
}
