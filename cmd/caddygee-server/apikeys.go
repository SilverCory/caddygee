package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"caddygee/modules/apigeecompat"
)

// registerAPIKeyRoutes registers developer/app/product management endpoints on mux.
// All require OIDC authentication via verifyDebugCaller.
func (s *deployServer) registerAPIKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/developers", s.handleDevelopers)
	mux.HandleFunc("/developers/", s.handleDeveloper)
	mux.HandleFunc("/apps", s.handleApps)
	mux.HandleFunc("/apps/", s.handleApp)
	mux.HandleFunc("/products", s.handleProducts)
	mux.HandleFunc("/products/", s.handleProduct)
}

func (s *deployServer) requireFS(w http.ResponseWriter) bool {
	if s.fsClient == nil {
		http.Error(w, "Firestore not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (s *deployServer) requireAuth(w http.ResponseWriter, r *http.Request) (email string, ok bool) {
	e, _, err := s.verifyDebugCaller(r)
	if err != nil {
		log.Printf("API key mgmt auth failed: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return e, true
}

// ─── Developers ───────────────────────────────────────────────────────────────

type developerDoc struct {
	Email     string    `firestore:"email" json:"email"`
	FirstName string    `firestore:"first_name" json:"first_name"`
	LastName  string    `firestore:"last_name" json:"last_name"`
	Status    string    `firestore:"status" json:"status"`
	CreatedBy string    `firestore:"created_by" json:"created_by"`
	CreatedAt time.Time `firestore:"created_at" json:"created_at"`
}

// handleDevelopers handles POST /developers.
func (s *deployServer) handleDevelopers(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	email, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	devID := slugID(req.Email)
	doc := developerDoc{
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Status:    "active",
		CreatedBy: email,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := s.fsClient.Collection("developers").Doc(devID).Set(r.Context(), doc); err != nil {
		log.Printf("create developer: %v", err)
		http.Error(w, "failed to create developer", http.StatusInternalServerError)
		return
	}

	log.Printf("created developer id=%s email=%s by=%s", devID, req.Email, email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"developer_id": devID,
		"email":        req.Email,
		"status":       "active",
	})
}

// handleDeveloper handles GET /developers/{id} and DELETE /developers/{id}.
func (s *deployServer) handleDeveloper(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}

	devID := strings.TrimPrefix(r.URL.Path, "/developers/")
	if devID == "" {
		http.Error(w, "developer ID required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		snap, err := s.fsClient.Collection("developers").Doc(devID).Get(ctx)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		var doc developerDoc
		if err := snap.DataTo(&doc); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"developer_id": devID,
			"email":        doc.Email,
			"first_name":   doc.FirstName,
			"last_name":    doc.LastName,
			"status":       doc.Status,
			"created_by":   doc.CreatedBy,
			"created_at":   doc.CreatedAt,
		}
		json.NewEncoder(w).Encode(resp)

	case http.MethodDelete:
		_, err := s.fsClient.Collection("developers").Doc(devID).Update(ctx, []firestore.Update{
			{Path: "status", Value: "inactive"},
		})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}
		log.Printf("deactivated developer id=%s", devID)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

type appDoc struct {
	Name        string    `firestore:"name" json:"name"`
	DeveloperID string    `firestore:"developer_id" json:"developer_id"`
	ConsumerKey string    `firestore:"consumer_key" json:"consumer_key"` // sha256 hash (audit)
	Status      string    `firestore:"status" json:"status"`
	ProductIDs  []string  `firestore:"product_ids" json:"product_ids"`
	CreatedBy   string    `firestore:"created_by" json:"created_by"`
	CreatedAt   time.Time `firestore:"created_at" json:"created_at"`
}

// handleApps handles POST /apps.
func (s *deployServer) handleApps(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	email, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string   `json:"name"`
		DeveloperID string   `json:"developer_id"`
		ProductIDs  []string `json:"product_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.DeveloperID == "" {
		http.Error(w, "name and developer_id are required", http.StatusBadRequest)
		return
	}

	// Generate a raw API key (32 random bytes encoded as base32).
	rawKey, err := generateKey()
	if err != nil {
		log.Printf("generate key: %v", err)
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}
	keyHash := apigeecompat.HashKey(rawKey)
	appID := generateID()

	ctx := r.Context()

	// Write the api_keys lookup doc.
	apiKeyEntry := map[string]interface{}{
		"app_id":  appID,
		"enabled": true,
	}
	if _, err := s.fsClient.Collection("api_keys").Doc(keyHash).Set(ctx, apiKeyEntry); err != nil {
		log.Printf("write api_keys doc: %v", err)
		http.Error(w, "failed to create API key", http.StatusInternalServerError)
		return
	}

	// Write the app doc.
	app := appDoc{
		Name:        req.Name,
		DeveloperID: req.DeveloperID,
		ConsumerKey: keyHash,
		Status:      "approved",
		ProductIDs:  req.ProductIDs,
		CreatedBy:   email,
		CreatedAt:   time.Now().UTC(),
	}
	if _, err := s.fsClient.Collection("apps").Doc(appID).Set(ctx, app); err != nil {
		log.Printf("write app doc: %v", err)
		http.Error(w, "failed to create app", http.StatusInternalServerError)
		return
	}

	log.Printf("created app id=%s developer=%s by=%s", appID, req.DeveloperID, email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_id":       appID,
		"name":         req.Name,
		"developer_id": req.DeveloperID,
		"product_ids":  req.ProductIDs,
		"status":       "approved",
		"consumer_key": rawKey, // returned once only
	})
}

// handleApp handles GET, POST /apps/{id}/revoke, POST /apps/{id}/approve.
func (s *deployServer) handleApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/apps/")
	parts := strings.SplitN(path, "/", 2)
	appID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if appID == "" {
		http.Error(w, "app ID required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	switch {
	case r.Method == http.MethodGet && action == "":
		snap, err := s.fsClient.Collection("apps").Doc(appID).Get(ctx)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		var doc appDoc
		if err := snap.DataTo(&doc); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"app_id":       appID,
			"name":         doc.Name,
			"developer_id": doc.DeveloperID,
			"product_ids":  doc.ProductIDs,
			"status":       doc.Status,
			"created_by":   doc.CreatedBy,
			"created_at":   doc.CreatedAt,
			// consumer_key hash only (raw key is never stored)
			"consumer_key_hash": doc.ConsumerKey,
		})

	case r.Method == http.MethodPost && action == "revoke":
		if err := s.setAppStatus(ctx, appID, "revoked"); err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "revoke failed", http.StatusInternalServerError)
			return
		}
		log.Printf("revoked app id=%s", appID)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && action == "approve":
		if err := s.setAppStatus(ctx, appID, "approved"); err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "approve failed", http.StatusInternalServerError)
			return
		}
		log.Printf("approved app id=%s", appID)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *deployServer) setAppStatus(ctx context.Context, appID, newStatus string) error {
	// Fetch app to get consumer_key hash for updating the api_keys doc.
	snap, err := s.fsClient.Collection("apps").Doc(appID).Get(ctx)
	if err != nil {
		return err
	}
	var doc appDoc
	if err := snap.DataTo(&doc); err != nil {
		return err
	}

	enabled := newStatus == "approved"

	// Update app status.
	if _, err := s.fsClient.Collection("apps").Doc(appID).Update(ctx, []firestore.Update{
		{Path: "status", Value: newStatus},
	}); err != nil {
		return fmt.Errorf("update app status: %w", err)
	}

	// Mirror enabled state on the api_keys lookup doc.
	if doc.ConsumerKey != "" {
		if _, err := s.fsClient.Collection("api_keys").Doc(doc.ConsumerKey).Update(ctx, []firestore.Update{
			{Path: "enabled", Value: enabled},
		}); err != nil {
			log.Printf("WARNING: could not update api_keys enabled for app %s: %v", appID, err)
		}
	}
	return nil
}

// ─── Products ─────────────────────────────────────────────────────────────────

type productDoc struct {
	Name          string    `firestore:"name" json:"name"`
	DisplayName   string    `firestore:"display_name" json:"display_name"`
	QuotaLimit    int64     `firestore:"quota_limit" json:"quota_limit"`
	QuotaInterval int64     `firestore:"quota_interval" json:"quota_interval"`
	QuotaTimeUnit string    `firestore:"quota_timeunit" json:"quota_timeunit"`
	BasePaths     []string  `firestore:"base_paths" json:"base_paths"`
	CreatedBy     string    `firestore:"created_by" json:"created_by"`
	CreatedAt     time.Time `firestore:"created_at" json:"created_at"`
}

// handleProducts handles POST /products.
func (s *deployServer) handleProducts(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	email, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name          string   `json:"name"`
		DisplayName   string   `json:"display_name"`
		QuotaLimit    int64    `json:"quota_limit"`
		QuotaInterval int64    `json:"quota_interval"`
		QuotaTimeUnit string   `json:"quota_timeunit"`
		BasePaths     []string `json:"base_paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	productID := slugID(req.Name)
	doc := productDoc{
		Name:          req.Name,
		DisplayName:   req.DisplayName,
		QuotaLimit:    req.QuotaLimit,
		QuotaInterval: req.QuotaInterval,
		QuotaTimeUnit: req.QuotaTimeUnit,
		BasePaths:     req.BasePaths,
		CreatedBy:     email,
		CreatedAt:     time.Now().UTC(),
	}
	if _, err := s.fsClient.Collection("api_products").Doc(productID).Set(r.Context(), doc); err != nil {
		log.Printf("create product: %v", err)
		http.Error(w, "failed to create product", http.StatusInternalServerError)
		return
	}

	log.Printf("created product id=%s name=%s by=%s", productID, req.Name, email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"product_id":     productID,
		"name":           req.Name,
		"display_name":   req.DisplayName,
		"quota_limit":    req.QuotaLimit,
		"quota_interval": req.QuotaInterval,
		"quota_timeunit": req.QuotaTimeUnit,
		"base_paths":     req.BasePaths,
	})
}

// handleProduct handles GET, PUT, DELETE /products/{id}.
func (s *deployServer) handleProduct(w http.ResponseWriter, r *http.Request) {
	if !s.requireFS(w) {
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}

	productID := strings.TrimPrefix(r.URL.Path, "/products/")
	if productID == "" {
		http.Error(w, "product ID required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		snap, err := s.fsClient.Collection("api_products").Doc(productID).Get(ctx)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		var doc productDoc
		if err := snap.DataTo(&doc); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"product_id":     productID,
			"name":           doc.Name,
			"display_name":   doc.DisplayName,
			"quota_limit":    doc.QuotaLimit,
			"quota_interval": doc.QuotaInterval,
			"quota_timeunit": doc.QuotaTimeUnit,
			"base_paths":     doc.BasePaths,
			"created_by":     doc.CreatedBy,
			"created_at":     doc.CreatedAt,
		})

	case http.MethodPut:
		var req struct {
			DisplayName   *string  `json:"display_name"`
			QuotaLimit    *int64   `json:"quota_limit"`
			QuotaInterval *int64   `json:"quota_interval"`
			QuotaTimeUnit *string  `json:"quota_timeunit"`
			BasePaths     []string `json:"base_paths"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		var updates []firestore.Update
		if req.DisplayName != nil {
			updates = append(updates, firestore.Update{Path: "display_name", Value: *req.DisplayName})
		}
		if req.QuotaLimit != nil {
			updates = append(updates, firestore.Update{Path: "quota_limit", Value: *req.QuotaLimit})
		}
		if req.QuotaInterval != nil {
			updates = append(updates, firestore.Update{Path: "quota_interval", Value: *req.QuotaInterval})
		}
		if req.QuotaTimeUnit != nil {
			updates = append(updates, firestore.Update{Path: "quota_timeunit", Value: *req.QuotaTimeUnit})
		}
		if req.BasePaths != nil {
			updates = append(updates, firestore.Update{Path: "base_paths", Value: req.BasePaths})
		}
		if len(updates) == 0 {
			http.Error(w, "no fields to update", http.StatusBadRequest)
			return
		}
		if _, err := s.fsClient.Collection("api_products").Doc(productID).Update(ctx, updates); err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}
		log.Printf("updated product id=%s", productID)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		if _, err := s.fsClient.Collection("api_products").Doc(productID).Delete(ctx); err != nil {
			if status.Code(err) == codes.NotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		log.Printf("deleted product id=%s", productID)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKey produces a 32-byte random API key encoded as base32 (no padding).
func generateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random key: %w", err)
	}
	return base32Enc.EncodeToString(b), nil
}

// generateID produces a short random ID suitable for Firestore document IDs.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("rand.Read: %v", err))
	}
	return strings.ToLower(base32Enc.EncodeToString(b))
}

// slugID derives a deterministic slug from a string (e.g. email).
// Lowercases, replaces non-alnum with '-', collapses consecutive '-'.
func slugID(s string) string {
	s = strings.ToLower(s)
	var out strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			out.WriteRune(ch)
		} else {
			out.WriteByte('-')
		}
	}
	// Collapse repeated dashes and trim leading/trailing.
	result := strings.Join(strings.FieldsFunc(out.String(), func(r rune) bool { return r == '-' }), "-")
	if result == "" {
		return generateID()
	}
	return result
}
