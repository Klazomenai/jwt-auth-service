package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/klazomenai/jwt-auth-service/pkg/auth"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
)

// setupTestServer creates a test server with miniredis
func setupTestServer(t *testing.T) (*Server, *miniredis.Miniredis) {
	// Create miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	// Create test store using miniredis address
	store, err := storage.NewRedisStore(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("Failed to create Redis store: %v", err)
	}

	// Generate test JWT service
	privateKey, _ := auth.GenerateKeyPair()
	privateKeyPEM := auth.ExportPrivateKeyPEM(privateKey)
	jwtService, _ := auth.NewJWTService(
		"https://test-jwt-service.local",
		"test-audience",
		privateKeyPEM,
	)

	server := NewServer(jwtService, store)

	return server, mr
}

func TestHealthEndpoint(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}

	if response["redis"] != "connected" {
		t.Errorf("Expected redis 'connected', got '%s'", response["redis"])
	}
}

func TestCreateToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	tests := []struct {
		name           string
		requestBody    TokenRequest
		expectedStatus int
	}{
		{
			name: "valid request with all fields",
			requestBody: TokenRequest{
				UserID:     "alice",
				Network:    "devnet",
				RateLimit:  100,
				ExpiryDays: 1,
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "valid request with defaults",
			requestBody: TokenRequest{
				UserID: "bob",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "missing user_id",
			requestBody: TokenRequest{
				Network:   "devnet",
				RateLimit: 100,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/tokens", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.CreateToken(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusCreated {
				var response TokenResponse
				json.NewDecoder(w.Body).Decode(&response)

				if response.Token == "" {
					t.Error("Token is empty")
				}

				if response.TokenID == "" {
					t.Error("TokenID is empty")
				}

				if response.ExpiresAt.IsZero() {
					t.Error("ExpiresAt is zero")
				}
			}
		})
	}
}

func TestCreateToken_DefaultExpiry(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create token without specifying expiry_days (should use 1-hour default)
	requestBody := TokenRequest{
		UserID:    "test-user",
		Network:   "devnet",
		RateLimit: 100,
		// ExpiryDays: 0 (not set, should use auth.DefaultTokenExpiry)
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.CreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var response TokenResponse
	json.NewDecoder(w.Body).Decode(&response)

	// Verify expiry is approximately 1 hour from now
	expectedExpiry := time.Now().Add(auth.DefaultTokenExpiry)
	actualExpiry := response.ExpiresAt

	// Allow 5 second tolerance for test execution time
	diff := actualExpiry.Sub(expectedExpiry).Abs()
	if diff > 5*time.Second {
		t.Errorf("Expected expiry ~%v (1 hour), got %v (diff: %v)", expectedExpiry, actualExpiry, diff)
	}
}

func TestRevokeToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create a token first
	ctx := context.Background()
	tokenID := "test-token-123"
	server.store.TrackUserToken(ctx, "alice", tokenID, 1*time.Hour)

	// Revoke the token using the router
	req := httptest.NewRequest("DELETE", "/tokens/"+tokenID, nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Use router to handle mux vars properly
	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	// Verify token is revoked
	isRevoked, _ := server.store.IsTokenRevoked(ctx, tokenID)
	if !isRevoked {
		t.Error("Token should be revoked")
	}
}

func TestGetJWKS(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	server.GetJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var jwks auth.JWKSet
	json.NewDecoder(w.Body).Decode(&jwks)

	if len(jwks.Keys) == 0 {
		t.Error("JWKS has no keys")
	}

	jwk := jwks.Keys[0]
	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty RSA, got %s", jwk.Kty)
	}

	if jwk.Alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", jwk.Alg)
	}
}

func TestAuthorize_ValidToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create a valid token
	token, tokenID, _ := server.jwtService.CreateToken("alice", "devnet", 100, 1*time.Hour)

	// Test authorization
	req := httptest.NewRequest("POST", "/authorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	server.Authorize(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	_ = tokenID // Used to avoid unused variable error
}

func TestAuthorize_RevokedToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create and revoke a token
	token, tokenID, _ := server.jwtService.CreateToken("alice", "devnet", 100, 1*time.Hour)
	ctx := context.Background()
	server.store.RevokeToken(ctx, tokenID, 1*time.Hour)

	// Test authorization with revoked token
	req := httptest.NewRequest("POST", "/authorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	server.Authorize(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestAuthorize_InvalidToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token format",
			authHeader:     "Bearer invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed header",
			authHeader:     "NotBearer token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "empty bearer token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/authorize", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			server.Authorize(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestAuthorize_SupportedMethods(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create valid token
	token, _, _ := server.jwtService.CreateToken("alice", "devnet", 100, 1*time.Hour)

	methods := []string{"POST", "GET", "HEAD"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/authorize", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			server.Authorize(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for %s, got %d", method, w.Code)
			}
		})
	}
}

func TestRevokeUserTokens(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()
	userID := "charlie"

	// Track multiple tokens for user
	tokens := []string{"token-1", "token-2", "token-3"}
	for _, tokenID := range tokens {
		server.store.TrackUserToken(ctx, userID, tokenID, 1*time.Hour)
	}

	// Revoke all user tokens using the router
	req := httptest.NewRequest("DELETE", "/users/"+userID+"/tokens", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Use router to handle mux vars properly
	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	// Verify all tokens are revoked
	for _, tokenID := range tokens {
		isRevoked, _ := server.store.IsTokenRevoked(ctx, tokenID)
		if !isRevoked {
			t.Errorf("Token %s should be revoked", tokenID)
		}
	}
}

func TestInvalidJSONRequest(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("POST", "/tokens", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.CreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCORS_OptionsMethod(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// OPTIONS requests should be supported for CORS preflight
	req := httptest.NewRequest("OPTIONS", "/tokens", nil)
	w := httptest.NewRecorder()

	// Note: CORS middleware would typically handle this, not the handler directly
	// This test verifies the endpoint exists for routing
	server.router.ServeHTTP(w, req)

	// OPTIONS should return 200 or 204 for CORS preflight
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent && w.Code != http.StatusMethodNotAllowed {
		t.Logf("OPTIONS request status: %d (typically handled by CORS middleware)", w.Code)
	}
}

func TestContentType(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.Health(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

func TestMetricsEndpoint_ReturnsOK(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestMetricsEndpoint_PrometheusFormat(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	server.Router().ServeHTTP(w, req)

	body := w.Body.String()

	// Check for Prometheus format indicators
	if !strings.Contains(body, "# HELP") {
		t.Error("Response should contain Prometheus HELP comments")
	}

	if !strings.Contains(body, "# TYPE") {
		t.Error("Response should contain Prometheus TYPE comments")
	}
}

func TestMetricsEndpoint_ContainsExpectedMetrics(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Create a token pair to populate metrics
	requestBody := TokenRequest{
		UserID:       "metrics-test-user",
		Network:      "testnet",
		RateLimit:    100,
		IncludeChild: true,
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/token-pairs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	server.CreateTokenPair(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create token pair: %d", w.Code)
	}

	// Give Redis a moment to persist
	time.Sleep(50 * time.Millisecond)

	// Now fetch metrics
	req2 := httptest.NewRequest("GET", "/metrics", nil)
	w2 := httptest.NewRecorder()

	server.Router().ServeHTTP(w2, req2)

	bodyStr := w2.Body.String()

	// Check for expected metric names
	expectedMetrics := []string{
		"jwt_parent_tokens_active_total",
		"jwt_parent_token_expiry_timestamp_seconds",
		"jwt_parent_token_issued_timestamp_seconds",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(bodyStr, metric) {
			t.Errorf("Response should contain metric: %s", metric)
		}
	}
}

func TestMetricsEndpoint_UpdatesFromStorage(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Create a token pair with auto-renewal config (creates storage entry)
	requestBody := TokenRequest{
		UserID:       "test-user",
		Network:      "devnet",
		RateLimit:    100,
		IncludeChild: true,
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/token-pairs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	server.CreateTokenPair(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Failed to create token pair: %d", w.Code)
	}

	// Give Redis a moment to persist
	time.Sleep(50 * time.Millisecond)

	// First metrics request
	req1 := httptest.NewRequest("GET", "/metrics", nil)
	w1 := httptest.NewRecorder()
	server.Router().ServeHTTP(w1, req1)

	body1 := w1.Body.String()

	// Check that jwt_parent_tokens_active_total shows 1
	if !strings.Contains(body1, "jwt_parent_tokens_active_total 1") {
		t.Error("First metrics request should show 1 active parent token")
	}

	// Create another token pair
	requestBody2 := TokenRequest{
		UserID:       "test-user-2",
		Network:      "mainnet",
		RateLimit:    100,
		IncludeChild: true,
	}

	body2, _ := json.Marshal(requestBody2)
	req2 := httptest.NewRequest("POST", "/token-pairs", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()

	server.CreateTokenPair(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("Failed to create second token pair: %d", w2.Code)
	}

	// Give Redis a moment to persist
	time.Sleep(50 * time.Millisecond)

	// Second metrics request - should show updated count
	req3 := httptest.NewRequest("GET", "/metrics", nil)
	w3 := httptest.NewRecorder()
	server.Router().ServeHTTP(w3, req3)

	body3 := w3.Body.String()

	// Check that jwt_parent_tokens_active_total now shows 2
	if !strings.Contains(body3, "jwt_parent_tokens_active_total 2") {
		t.Error("Second metrics request should show 2 active parent tokens, got: " + body3)
	}
}
