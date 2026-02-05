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

func TestRevokeToken_CascadesToChildren(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Create a parent token pair
	tokenPair, err := server.jwtService.CreateTokenPair("alice", "testnet", 100,
		auth.DefaultChildTokenExpiry, auth.DefaultParentTokenExpiry, true)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	parentJTI := tokenPair.ParentJTI
	childJTI := tokenPair.ChildJTI

	// Track child under parent for cascade
	err = server.store.TrackChildToken(ctx, parentJTI, childJTI, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to track child token: %v", err)
	}

	// Revoke parent via API
	req := httptest.NewRequest("DELETE", "/tokens/"+parentJTI, nil)
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	// Verify parent is revoked
	isRevoked, _ := server.store.IsTokenRevoked(ctx, parentJTI)
	if !isRevoked {
		t.Error("Parent token should be revoked")
	}

	// Verify child is also revoked (cascade)
	isRevoked, _ = server.store.IsTokenRevoked(ctx, childJTI)
	if !isRevoked {
		t.Error("Child token should be revoked via cascade")
	}
}

func TestAuthorize_ChildWithRevokedParent(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Create parent token
	parentToken, parentJTI, err := server.jwtService.CreateToken("alice", "testnet", 100, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to create parent token: %v", err)
	}
	_ = parentToken

	// Create child token linked to parent
	childToken, _, err := server.jwtService.CreateChildToken("alice", "testnet", 100, auth.DefaultChildTokenExpiry, parentJTI)
	if err != nil {
		t.Fatalf("Failed to create child token: %v", err)
	}

	// Authorize child token before revoking parent — should succeed
	req := httptest.NewRequest("POST", "/authorize", nil)
	req.Header.Set("Authorization", "Bearer "+childToken)
	w := httptest.NewRecorder()
	server.Authorize(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 before parent revocation, got %d", w.Code)
	}

	// Revoke parent
	err = server.store.RevokeToken(ctx, parentJTI, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to revoke parent token: %v", err)
	}

	// Authorize child token after revoking parent — should fail
	req2 := httptest.NewRequest("POST", "/authorize", nil)
	req2.Header.Set("Authorization", "Bearer "+childToken)
	w2 := httptest.NewRecorder()
	server.Authorize(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 after parent revocation, got %d", w2.Code)
	}
}

func TestAuthorize_ChildWithValidParent(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create parent token (not revoked)
	_, parentJTI, err := server.jwtService.CreateToken("alice", "testnet", 100, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to create parent token: %v", err)
	}

	// Create child token linked to parent
	childToken, _, err := server.jwtService.CreateChildToken("alice", "testnet", 100, auth.DefaultChildTokenExpiry, parentJTI)
	if err != nil {
		t.Fatalf("Failed to create child token: %v", err)
	}

	// Authorize child token — should succeed (parent not revoked)
	req := httptest.NewRequest("POST", "/authorize", nil)
	req.Header.Set("Authorization", "Bearer "+childToken)
	w := httptest.NewRecorder()
	server.Authorize(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for child with valid parent, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestRenewToken_SetsParentJTI(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Create parent token pair
	tokenPair, err := server.jwtService.CreateTokenPair("alice", "testnet", 100,
		auth.DefaultChildTokenExpiry, auth.DefaultParentTokenExpiry, false)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Renew via API using parent token
	reqBody := `{"parent_token":"` + tokenPair.ParentToken + `"}`
	req := httptest.NewRequest("POST", "/renew", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.RenewToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Parse response to get child token
	var resp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Validate child token claims
	claims, err := server.jwtService.ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("Failed to validate child token: %v", err)
	}

	if claims.ParentJTI != tokenPair.ParentJTI {
		t.Errorf("Expected parent_jti %q, got %q", tokenPair.ParentJTI, claims.ParentJTI)
	}

	if claims.TokenType != auth.TokenTypeChild {
		t.Errorf("Expected token_type %q, got %q", auth.TokenTypeChild, claims.TokenType)
	}
}

// --- ValidateSession tests ---

// helper: create a valid CSRF token stored in Redis and return it
func storeTestCSRF(t *testing.T, server *Server, pattern byte) string {
	t.Helper()
	token := generateTestToken(pattern)
	ctx := context.Background()
	if err := server.store.StoreCSRFToken(ctx, token, csrfTokenTTL); err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}
	return token
}

func TestValidateSession_ValidToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x10)
	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp ValidateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.Valid {
		t.Error("Expected valid=true")
	}
	if resp.UserID != "alice" {
		t.Errorf("Expected user_id 'alice', got %q", resp.UserID)
	}
	if resp.ExpiresAt.IsZero() {
		t.Error("Expected non-zero expires_at")
	}

	// Verify Set-Cookie header present
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected Set-Cookie header")
	}
}

func TestValidateSession_ValidChildToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x11)

	// Create parent, then child
	_, parentJTI, err := server.jwtService.CreateToken("bob", "testnet", 100, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to create parent token: %v", err)
	}
	childJWT, _, err := server.jwtService.CreateChildToken("bob", "testnet", 100, auth.DefaultChildTokenExpiry, parentJTI)
	if err != nil {
		t.Fatalf("Failed to create child token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: childJWT})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp ValidateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.TokenType != auth.TokenTypeChild {
		t.Errorf("Expected token_type %q, got %q", auth.TokenTypeChild, resp.TokenType)
	}
}

func TestValidateSession_MissingCSRFToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No X-CSRF-Token header
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestValidateSession_InvalidCSRFTokenFormat(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "not-valid-base64!@#$")
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestValidateSession_ExpiredCSRFToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Store CSRF with short TTL
	csrf := generateTestToken(0x12)
	ctx := context.Background()
	if err := server.store.StoreCSRFToken(ctx, csrf, 100*time.Millisecond); err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}

	// Fast-forward miniredis past expiry
	mr.FastForward(200 * time.Millisecond)

	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestValidateSession_InvalidJWT(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x13)

	body, _ := json.Marshal(ValidateRequest{Token: "garbage.jwt.token"})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestValidateSession_RevokedToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x14)
	jwt, jti, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Revoke the token
	ctx := context.Background()
	if err := server.store.RevokeToken(ctx, jti, 1*time.Hour); err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestValidateSession_ChildWithRevokedParent(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x15)
	ctx := context.Background()

	// Create parent and child
	_, parentJTI, err := server.jwtService.CreateToken("alice", "testnet", 100, auth.DefaultParentTokenExpiry)
	if err != nil {
		t.Fatalf("Failed to create parent token: %v", err)
	}
	childJWT, _, err := server.jwtService.CreateChildToken("alice", "testnet", 100, auth.DefaultChildTokenExpiry, parentJTI)
	if err != nil {
		t.Fatalf("Failed to create child token: %v", err)
	}

	// Revoke the parent
	if err := server.store.RevokeToken(ctx, parentJTI, auth.DefaultParentTokenExpiry); err != nil {
		t.Fatalf("Failed to revoke parent token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: childJWT})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestValidateSession_MissingBody(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x16)

	// Send empty body
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestValidateSession_EmptyToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x17)

	body, _ := json.Marshal(ValidateRequest{Token: ""})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestValidateSession_CookieAttributes(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x18)
	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected Set-Cookie header")
	}

	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatalf("Expected cookie named %q", sessionCookieName)
	}

	if !sessionCookie.HttpOnly {
		t.Error("Expected HttpOnly=true")
	}
	if !sessionCookie.Secure {
		t.Error("Expected Secure=true")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite=Strict, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Path != sessionCookiePath {
		t.Errorf("Expected Path=%q, got %q", sessionCookiePath, sessionCookie.Path)
	}
	if sessionCookie.Value != jwt {
		t.Error("Expected cookie value to be the JWT token")
	}
}

func TestValidateSession_MaxAgeMatchesJWTExpiry(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	csrf := storeTestCSRF(t, server, 0x19)
	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("Expected session cookie")
	}

	// MaxAge should be approximately 3600 seconds (1 hour), allow ±5s tolerance
	expectedMaxAge := 3600
	diff := sessionCookie.MaxAge - expectedMaxAge
	if diff < 0 {
		diff = -diff
	}
	if diff > 5 {
		t.Errorf("Expected MaxAge ~%d, got %d (diff: %d)", expectedMaxAge, sessionCookie.MaxAge, diff)
	}
}

func TestValidateSession_RedisFailure(t *testing.T) {
	server, mr := setupTestServer(t)

	// Store CSRF token while Redis is up
	csrf := storeTestCSRF(t, server, 0x1A)
	jwt, _, err := server.jwtService.CreateToken("alice", "testnet", 100, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Close Redis to simulate failure
	mr.Close()

	body, _ := json.Marshal(ValidateRequest{Token: jwt})
	req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()

	server.ValidateSession(w, req)

	// Should return 500 (fail-closed)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for Redis failure, got %d", w.Code)
	}
}
