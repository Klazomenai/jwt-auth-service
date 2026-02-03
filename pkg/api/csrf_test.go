package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGenerateCSRFToken tests the CSRF token generation endpoint
func TestGenerateCSRFToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	tests := []struct {
		name           string
		wantStatusCode int
	}{
		{
			name:           "successful generation",
			wantStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/csrf", nil)
			w := httptest.NewRecorder()

			server.GenerateCSRFToken(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("Expected status %d, got %d", tt.wantStatusCode, w.Code)
			}

			// Parse response
			var resp CSRFTokenResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			// Verify token is not empty
			if resp.Token == "" {
				t.Error("Token should not be empty")
			}

			// Verify expiry is set (approximately 5 minutes from now)
			expectedExpiry := time.Now().Add(csrfTokenTTL)
			timeDiff := expectedExpiry.Sub(resp.ExpiresAt).Abs()
			if timeDiff > 5*time.Second {
				t.Errorf("Expiry time mismatch: expected ~%v, got %v (diff: %v)",
					expectedExpiry, resp.ExpiresAt, timeDiff)
			}

			// Verify token exists and can be consumed from Redis (one-time use)
			ctx := context.Background()
			valid, err := server.store.ValidateAndConsumeCSRFToken(ctx, resp.Token)
			if err != nil {
				t.Fatalf("Failed to validate and consume token: %v", err)
			}
			if !valid {
				t.Error("Generated token should be valid and consumable")
			}
		})
	}
}

// TestGenerateCSRFToken_Uniqueness tests that generated tokens are unique
func TestGenerateCSRFToken_Uniqueness(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	// Generate multiple tokens
	tokens := make(map[string]bool)
	numTokens := 100

	for i := 0; i < numTokens; i++ {
		req := httptest.NewRequest("GET", "/csrf", nil)
		w := httptest.NewRecorder()

		server.GenerateCSRFToken(w, req)

		var resp CSRFTokenResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if tokens[resp.Token] {
			t.Errorf("Duplicate token generated: %s", resp.Token)
		}
		tokens[resp.Token] = true
	}

	if len(tokens) != numTokens {
		t.Errorf("Expected %d unique tokens, got %d", numTokens, len(tokens))
	}
}

// TestValidateCSRFToken tests the CSRF token validation endpoint
func TestValidateCSRFToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Generate a valid token
	validToken := "test-valid-token-123"
	if err := server.store.StoreCSRFToken(ctx, validToken, 5*time.Minute); err != nil {
		t.Fatalf("Failed to store valid token: %v", err)
	}

	tests := []struct {
		name           string
		requestBody    interface{}
		wantStatusCode int
		wantValid      bool
	}{
		{
			name: "valid token",
			requestBody: CSRFValidateRequest{
				Token: validToken,
			},
			wantStatusCode: http.StatusOK,
			wantValid:      true,
		},
		{
			name: "invalid token",
			requestBody: CSRFValidateRequest{
				Token: "nonexistent-token",
			},
			wantStatusCode: http.StatusUnauthorized,
			wantValid:      false,
		},
		{
			name: "empty token",
			requestBody: CSRFValidateRequest{
				Token: "",
			},
			wantStatusCode: http.StatusBadRequest,
			wantValid:      false,
		},
		{
			name:           "invalid JSON",
			requestBody:    "invalid json",
			wantStatusCode: http.StatusBadRequest,
			wantValid:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request body
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/validate-csrf", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.ValidateCSRFToken(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("Expected status %d, got %d", tt.wantStatusCode, w.Code)
			}

			// For valid status codes, parse response
			if w.Code == http.StatusOK || w.Code == http.StatusUnauthorized {
				var resp CSRFValidateResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				if resp.Valid != tt.wantValid {
					t.Errorf("Expected valid=%v, got %v", tt.wantValid, resp.Valid)
				}
			}
		})
	}
}

// TestValidateCSRFToken_OneTimeUse tests that tokens can only be validated once
func TestValidateCSRFToken_OneTimeUse(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Store a token
	token := "one-time-token-456"
	if err := server.store.StoreCSRFToken(ctx, token, 5*time.Minute); err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// First validation should succeed
	reqBody := CSRFValidateRequest{Token: token}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/validate-csrf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.ValidateCSRFToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("First validation should succeed, got status %d", w.Code)
	}

	var resp1 CSRFValidateResponse
	json.NewDecoder(w.Body).Decode(&resp1)
	if !resp1.Valid {
		t.Error("First validation should be valid")
	}

	// Second validation should fail (token consumed)
	req2 := httptest.NewRequest("POST", "/validate-csrf", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	server.ValidateCSRFToken(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("Second validation should fail with 401, got status %d", w2.Code)
	}

	var resp2 CSRFValidateResponse
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Valid {
		t.Error("Second validation should be invalid (one-time use)")
	}
}

// TestValidateCSRFToken_ExpiredToken tests validation of expired tokens
func TestValidateCSRFToken_ExpiredToken(t *testing.T) {
	server, mr := setupTestServer(t)
	defer mr.Close()

	ctx := context.Background()

	// Store token with short TTL
	token := "expiring-token-789"
	if err := server.store.StoreCSRFToken(ctx, token, 100*time.Millisecond); err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Fast-forward time in miniredis
	mr.FastForward(200 * time.Millisecond)

	// Validation should fail (token expired)
	reqBody := CSRFValidateRequest{Token: token}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/validate-csrf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.ValidateCSRFToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for expired token, got %d", w.Code)
	}

	var resp CSRFValidateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Valid {
		t.Error("Expired token should be invalid")
	}
}
