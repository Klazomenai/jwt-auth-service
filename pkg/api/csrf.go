package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// CSRF token length in bytes (32 bytes = 256 bits)
	csrfTokenLength = 32
	// CSRF token TTL (5 minutes)
	csrfTokenTTL = 5 * time.Minute
)

// CSRFTokenResponse represents a CSRF token generation response
type CSRFTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CSRFValidateRequest represents a CSRF token validation request
type CSRFValidateRequest struct {
	Token string `json:"token"`
}

// CSRFValidateResponse represents a CSRF token validation response
type CSRFValidateResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// GenerateCSRFToken handles CSRF token generation requests (GET /csrf)
// Generates a cryptographically secure random token, stores it in Redis with 5min TTL
func (s *Server) GenerateCSRFToken(w http.ResponseWriter, r *http.Request) {
	// Generate cryptographically secure random token
	tokenBytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to generate CSRF token", err.Error())
		return
	}

	// Encode to base64 URL-safe format
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Store token in Redis with 5 minute TTL
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.store.StoreCSRFToken(ctx, token, csrfTokenTTL); err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to store CSRF token", err.Error())
		return
	}

	// Log token generation (don't log the token value)
	fmt.Printf("CSRF token generated: length=%d bytes, ttl=%s\n", csrfTokenLength, csrfTokenTTL)

	// Return token with expiry
	resp := CSRFTokenResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(csrfTokenTTL),
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// ValidateCSRFToken handles CSRF token validation requests (POST /validate-csrf)
// Validates token existence in Redis and consumes it (one-time use)
func (s *Server) ValidateCSRFToken(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req CSRFValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate token field is not empty
	if req.Token == "" {
		resp := CSRFValidateResponse{
			Valid:   false,
			Message: "token field is required",
		}
		s.sendJSON(w, http.StatusBadRequest, resp)
		return
	}

	// Check token in Redis
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	exists, err := s.store.ValidateAndConsumeCSRFToken(ctx, req.Token)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to validate CSRF token", err.Error())
		return
	}

	if !exists {
		// Token not found, expired, or already consumed
		resp := CSRFValidateResponse{
			Valid:   false,
			Message: "CSRF token invalid, expired, or already used",
		}
		s.sendJSON(w, http.StatusUnauthorized, resp)
		return
	}

	// Token is valid and has been consumed
	fmt.Printf("CSRF token validated and consumed successfully\n")

	resp := CSRFValidateResponse{
		Valid:   true,
		Message: "CSRF token valid",
	}

	s.sendJSON(w, http.StatusOK, resp)
}
