package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/klazomenai/jwt-auth-service/pkg/auth"
	"github.com/klazomenai/jwt-auth-service/pkg/metrics"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP API server
type Server struct {
	jwtService       *auth.JWTService
	store            *storage.RedisStore
	router           *mux.Router
	metricsCollector *metrics.Collector
}

// TokenRequest represents a token creation request
type TokenRequest struct {
	UserID       string `json:"user_id"`
	Network      string `json:"network"`
	RateLimit    int    `json:"rate_limit,omitempty"`
	ExpiryDays   int    `json:"expiry_days,omitempty"`   // Default: 30 days
	IncludeChild bool   `json:"include_child,omitempty"` // Whether to include child token in response (default: false)
}

// TokenResponse represents a token creation response
type TokenResponse struct {
	Token     string    `json:"token"`
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// ValidateRequest represents a session validation request
type ValidateRequest struct {
	Token string `json:"token"`
}

// ValidateResponse represents a session validation response
type ValidateResponse struct {
	Valid     bool      `json:"valid"`
	UserID    string    `json:"user_id,omitempty"`
	TokenType string    `json:"token_type,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

const (
	sessionCookieName = "session_token"
	sessionCookiePath = "/"
)

// NewServer creates a new API server
func NewServer(jwtService *auth.JWTService, store *storage.RedisStore) *Server {
	s := &Server{
		jwtService:       jwtService,
		store:            store,
		router:           mux.NewRouter(),
		metricsCollector: metrics.NewCollector(store),
	}

	// Setup routes
	s.router.HandleFunc("/tokens", s.CreateToken).Methods("POST")
	s.router.HandleFunc("/token-pairs", s.CreateTokenPair).Methods("POST")
	s.router.HandleFunc("/renew", s.RenewToken).Methods("POST")
	s.router.HandleFunc("/tokens/latest", s.GetLatestToken).Methods("GET")
	s.router.HandleFunc("/tokens/stream", s.StreamTokenUpdates).Methods("GET")
	s.router.HandleFunc("/tokens/{tokenID}", s.RevokeToken).Methods("DELETE")
	s.router.HandleFunc("/users/{userID}/tokens", s.RevokeUserTokens).Methods("DELETE")
	s.router.HandleFunc("/authorize", s.Authorize).Methods("POST", "GET", "HEAD")
	s.router.HandleFunc("/csrf", s.GenerateCSRFToken).Methods("GET")
	s.router.HandleFunc("/validate-csrf", s.ValidateCSRFToken).Methods("POST")
	s.router.HandleFunc("/api/validate", s.ValidateSession).Methods("POST")
	s.router.HandleFunc("/.well-known/jwks.json", s.GetJWKS).Methods("GET")
	s.router.HandleFunc("/health", s.Health).Methods("GET")
	s.router.HandleFunc("/healthz", s.Health).Methods("GET")
	s.router.Handle("/metrics", s.metricsHandler()).Methods("GET")

	return s
}

// CreateToken handles token creation requests
func (s *Server) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if req.UserID == "" {
		s.sendError(w, http.StatusBadRequest, "user_id is required", "")
		return
	}
	if req.Network == "" {
		req.Network = "default" // Default network
	}
	if req.RateLimit == 0 {
		req.RateLimit = 100 // Default rate limit
	}
	// Calculate expiry duration
	var expiry time.Duration
	if req.ExpiryDays == 0 {
		// Use default from auth package (1 hour)
		expiry = auth.DefaultTokenExpiry
	} else {
		// Use explicit days from request
		expiry = time.Duration(req.ExpiryDays) * 24 * time.Hour
	}
	token, tokenID, err := s.jwtService.CreateToken(req.UserID, req.Network, req.RateLimit, expiry)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to create token", err.Error())
		return
	}

	// Track token for user
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.store.TrackUserToken(ctx, req.UserID, tokenID, expiry); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Warning: Failed to track user token: %v\n", err)
	}

	// Send response
	resp := TokenResponse{
		Token:     token,
		TokenID:   tokenID,
		ExpiresAt: time.Now().Add(expiry),
	}

	s.sendJSON(w, http.StatusCreated, resp)
}

// CreateTokenPair handles token pair creation requests (parent + optional child tokens)
func (s *Server) CreateTokenPair(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if req.UserID == "" {
		s.sendError(w, http.StatusBadRequest, "user_id is required", "")
		return
	}
	if req.Network == "" {
		req.Network = "default" // Default network
	}
	if req.RateLimit == 0 {
		req.RateLimit = 100 // Default rate limit
	}

	// Use default token expiries from auth package
	childExpiry := auth.DefaultChildTokenExpiry   // 15 minutes
	parentExpiry := auth.DefaultParentTokenExpiry // 30 days

	// Create token pair (parent + optional child)
	tokenPair, err := s.jwtService.CreateTokenPair(req.UserID, req.Network, req.RateLimit, childExpiry, parentExpiry, req.IncludeChild)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to create token pair", err.Error())
		return
	}

	// Track tokens for user
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Always track parent token
	if err := s.store.TrackUserToken(ctx, req.UserID, tokenPair.ParentJTI, parentExpiry); err != nil {
		fmt.Printf("Warning: Failed to track parent token: %v\n", err)
	}

	// Track child token if included
	if req.IncludeChild && tokenPair.ChildJTI != "" {
		if err := s.store.TrackUserToken(ctx, req.UserID, tokenPair.ChildJTI, childExpiry); err != nil {
			fmt.Printf("Warning: Failed to track child token: %v\n", err)
		}
	}

	// Always enable server-side auto-renewal (background worker generates children)
	config := &storage.AutoRenewalConfig{
		ParentJTI:    tokenPair.ParentJTI,
		UserID:       req.UserID,
		Network:      req.Network,
		RateLimit:    req.RateLimit,
		ChildExpiry:  int64(childExpiry.Seconds()),
		ParentExpiry: time.Now().Add(parentExpiry),
		CreatedAt:    time.Now(),
	}

	if err := s.store.StoreAutoRenewalConfig(ctx, config); err != nil {
		fmt.Printf("Warning: Failed to store auto-renewal config: %v\n", err)
	} else {
		fmt.Printf("✅ Server-side auto-renewal enabled for user %s (parent_jti=%s)\n",
			req.UserID, tokenPair.ParentJTI)
	}

	// Log token pair creation
	if req.IncludeChild {
		fmt.Printf("Created token family for user %s: parent_jti=%s, child_jti=%s, child_expiry=%s, parent_expiry=%s\n",
			req.UserID, tokenPair.ParentJTI, tokenPair.ChildJTI, childExpiry, parentExpiry)
	} else {
		fmt.Printf("Created token family for user %s: parent_jti=%s, parent_expiry=%s (child will be auto-generated by worker)\n",
			req.UserID, tokenPair.ParentJTI, parentExpiry)
	}

	s.sendJSON(w, http.StatusCreated, tokenPair)
}

// RenewRequest represents a token renewal request
type RenewRequest struct {
	ParentToken string `json:"parent_token"`
}

// RenewToken handles manual child token generation requests
func (s *Server) RenewToken(w http.ResponseWriter, r *http.Request) {
	var req RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.ParentToken == "" {
		s.sendError(w, http.StatusBadRequest, "parent_token is required", "")
		return
	}

	// Validate parent token and extract claims
	claims, err := s.jwtService.ValidateToken(req.ParentToken)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, "Invalid parent token", err.Error())
		return
	}

	// Verify this is a parent token
	if claims.TokenType != auth.TokenTypeParent {
		s.sendError(w, http.StatusBadRequest, "Token is not a parent token", fmt.Sprintf("Expected token_type='%s', got '%s'", auth.TokenTypeParent, claims.TokenType))
		return
	}

	// Check if parent token has been revoked
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	parentJTI := claims.ID
	isRevoked, err := s.store.IsTokenRevoked(ctx, parentJTI)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to check token revocation status", err.Error())
		return
	}

	if isRevoked {
		fmt.Printf("Renewal blocked: parent token %s has been revoked (user: %s)\n", parentJTI, claims.UserID)
		s.sendError(w, http.StatusForbidden, "Parent token has been revoked", "")
		return
	}

	// Create new child token linked to parent
	childExpiry := auth.DefaultChildTokenExpiry
	newChildToken, childJTI, err := s.jwtService.CreateChildToken(claims.UserID, claims.Network, claims.RateLimit, childExpiry, parentJTI)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to create child token", err.Error())
		return
	}

	// Track new child token
	if err := s.store.TrackUserToken(ctx, claims.UserID, childJTI, childExpiry); err != nil {
		fmt.Printf("Warning: Failed to track renewed child token: %v\n", err)
	}

	// Track child→parent relationship for cascade revocation
	if err := s.store.TrackChildToken(ctx, parentJTI, childJTI, auth.DefaultParentTokenExpiry); err != nil {
		fmt.Printf("Warning: Failed to track child token for cascade: %v\n", err)
	}

	// Log successful renewal
	fmt.Printf("Child token generated for user %s: parent_jti=%s, new_child_jti=%s, child_expiry=%s\n",
		claims.UserID, parentJTI, childJTI, childExpiry)

	// Return new child token
	resp := TokenResponse{
		Token:     newChildToken,
		TokenID:   childJTI,
		ExpiresAt: time.Now().Add(childExpiry),
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// RevokeToken handles token revocation requests
func (s *Server) RevokeToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tokenID := vars["tokenID"]

	if tokenID == "" {
		s.sendError(w, http.StatusBadRequest, "tokenID is required", "")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Revoke token with TTL matching max token lifetime (30 days)
	if err := s.store.RevokeToken(ctx, tokenID, 30*24*time.Hour); err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to revoke token", err.Error())
		return
	}

	// Cascade: revoke all child tokens of this parent
	childCount, err := s.store.RevokeChildTokens(ctx, tokenID, auth.DefaultParentTokenExpiry)
	if err != nil {
		fmt.Printf("Warning: Failed to cascade revoke child tokens for %s: %v\n", tokenID, err)
	} else if childCount > 0 {
		fmt.Printf("Cascade revocation: revoked %d child tokens for parent %s\n", childCount, tokenID)
	}

	// Stop auto-renewal if this was a parent token
	_ = s.store.DeleteAutoRenewalConfig(ctx, tokenID)

	w.WriteHeader(http.StatusNoContent)
}

// RevokeUserTokens handles revoking all tokens for a user
func (s *Server) RevokeUserTokens(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userID"]

	if userID == "" {
		s.sendError(w, http.StatusBadRequest, "userID is required", "")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get user tokens before revoking to clean up auto-renewal configs
	tokens, err := s.store.GetUserTokens(ctx, userID)
	if err != nil {
		fmt.Printf("Warning: Failed to get user tokens for auto-renewal cleanup: %v\n", err)
	} else {
		// Clean up auto-renewal configs for any parent tokens
		for _, tokenID := range tokens {
			config, err := s.store.GetAutoRenewalConfig(ctx, tokenID)
			if err != nil {
				fmt.Printf("Warning: Failed to check auto-renewal config for token %s: %v\n", tokenID, err)
				continue
			}
			if config != nil {
				// Delete auto-renewal configuration (stops server-side renewal)
				if err := s.store.DeleteAutoRenewalConfig(ctx, tokenID); err != nil {
					fmt.Printf("Warning: Failed to delete auto-renewal config for token %s: %v\n", tokenID, err)
				} else {
					fmt.Printf("🛑 Server-side auto-renewal stopped for user %s (parent_jti=%s)\n",
						userID, tokenID)
				}
			}
		}
	}

	// Revoke all user tokens
	if err := s.store.RevokeUserTokens(ctx, userID, 30*24*time.Hour); err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to revoke user tokens", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Authorize handles external authorization requests from Envoy ext_authz filter
// This endpoint checks if a JWT token (already validated) has been revoked
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	// Extract JWT from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.sendError(w, http.StatusUnauthorized, "Missing Authorization header", "")
		return
	}

	// Extract token from "Bearer <token>" format
	tokenString := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	} else {
		s.sendError(w, http.StatusUnauthorized, "Invalid Authorization header format", "Expected 'Bearer <token>'")
		return
	}

	// Validate and extract claims from JWT
	claims, err := s.jwtService.ValidateToken(tokenString)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, "Invalid JWT token", err.Error())
		return
	}

	// Extract JTI (JWT ID) from claims
	jti := claims.ID
	if jti == "" {
		s.sendError(w, http.StatusBadRequest, "JWT missing jti claim", "")
		return
	}

	// Check if token is revoked
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	isRevoked, err := s.store.IsTokenRevoked(ctx, jti)
	if err != nil {
		// Log error but allow request (fail open for availability)
		fmt.Printf("Error checking token revocation: %v\n", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if isRevoked {
		s.sendError(w, http.StatusForbidden, "Token has been revoked", "")
		return
	}

	// If this is a child token, also check if parent has been revoked
	if claims.ParentJTI != "" {
		parentRevoked, err := s.store.IsTokenRevoked(ctx, claims.ParentJTI)
		if err != nil {
			// Log error but allow request (fail open for availability)
			fmt.Printf("Error checking parent token revocation: %v\n", err)
		} else if parentRevoked {
			s.sendError(w, http.StatusForbidden, "Parent token has been revoked", "")
			return
		}
	}

	// Token is valid and not revoked - allow request
	w.WriteHeader(http.StatusOK)
}

// ValidateSession handles JWT validation and sets HttpOnly session cookies (POST /api/validate)
// Requires X-CSRF-Token header for CSRF protection. Fail-closed on Redis errors.
func (s *Server) ValidateSession(w http.ResponseWriter, r *http.Request) {
	// Step 1: Extract CSRF token from header
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		s.sendError(w, http.StatusForbidden, "Missing CSRF token", "X-CSRF-Token header is required")
		return
	}

	// Step 2: Validate CSRF token format
	if err := validateCSRFTokenFormat(csrfToken); err != nil {
		s.sendError(w, http.StatusForbidden, "Invalid CSRF token format", err.Error())
		return
	}

	// Step 3: Consume CSRF token (one-time use, consumed before JWT parsing)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	csrfValid, err := s.store.ValidateAndConsumeCSRFToken(ctx, csrfToken)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to validate CSRF token", err.Error())
		return
	}
	if !csrfValid {
		s.sendError(w, http.StatusForbidden, "CSRF token invalid, expired, or already used", "")
		return
	}

	// Step 4: Parse request body
	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Step 5: Validate token field
	if req.Token == "" {
		s.sendError(w, http.StatusBadRequest, "token field is required", "")
		return
	}

	// Step 6: Validate JWT
	claims, err := s.jwtService.ValidateToken(req.Token)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, "Invalid JWT token", err.Error())
		return
	}

	// Step 7: Check JTI exists
	jti := claims.ID
	if jti == "" {
		s.sendError(w, http.StatusBadRequest, "JWT missing jti claim", "")
		return
	}

	// Step 8: Check if token is revoked (fail-closed on Redis errors)
	isRevoked, err := s.store.IsTokenRevoked(ctx, jti)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to check token revocation status", err.Error())
		return
	}
	if isRevoked {
		s.sendError(w, http.StatusForbidden, "Token has been revoked", "")
		return
	}

	// Step 9: If child token, check parent revocation (fail-closed on Redis errors)
	if claims.ParentJTI != "" {
		parentRevoked, err := s.store.IsTokenRevoked(ctx, claims.ParentJTI)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, "Failed to check parent token revocation status", err.Error())
			return
		}
		if parentRevoked {
			s.sendError(w, http.StatusForbidden, "Parent token has been revoked", "")
			return
		}
	}

	// Step 10: Compute cookie MaxAge from JWT expiry
	maxAge := int(time.Until(claims.ExpiresAt.Time).Seconds())
	if maxAge <= 0 {
		s.sendError(w, http.StatusUnauthorized, "Token has expired", "")
		return
	}

	// Step 11: Set HttpOnly session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    req.Token,
		Path:     sessionCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Step 12: Return success response
	fmt.Printf("Session validated: user=%s, token_type=%s, jti=%s, max_age=%ds\n",
		claims.UserID, claims.TokenType, jti, maxAge)

	resp := ValidateResponse{
		Valid:     true,
		UserID:    claims.UserID,
		TokenType: claims.TokenType,
		ExpiresAt: claims.ExpiresAt.Time,
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// GetJWKS returns the JSON Web Key Set
func (s *Server) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.jwtService.GetJWKS()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to get JWKS", err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, jwks)
}

// Health handles health check requests
func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Check Redis health
	if err := s.store.Health(ctx); err != nil {
		s.sendError(w, http.StatusServiceUnavailable, "Redis unhealthy", err.Error())
		return
	}

	resp := map[string]string{
		"status": "healthy",
		"redis":  "connected",
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// GetLatestToken handles polling requests for latest auto-renewed child token
func (s *Server) GetLatestToken(w http.ResponseWriter, r *http.Request) {
	// Get parent JTI from query parameter
	parentJTI := r.URL.Query().Get("parent_jti")
	if parentJTI == "" {
		s.sendError(w, http.StatusBadRequest, "parent_jti query parameter is required", "")
		return
	}

	// Check if parent token has been revoked
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	isRevoked, err := s.store.IsTokenRevoked(ctx, parentJTI)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to check token revocation status", err.Error())
		return
	}

	if isRevoked {
		s.sendError(w, http.StatusForbidden, "Parent token has been revoked", "")
		return
	}

	// Get latest child token
	latestToken, err := s.store.GetLatestChildToken(ctx, parentJTI)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to get latest child token", err.Error())
		return
	}

	if latestToken == nil {
		s.sendError(w, http.StatusNotFound, "No auto-renewed token available", "Server-side auto-renewal may not be enabled for this token")
		return
	}

	// Return latest token
	resp := map[string]interface{}{
		"child_token": latestToken.ChildToken,
		"child_jti":   latestToken.ChildJTI,
		"expires_at":  latestToken.ExpiresAt,
		"renewed_at":  latestToken.RenewedAt,
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// StreamTokenUpdates handles Server-Sent Events (SSE) streaming of child token updates
func (s *Server) StreamTokenUpdates(w http.ResponseWriter, r *http.Request) {
	// Get parent JTI from query parameter
	parentJTI := r.URL.Query().Get("parent_jti")
	if parentJTI == "" {
		s.sendError(w, http.StatusBadRequest, "parent_jti query parameter is required", "")
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendError(w, http.StatusInternalServerError, "Streaming not supported", "")
		return
	}

	// Send initial connection confirmation
	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Token update stream connected\"}\n\n")
	flusher.Flush()

	// Stream token updates
	ctx := r.Context()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastChildJTI string

	// Send initial token immediately
	latestToken, err := s.store.GetLatestChildToken(ctx, parentJTI)
	if err == nil && latestToken != nil {
		lastChildJTI = latestToken.ChildJTI
		tokenData, _ := json.Marshal(map[string]interface{}{
			"child_token": latestToken.ChildToken,
			"child_jti":   latestToken.ChildJTI,
			"expires_at":  latestToken.ExpiresAt,
			"renewed_at":  latestToken.RenewedAt,
		})
		fmt.Fprintf(w, "event: token\ndata: %s\n\n", tokenData)
		flusher.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case <-ticker.C:
			// Check for new token
			latestToken, err := s.store.GetLatestChildToken(ctx, parentJTI)
			if err != nil {
				// Log error but don't disconnect
				fmt.Printf("SSE: Failed to get latest token: %v\n", err)
				continue
			}

			if latestToken == nil {
				continue
			}

			// Only send update if token has changed
			if latestToken.ChildJTI != lastChildJTI {
				lastChildJTI = latestToken.ChildJTI
				tokenData, _ := json.Marshal(map[string]interface{}{
					"child_token": latestToken.ChildToken,
					"child_jti":   latestToken.ChildJTI,
					"expires_at":  latestToken.ExpiresAt,
					"renewed_at":  latestToken.RenewedAt,
				})
				fmt.Fprintf(w, "event: token\ndata: %s\n\n", tokenData)
				flusher.Flush()
			}

			// Send keepalive heartbeat
			fmt.Fprintf(w, "event: heartbeat\ndata: {\"timestamp\":\"%s\"}\n\n", time.Now().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

// Router returns the HTTP router
func (s *Server) Router() *mux.Router {
	return s.router
}

// metricsHandler returns an HTTP handler for Prometheus metrics
// It updates metrics from storage on each scrape to ensure fresh data
func (s *Server) metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Update metrics from current storage state
		s.metricsCollector.UpdateMetrics()
		// Serve Prometheus metrics
		promhttp.Handler().ServeHTTP(w, r)
	})
}

// Helper methods
func (s *Server) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) sendError(w http.ResponseWriter, status int, error, message string) {
	resp := ErrorResponse{
		Error:   error,
		Message: message,
	}
	s.sendJSON(w, status, resp)
}
