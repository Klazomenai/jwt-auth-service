package storage

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// NewTestRedisStore creates a RedisStore for testing with a custom client
// This is exported for use in other package tests
func NewTestRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
	}
}

// setupTestRedis creates a miniredis server for testing
func setupTestRedis(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	// Create miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	// Create Redis client pointing to miniredis
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	store := NewTestRedisStore(client)

	return store, mr
}

func TestNewRedisStore(t *testing.T) {
	// Create miniredis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer mr.Close()

	tests := []struct {
		name     string
		addr     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid connection",
			addr:     mr.Addr(),
			password: "",
			wantErr:  false,
		},
		{
			name:     "invalid address",
			addr:     "invalid:99999",
			password: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewRedisStore(tt.addr, tt.password, 0)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if store != nil {
				defer store.Close()
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		tokenID string
		ttl     time.Duration
	}{
		{
			name:    "revoke with 1 hour TTL",
			tokenID: "test-token-1",
			ttl:     1 * time.Hour,
		},
		{
			name:    "revoke with 1 day TTL",
			tokenID: "test-token-2",
			ttl:     24 * time.Hour,
		},
		{
			name:    "revoke with 1 minute TTL",
			tokenID: "test-token-3",
			ttl:     1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.RevokeToken(ctx, tt.tokenID, tt.ttl)
			if err != nil {
				t.Fatalf("Failed to revoke token: %v", err)
			}

			// Verify token is marked as revoked
			key := revokedTokenPrefix + tt.tokenID
			val, err := store.client.Get(ctx, key).Result()
			if err != nil {
				t.Fatalf("Failed to get revoked token: %v", err)
			}

			if val != "1" {
				t.Errorf("Expected value '1', got '%s'", val)
			}

			// Verify TTL is set (approximately)
			ttl, err := store.client.TTL(ctx, key).Result()
			if err != nil {
				t.Fatalf("Failed to get TTL: %v", err)
			}

			// TTL should be close to expected (within 1 second tolerance)
			expectedTTL := tt.ttl
			if ttl < expectedTTL-time.Second || ttl > expectedTTL+time.Second {
				t.Errorf("Expected TTL ~%v, got %v", expectedTTL, ttl)
			}
		})
	}
}

func TestIsTokenRevoked(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	// Revoke a token
	revokedTokenID := "revoked-token"
	err := store.RevokeToken(ctx, revokedTokenID, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	tests := []struct {
		name           string
		tokenID        string
		expectedRevoked bool
	}{
		{
			name:           "revoked token",
			tokenID:        revokedTokenID,
			expectedRevoked: true,
		},
		{
			name:           "non-revoked token",
			tokenID:        "active-token",
			expectedRevoked: false,
		},
		{
			name:           "non-existent token",
			tokenID:        "non-existent",
			expectedRevoked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isRevoked, err := store.IsTokenRevoked(ctx, tt.tokenID)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if isRevoked != tt.expectedRevoked {
				t.Errorf("Expected revoked=%v, got %v", tt.expectedRevoked, isRevoked)
			}
		})
	}
}

func TestTrackUserToken(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	userID := "alice"
	tokenID := "token-123"
	ttl := 1 * time.Hour

	err := store.TrackUserToken(ctx, userID, tokenID, ttl)
	if err != nil {
		t.Fatalf("Failed to track user token: %v", err)
	}

	// Verify token is tracked
	key := userTokenPrefix + userID
	isMember, err := store.client.SIsMember(ctx, key, tokenID).Result()
	if err != nil {
		t.Fatalf("Failed to check set membership: %v", err)
	}

	if !isMember {
		t.Error("Token not found in user's token set")
	}

	// Verify TTL is set
	ttlResult, err := store.client.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("Failed to get TTL: %v", err)
	}

	if ttlResult < 0 {
		t.Error("TTL not set on user token set")
	}
}

func TestGetUserTokens(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	userID := "bob"
	tokens := []string{"token-1", "token-2", "token-3"}
	ttl := 1 * time.Hour

	// Track multiple tokens
	for _, tokenID := range tokens {
		err := store.TrackUserToken(ctx, userID, tokenID, ttl)
		if err != nil {
			t.Fatalf("Failed to track token: %v", err)
		}
	}

	// Get user tokens
	retrievedTokens, err := store.GetUserTokens(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to get user tokens: %v", err)
	}

	// Verify count
	if len(retrievedTokens) != len(tokens) {
		t.Errorf("Expected %d tokens, got %d", len(tokens), len(retrievedTokens))
	}

	// Verify all tokens are present
	tokenMap := make(map[string]bool)
	for _, token := range retrievedTokens {
		tokenMap[token] = true
	}

	for _, expectedToken := range tokens {
		if !tokenMap[expectedToken] {
			t.Errorf("Expected token %s not found in results", expectedToken)
		}
	}
}

func TestGetUserTokens_NoTokens(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	// Get tokens for user with no tokens
	tokens, err := store.GetUserTokens(ctx, "non-existent-user")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}
}

func TestRevokeUserTokens(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	userID := "charlie"
	tokens := []string{"token-1", "token-2", "token-3"}
	ttl := 1 * time.Hour

	// Track multiple tokens
	for _, tokenID := range tokens {
		err := store.TrackUserToken(ctx, userID, tokenID, ttl)
		if err != nil {
			t.Fatalf("Failed to track token: %v", err)
		}
	}

	// Revoke all user tokens
	err := store.RevokeUserTokens(ctx, userID, ttl)
	if err != nil {
		t.Fatalf("Failed to revoke user tokens: %v", err)
	}

	// Verify all tokens are revoked
	for _, tokenID := range tokens {
		isRevoked, err := store.IsTokenRevoked(ctx, tokenID)
		if err != nil {
			t.Fatalf("Failed to check revocation: %v", err)
		}

		if !isRevoked {
			t.Errorf("Token %s should be revoked but is not", tokenID)
		}
	}

	// Verify user token set is removed
	key := userTokenPrefix + userID
	exists, err := store.client.Exists(ctx, key).Result()
	if err != nil {
		t.Fatalf("Failed to check key existence: %v", err)
	}

	if exists != 0 {
		t.Error("User token set should be deleted after revoking all tokens")
	}
}

func TestTTLExpiry(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	tokenID := "expiring-token"
	shortTTL := 2 * time.Second

	// Revoke token with short TTL
	err := store.RevokeToken(ctx, tokenID, shortTTL)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Verify token is revoked
	isRevoked, _ := store.IsTokenRevoked(ctx, tokenID)
	if !isRevoked {
		t.Error("Token should be revoked")
	}

	// Fast-forward time in miniredis
	mr.FastForward(3 * time.Second)

	// Verify token is no longer in Redis (TTL expired)
	isRevoked, _ = store.IsTokenRevoked(ctx, tokenID)
	if isRevoked {
		t.Error("Token should have expired from Redis")
	}
}

func TestClose(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()

	// Close should not panic
	err := store.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Operations after close should fail gracefully
	ctx := context.Background()
	_, err = store.IsTokenRevoked(ctx, "test")
	if err == nil {
		t.Error("Expected error after closing store, got nil")
	}
}

func TestConcurrentOperations(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()
	userID := "concurrent-user"
	numTokens := 100

	// Track multiple tokens concurrently
	errChan := make(chan error, numTokens)
	for i := 0; i < numTokens; i++ {
		go func(idx int) {
			tokenID := string(rune('A' + idx))
			errChan <- store.TrackUserToken(ctx, userID, tokenID, 1*time.Hour)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numTokens; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent track failed: %v", err)
		}
	}

	// Verify all tokens were tracked
	tokens, err := store.GetUserTokens(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to get user tokens: %v", err)
	}

	if len(tokens) != numTokens {
		t.Errorf("Expected %d tokens, got %d", numTokens, len(tokens))
	}
}

// TestStoreCSRFToken tests CSRF token storage
func TestStoreCSRFToken(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()
	token := "test-csrf-token-12345"
	ttl := 5 * time.Minute

	// Store CSRF token
	err := store.StoreCSRFToken(ctx, token, ttl)
	if err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}

	// Verify token exists in Redis
	key := csrfTokenPrefix + token
	val, err := store.client.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("Failed to get CSRF token from Redis: %v", err)
	}

	if val != "1" {
		t.Errorf("Expected value '1', got '%s'", val)
	}

	// Verify TTL is set
	ttlResult := store.client.TTL(ctx, key).Val()
	if ttlResult <= 0 {
		t.Errorf("Expected TTL > 0, got %v", ttlResult)
	}
}

// TestValidateAndConsumeCSRFToken tests CSRF token validation and consumption
func TestValidateAndConsumeCSRFToken(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()

	tests := []struct {
		name       string
		token      string
		storeFirst bool
		wantValid  bool
		wantErr    bool
	}{
		{
			name:       "valid token",
			token:      "valid-token-123",
			storeFirst: true,
			wantValid:  true,
			wantErr:    false,
		},
		{
			name:       "token not found",
			token:      "nonexistent-token",
			storeFirst: false,
			wantValid:  false,
			wantErr:    false,
		},
		{
			name:       "empty token",
			token:      "",
			storeFirst: false,
			wantValid:  false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store token if needed
			if tt.storeFirst {
				err := store.StoreCSRFToken(ctx, tt.token, 5*time.Minute)
				if err != nil {
					t.Fatalf("Failed to store CSRF token: %v", err)
				}
			}

			// Validate and consume
			valid, err := store.ValidateAndConsumeCSRFToken(ctx, tt.token)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if valid != tt.wantValid {
				t.Errorf("Expected valid=%v, got %v", tt.wantValid, valid)
			}

			// Verify token was deleted if it was valid
			if tt.wantValid && tt.storeFirst {
				key := csrfTokenPrefix + tt.token
				exists, err := store.client.Exists(ctx, key).Result()
				if err != nil {
					t.Fatalf("Failed to check token existence: %v", err)
				}
				if exists > 0 {
					t.Error("Token should have been deleted after consumption")
				}
			}
		})
	}
}

// TestValidateAndConsumeCSRFToken_OneTimeUse tests that tokens can only be used once
func TestValidateAndConsumeCSRFToken_OneTimeUse(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()
	token := "one-time-token-456"

	// Store token
	err := store.StoreCSRFToken(ctx, token, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}

	// First validation should succeed
	valid, err := store.ValidateAndConsumeCSRFToken(ctx, token)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}
	if !valid {
		t.Error("First validation should be valid")
	}

	// Second validation should fail (token already consumed)
	valid, err = store.ValidateAndConsumeCSRFToken(ctx, token)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}
	if valid {
		t.Error("Second validation should fail (one-time use)")
	}
}

// TestCSRFTokenExpiry tests that CSRF tokens expire after TTL
func TestCSRFTokenExpiry(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()
	token := "expiring-token-789"
	ttl := 100 * time.Millisecond // Short TTL for testing

	// Store token with short TTL
	err := store.StoreCSRFToken(ctx, token, ttl)
	if err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}

	// Fast-forward time in miniredis
	mr.FastForward(200 * time.Millisecond)

	// Validation should fail (token expired)
	valid, err := store.ValidateAndConsumeCSRFToken(ctx, token)
	if err != nil {
		t.Fatalf("Validation failed with error: %v", err)
	}
	if valid {
		t.Error("Validation should fail for expired token")
	}
}

// TestCSRFTokenConcurrent tests concurrent CSRF token operations
func TestCSRFTokenConcurrent(t *testing.T) {
	store, mr := setupTestRedis(t)
	defer mr.Close()
	defer store.Close()

	ctx := context.Background()
	token := "concurrent-token-abc"

	// Store token
	err := store.StoreCSRFToken(ctx, token, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to store CSRF token: %v", err)
	}

	// Try to consume the same token concurrently from 10 goroutines
	numGoroutines := 10
	successChan := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			valid, _ := store.ValidateAndConsumeCSRFToken(ctx, token)
			successChan <- valid
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		if <-successChan {
			successCount++
		}
	}

	// Only one goroutine should have successfully consumed the token
	if successCount != 1 {
		t.Errorf("Expected exactly 1 successful consumption, got %d", successCount)
	}
}
