package renewal

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/klazomenai/jwt-auth-service/pkg/auth"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
)

// Test helper: setup test dependencies
func setupTestWorker(t *testing.T) (*Worker, *storage.RedisStore, *auth.JWTService, *miniredis.Miniredis) {
	t.Helper()

	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	// Create Redis store
	store, err := storage.NewRedisStore(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("Failed to create Redis store: %v", err)
		mr.Close()
	}

	// Generate RSA keys for JWT service
	privateKey, err := auth.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
		mr.Close()
	}

	privateKeyPEM := auth.ExportPrivateKeyPEM(privateKey)

	// Create JWT service
	jwtService, err := auth.NewJWTService(
		"https://test-issuer.local",
		"test-audience",
		privateKeyPEM,
	)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
		mr.Close()
	}

	// Create worker with test config
	config := &WorkerConfig{
		CheckInterval:    1 * time.Second,
		RenewalThreshold: 5 * time.Minute,
	}

	worker := NewWorker(config, jwtService, store)

	return worker, store, jwtService, mr
}

func TestNewWorker(t *testing.T) {
	worker, _, _, mr := setupTestWorker(t)
	defer mr.Close()

	if worker == nil {
		t.Fatal("Expected worker to be created")
	}

	if worker.config.CheckInterval != 1*time.Second {
		t.Errorf("Expected check interval 1s, got %v", worker.config.CheckInterval)
	}

	if worker.config.RenewalThreshold != 5*time.Minute {
		t.Errorf("Expected renewal threshold 5m, got %v", worker.config.RenewalThreshold)
	}
}

func TestWorkerStartStop(t *testing.T) {
	worker, _, _, mr := setupTestWorker(t)
	defer mr.Close()

	// Start worker in goroutine
	done := make(chan bool)
	go func() {
		worker.Start()
		done <- true
	}()

	// Let it run for a short time
	time.Sleep(100 * time.Millisecond)

	// Stop worker
	worker.Stop()

	// Wait for completion
	select {
	case <-done:
		// Worker stopped successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Worker did not stop within timeout")
	}
}

func TestProcessRenewals_NoConfigs(t *testing.T) {
	worker, _, _, mr := setupTestWorker(t)
	defer mr.Close()

	// Process renewals with no configs - should not error
	worker.processRenewals()

	// Test passes if no panic/error
}

func TestProcessRenewals_FirstTimeChildGeneration(t *testing.T) {
	worker, store, _, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	// Create auto-renewal config (no existing child token)
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-jti-123",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900, // 15 minutes
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Process renewals - should generate first child token
	worker.processRenewals()

	// Verify child token was created
	latestChild, err := store.GetLatestChildToken(ctx, "parent-jti-123")
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild == nil {
		t.Fatal("Expected child token to be generated")
	}

	if latestChild.ChildToken == "" {
		t.Error("Expected child token to have value")
	}

	if latestChild.ChildJTI == "" {
		t.Error("Expected child JTI to have value")
	}

	if time.Until(latestChild.ExpiresAt) > 15*time.Minute {
		t.Error("Expected child token expiry ~15 minutes")
	}
}

func TestProcessRenewals_RenewalNeeded(t *testing.T) {
	worker, store, jwtService, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	// Create auto-renewal config
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-jti-456",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Create existing child token that expires WITHIN threshold (needs renewal)
	oldToken, oldJTI, err := jwtService.CreateToken("test-user", "testnet", 100, 2*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create old token: %v", err)
	}

	oldChild := &storage.LatestChildToken{
		ChildToken: oldToken,
		ChildJTI:   oldJTI,
		ExpiresAt:  time.Now().Add(2 * time.Minute), // Expires in 2 min (< 5 min threshold)
		RenewedAt:  time.Now().Add(-10 * time.Minute),
	}

	err = store.StoreLatestChildToken(ctx, "parent-jti-456", oldChild)
	if err != nil {
		t.Fatalf("Failed to store old child token: %v", err)
	}

	// Process renewals - should renew the child token
	worker.processRenewals()

	// Verify new child token was created
	latestChild, err := store.GetLatestChildToken(ctx, "parent-jti-456")
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild.ChildJTI == oldJTI {
		t.Error("Expected new child token JTI, got same as old")
	}

	if latestChild.RenewedAt.Before(oldChild.RenewedAt) {
		t.Error("Expected renewed_at to be updated")
	}
}

func TestProcessRenewals_RenewalNotNeeded(t *testing.T) {
	worker, store, jwtService, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	// Create auto-renewal config
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-jti-789",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Create existing child token that expires BEYOND threshold (no renewal)
	oldToken, oldJTI, err := jwtService.CreateToken("test-user", "testnet", 100, 20*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create old token: %v", err)
	}

	oldChild := &storage.LatestChildToken{
		ChildToken: oldToken,
		ChildJTI:   oldJTI,
		ExpiresAt:  time.Now().Add(20 * time.Minute), // Expires in 20 min (> 5 min threshold)
		RenewedAt:  time.Now(),
	}

	err = store.StoreLatestChildToken(ctx, "parent-jti-789", oldChild)
	if err != nil {
		t.Fatalf("Failed to store old child token: %v", err)
	}

	// Process renewals - should NOT renew
	worker.processRenewals()

	// Verify child token was NOT changed
	latestChild, err := store.GetLatestChildToken(ctx, "parent-jti-789")
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild.ChildJTI != oldJTI {
		t.Error("Expected child token JTI to remain unchanged")
	}
}

func TestProcessRenewals_ParentTokenRevoked(t *testing.T) {
	worker, store, _, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	// Create auto-renewal config
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-jti-revoked",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Revoke parent token
	err = store.RevokeToken(ctx, "parent-jti-revoked", 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to revoke parent token: %v", err)
	}

	// Process renewals - should delete config
	worker.processRenewals()

	// Verify config was deleted
	deletedConfig, err := store.GetAutoRenewalConfig(ctx, "parent-jti-revoked")
	if err != nil {
		t.Fatalf("Failed to check config deletion: %v", err)
	}

	if deletedConfig != nil {
		t.Error("Expected auto-renewal config to be deleted for revoked parent token")
	}

	// Verify no child token was created
	latestChild, err := store.GetLatestChildToken(ctx, "parent-jti-revoked")
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild != nil {
		t.Error("Expected no child token for revoked parent")
	}
}

func TestProcessConfig_ErrorHandling(t *testing.T) {
	worker, _, _, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	// Test with invalid config (non-existent parent JTI)
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "non-existent-parent",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	// Should handle gracefully (first-time generation)
	renewed, err := worker.processConfig(ctx, config)
	if err != nil {
		t.Errorf("Expected no error for first-time generation, got: %v", err)
	}

	if !renewed {
		t.Error("Expected renewal to succeed for first-time generation")
	}
}

func TestProcessConfig_SetsParentJTI(t *testing.T) {
	worker, store, jwtService, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	parentJTI := "parent-jti-linkage-test"
	config := &storage.AutoRenewalConfig{
		ParentJTI:    parentJTI,
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Process renewals to generate child token
	worker.processRenewals()

	// Get generated child token
	latestChild, err := store.GetLatestChildToken(ctx, parentJTI)
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild == nil {
		t.Fatal("Expected child token to be generated")
	}

	// Validate the child token and check parent_jti claim
	claims, err := jwtService.ValidateToken(latestChild.ChildToken)
	if err != nil {
		t.Fatalf("Failed to validate child token: %v", err)
	}

	if claims.ParentJTI != parentJTI {
		t.Errorf("Expected parent_jti %q, got %q", parentJTI, claims.ParentJTI)
	}

	if claims.TokenType != auth.TokenTypeChild {
		t.Errorf("Expected token_type %q, got %q", auth.TokenTypeChild, claims.TokenType)
	}
}

func TestProcessConfig_TracksChildToken(t *testing.T) {
	worker, store, _, mr := setupTestWorker(t)
	defer mr.Close()

	ctx := context.Background()

	parentJTI := "parent-jti-tracking-test"
	config := &storage.AutoRenewalConfig{
		ParentJTI:    parentJTI,
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err := store.StoreAutoRenewalConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to store auto-renewal config: %v", err)
	}

	// Process renewals to generate child token
	worker.processRenewals()

	// Get the child JTI from latest child token
	latestChild, err := store.GetLatestChildToken(ctx, parentJTI)
	if err != nil {
		t.Fatalf("Failed to get latest child token: %v", err)
	}

	if latestChild == nil {
		t.Fatal("Expected child token to be generated")
	}

	// Verify child JTI is tracked in parent:children set
	children, err := store.GetChildTokens(ctx, parentJTI)
	if err != nil {
		t.Fatalf("Failed to get child tokens: %v", err)
	}

	if len(children) == 0 {
		t.Fatal("Expected at least one child token tracked")
	}

	found := false
	for _, childJTI := range children {
		if childJTI == latestChild.ChildJTI {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected child JTI %q to be tracked under parent %q", latestChild.ChildJTI, parentJTI)
	}
}

func TestWorkerConfig_Validation(t *testing.T) {
	tests := []struct {
		name             string
		checkInterval    time.Duration
		renewalThreshold time.Duration
		expectValid      bool
	}{
		{
			name:             "valid_config",
			checkInterval:    30 * time.Second,
			renewalThreshold: 2 * time.Minute,
			expectValid:      true,
		},
		{
			name:             "zero_check_interval",
			checkInterval:    0,
			renewalThreshold: 2 * time.Minute,
			expectValid:      true, // Worker will accept but may not work as expected
		},
		{
			name:             "zero_threshold",
			checkInterval:    30 * time.Second,
			renewalThreshold: 0,
			expectValid:      true, // Immediate renewal (edge case)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &WorkerConfig{
				CheckInterval:    tt.checkInterval,
				RenewalThreshold: tt.renewalThreshold,
			}

			// Just verify config can be created (no validation in constructor currently)
			if config.CheckInterval != tt.checkInterval {
				t.Errorf("Expected check interval %v, got %v", tt.checkInterval, config.CheckInterval)
			}
		})
	}
}
