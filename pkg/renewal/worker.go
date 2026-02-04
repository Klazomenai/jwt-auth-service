package renewal

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/klazomenai/jwt-auth-service/pkg/auth"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
)

// Worker configuration
type WorkerConfig struct {
	CheckInterval    time.Duration // How often to check for tokens needing renewal
	RenewalThreshold time.Duration // Renew tokens this close to expiry
}

// Worker handles background auto-renewal of access tokens
type Worker struct {
	config     *WorkerConfig
	jwtService *auth.JWTService
	store      *storage.RedisStore
	stopChan   chan struct{}
	doneChan   chan struct{}
}

// NewWorker creates a new auto-renewal worker
func NewWorker(config *WorkerConfig, jwtService *auth.JWTService, store *storage.RedisStore) *Worker {
	return &Worker{
		config:     config,
		jwtService: jwtService,
		store:      store,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}
}

// Start begins the background renewal worker
func (w *Worker) Start() {
	log.Printf("🔄 Starting auto-renewal worker (check_interval=%s, renewal_threshold=%s)",
		w.config.CheckInterval, w.config.RenewalThreshold)

	ticker := time.NewTicker(w.config.CheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	w.processRenewals()

	for {
		select {
		case <-ticker.C:
			w.processRenewals()
		case <-w.stopChan:
			log.Println("🛑 Auto-renewal worker stopping...")
			close(w.doneChan)
			return
		}
	}
}

// Stop gracefully stops the worker
func (w *Worker) Stop() {
	close(w.stopChan)
	<-w.doneChan
	log.Println("✅ Auto-renewal worker stopped")
}

// processRenewals checks all auto-renewal configs and renews tokens if needed
func (w *Worker) processRenewals() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get all active auto-renewal configurations
	configs, err := w.store.GetAllAutoRenewalConfigs(ctx)
	if err != nil {
		log.Printf("❌ Failed to get auto-renewal configs: %v", err)
		return
	}

	if len(configs) == 0 {
		log.Println("ℹ️  No active auto-renewal configurations")
		return
	}

	log.Printf("🔍 Checking %d auto-renewal configurations...", len(configs))

	renewedCount := 0
	skippedCount := 0
	errorCount := 0

	for _, config := range configs {
		renewed, err := w.processConfig(ctx, config)
		if err != nil {
			log.Printf("❌ Error processing renewal for user %s (parent_jti=%s): %v",
				config.UserID, config.ParentJTI, err)
			errorCount++
			continue
		}

		if renewed {
			renewedCount++
		} else {
			skippedCount++
		}
	}

	log.Printf("✅ Renewal cycle complete: renewed=%d, skipped=%d, errors=%d",
		renewedCount, skippedCount, errorCount)
}

// processConfig processes a single auto-renewal configuration
func (w *Worker) processConfig(ctx context.Context, config *storage.AutoRenewalConfig) (bool, error) {
	// Check if parent token has been revoked
	isRevoked, err := w.store.IsTokenRevoked(ctx, config.ParentJTI)
	if err != nil {
		return false, fmt.Errorf("failed to check parent token revocation: %w", err)
	}

	if isRevoked {
		log.Printf("⚠️  Parent token revoked, stopping auto-renewal: user=%s, parent_jti=%s",
			config.UserID, config.ParentJTI)
		// Delete auto-renewal config (per requirement: stop renewal immediately)
		if err := w.store.DeleteAutoRenewalConfig(ctx, config.ParentJTI); err != nil {
			return false, fmt.Errorf("failed to delete auto-renewal config: %w", err)
		}
		return false, nil
	}

	// Get current latest child token (if any)
	latestChild, err := w.store.GetLatestChildToken(ctx, config.ParentJTI)
	if err != nil {
		return false, fmt.Errorf("failed to get latest child token: %w", err)
	}

	// Determine if renewal is needed
	needsRenewal := false
	if latestChild == nil {
		// No token exists yet (first-time scenario)
		needsRenewal = true
		log.Printf("🆕 First-time child generation needed: user=%s, parent_jti=%s",
			config.UserID, config.ParentJTI)
	} else {
		// Check if token is within renewal threshold
		timeUntilExpiry := time.Until(latestChild.ExpiresAt)
		if timeUntilExpiry <= w.config.RenewalThreshold {
			needsRenewal = true
			log.Printf("🔄 Child renewal needed: user=%s, time_until_expiry=%s, threshold=%s",
				config.UserID, timeUntilExpiry, w.config.RenewalThreshold)
		}
	}

	if !needsRenewal {
		return false, nil
	}

	// Generate new child token with parent linkage
	childExpiry := time.Duration(config.ChildExpiry) * time.Second
	newChildToken, newChildJTI, err := w.jwtService.CreateChildToken(
		config.UserID,
		config.Network,
		config.RateLimit,
		childExpiry,
		config.ParentJTI,
	)
	if err != nil {
		return false, fmt.Errorf("failed to create new child token: %w", err)
	}

	// Store new child token
	newLatestChild := &storage.LatestChildToken{
		ChildToken: newChildToken,
		ChildJTI:   newChildJTI,
		ExpiresAt:  time.Now().Add(childExpiry),
		RenewedAt:  time.Now(),
	}

	if err := w.store.StoreLatestChildToken(ctx, config.ParentJTI, newLatestChild); err != nil {
		return false, fmt.Errorf("failed to store latest child token: %w", err)
	}

	// Track new child token for user (for revocation purposes)
	if err := w.store.TrackUserToken(ctx, config.UserID, newChildJTI, childExpiry); err != nil {
		log.Printf("⚠️  Warning: Failed to track renewed child token: %v", err)
	}

	// Track child→parent relationship for cascade revocation
	if err := w.store.TrackChildToken(ctx, config.ParentJTI, newChildJTI, time.Until(config.ParentExpiry)); err != nil {
		return false, fmt.Errorf("failed to track child token for cascade: %w", err)
	}

	log.Printf("✅ Child token auto-generated: user=%s, parent_jti=%s, child_jti=%s, expires_at=%s",
		config.UserID, config.ParentJTI, newChildJTI, newLatestChild.ExpiresAt.Format(time.RFC3339))

	return true, nil
}
