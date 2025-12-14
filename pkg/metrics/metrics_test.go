package metrics

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Note: Tests use t.Context() which requires Go 1.21+

// setupTestMetrics creates a test environment with miniredis
func setupTestMetrics(t *testing.T) (*Collector, *storage.RedisStore, *miniredis.Miniredis) {
	t.Helper()

	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	// Create Redis store
	store, err := storage.NewRedisStore(mr.Addr(), "", 0)
	if err != nil {
		mr.Close()
		t.Fatalf("Failed to create Redis store: %v", err)
	}

	collector := NewCollector(store)

	return collector, store, mr
}

// getGaugeValue extracts the float64 value from a Gauge metric
func getGaugeValue(g prometheus.Gauge) float64 {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// getGaugeVecValue extracts the float64 value from a GaugeVec with specific labels
func getGaugeVecValue(gv *prometheus.GaugeVec, labels prometheus.Labels) float64 {
	gauge, err := gv.GetMetricWith(labels)
	if err != nil {
		return 0
	}
	return getGaugeValue(gauge)
}

func TestNewCollector(t *testing.T) {
	collector, _, mr := setupTestMetrics(t)
	defer mr.Close()

	if collector == nil {
		t.Fatal("Expected collector to be created")
	}

	if collector.store == nil {
		t.Fatal("Expected collector to have store")
	}
}

func TestUpdateMetrics_NoConfigs(t *testing.T) {
	collector, _, mr := setupTestMetrics(t)
	defer mr.Close()

	// Update metrics with no configurations
	collector.UpdateMetrics()

	// Verify active tokens is 0
	value := getGaugeValue(ParentTokensActiveTotal)
	if value != 0 {
		t.Errorf("Expected 0 active tokens, got %v", value)
	}
}

func TestUpdateMetrics_WithConfigs(t *testing.T) {
	collector, store, mr := setupTestMetrics(t)
	defer mr.Close()

	// Create test auto-renewal config
	config := &storage.AutoRenewalConfig{
		ParentJTI:    "test-parent-jti-123",
		UserID:       "test-user",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now().Add(-1 * time.Hour), // Created 1 hour ago
	}

	ctx := t.Context()
	if err := store.StoreAutoRenewalConfig(ctx, config); err != nil {
		t.Fatalf("Failed to store config: %v", err)
	}

	// Update metrics
	collector.UpdateMetrics()

	// Verify active tokens count
	activeCount := getGaugeValue(ParentTokensActiveTotal)
	if activeCount != 1 {
		t.Errorf("Expected 1 active token, got %v", activeCount)
	}

	// Verify per-token expiry metric
	labels := prometheus.Labels{
		"user_id":    "test-user",
		"network":    "testnet",
		"parent_jti": "test-parent-jti-123",
	}

	expiryValue := getGaugeVecValue(ParentTokenExpiryTimestamp, labels)
	if expiryValue == 0 {
		t.Error("Expected expiry timestamp to be set")
	}

	// Verify expiry is approximately 24 hours from now
	expectedExpiry := float64(config.ParentExpiry.Unix())
	if expiryValue != expectedExpiry {
		t.Errorf("Expected expiry %v, got %v", expectedExpiry, expiryValue)
	}

	// Verify issued timestamp
	issuedValue := getGaugeVecValue(ParentTokenIssuedTimestamp, labels)
	if issuedValue == 0 {
		t.Error("Expected issued timestamp to be set")
	}

	expectedIssued := float64(config.CreatedAt.Unix())
	if issuedValue != expectedIssued {
		t.Errorf("Expected issued %v, got %v", expectedIssued, issuedValue)
	}
}

func TestUpdateMetrics_MultipleConfigs(t *testing.T) {
	collector, store, mr := setupTestMetrics(t)
	defer mr.Close()

	ctx := t.Context()

	// Create multiple test configs
	configs := []*storage.AutoRenewalConfig{
		{
			ParentJTI:    "parent-1",
			UserID:       "user-1",
			Network:      "mainnet",
			RateLimit:    100,
			ChildExpiry:  900,
			ParentExpiry: time.Now().Add(24 * time.Hour),
			CreatedAt:    time.Now(),
		},
		{
			ParentJTI:    "parent-2",
			UserID:       "user-2",
			Network:      "testnet",
			RateLimit:    200,
			ChildExpiry:  600,
			ParentExpiry: time.Now().Add(48 * time.Hour),
			CreatedAt:    time.Now(),
		},
		{
			ParentJTI:    "parent-3",
			UserID:       "user-1", // Same user, different token
			Network:      "mainnet",
			RateLimit:    150,
			ChildExpiry:  900,
			ParentExpiry: time.Now().Add(72 * time.Hour),
			CreatedAt:    time.Now(),
		},
	}

	for _, config := range configs {
		if err := store.StoreAutoRenewalConfig(ctx, config); err != nil {
			t.Fatalf("Failed to store config: %v", err)
		}
	}

	// Update metrics
	collector.UpdateMetrics()

	// Verify total count
	activeCount := getGaugeValue(ParentTokensActiveTotal)
	if activeCount != 3 {
		t.Errorf("Expected 3 active tokens, got %v", activeCount)
	}
}

func TestUpdateMetrics_ResetsStaleMetrics(t *testing.T) {
	collector, store, mr := setupTestMetrics(t)
	defer mr.Close()

	ctx := t.Context()

	// Create initial config
	config1 := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-to-remove",
		UserID:       "user-1",
		Network:      "testnet",
		RateLimit:    100,
		ChildExpiry:  900,
		ParentExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := store.StoreAutoRenewalConfig(ctx, config1); err != nil {
		t.Fatalf("Failed to store config: %v", err)
	}

	// First update
	collector.UpdateMetrics()

	// Verify config is tracked
	labels1 := prometheus.Labels{
		"user_id":    "user-1",
		"network":    "testnet",
		"parent_jti": "parent-to-remove",
	}
	value1 := getGaugeVecValue(ParentTokenExpiryTimestamp, labels1)
	if value1 == 0 {
		t.Error("Expected first config to be tracked")
	}

	// Delete the config
	if err := store.DeleteAutoRenewalConfig(ctx, "parent-to-remove"); err != nil {
		t.Fatalf("Failed to delete config: %v", err)
	}

	// Create new config
	config2 := &storage.AutoRenewalConfig{
		ParentJTI:    "parent-new",
		UserID:       "user-2",
		Network:      "mainnet",
		RateLimit:    200,
		ChildExpiry:  600,
		ParentExpiry: time.Now().Add(48 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := store.StoreAutoRenewalConfig(ctx, config2); err != nil {
		t.Fatalf("Failed to store config: %v", err)
	}

	// Second update (should reset and only show new config)
	collector.UpdateMetrics()

	// Verify only 1 active token
	activeCount := getGaugeValue(ParentTokensActiveTotal)
	if activeCount != 1 {
		t.Errorf("Expected 1 active token after reset, got %v", activeCount)
	}

	// Verify new config is tracked
	labels2 := prometheus.Labels{
		"user_id":    "user-2",
		"network":    "mainnet",
		"parent_jti": "parent-new",
	}
	value2 := getGaugeVecValue(ParentTokenExpiryTimestamp, labels2)
	if value2 == 0 {
		t.Error("Expected new config to be tracked")
	}
}

func TestMetricsRegistration(t *testing.T) {
	// Verify metrics are registered (init() should have run)
	// This test ensures the metrics don't panic on double registration

	// These should already be registered via init()
	// Just verify they exist and can be used
	if ParentTokenExpiryTimestamp == nil {
		t.Error("ParentTokenExpiryTimestamp not registered")
	}
	if ParentTokenIssuedTimestamp == nil {
		t.Error("ParentTokenIssuedTimestamp not registered")
	}
	if ParentTokensActiveTotal == nil {
		t.Error("ParentTokensActiveTotal not registered")
	}
	if RevokedTokensTotal == nil {
		t.Error("RevokedTokensTotal not registered")
	}
}
