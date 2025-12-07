package metrics

import (
	"context"
	"log"
	"time"

	"github.com/klazomenai/jwt-auth-service/pkg/storage"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "jwt"
)

var (
	// ParentTokenExpiryTimestamp tracks when parent tokens expire
	ParentTokenExpiryTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "parent_token_expiry_timestamp_seconds",
			Help:      "Unix timestamp when parent token expires",
		},
		[]string{"user_id", "network", "parent_jti"},
	)

	// ParentTokenIssuedTimestamp tracks when parent tokens were issued
	ParentTokenIssuedTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "parent_token_issued_timestamp_seconds",
			Help:      "Unix timestamp when parent token was issued",
		},
		[]string{"user_id", "network", "parent_jti"},
	)

	// ParentTokensActiveTotal tracks total number of active parent tokens
	ParentTokensActiveTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "parent_tokens_active_total",
			Help:      "Total number of active parent tokens",
		},
	)

	// RevokedTokensTotal tracks total number of revoked tokens
	RevokedTokensTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "revoked_tokens_total",
			Help:      "Total number of revoked tokens",
		},
	)
)

func init() {
	// Register metrics with Prometheus default registry
	prometheus.MustRegister(ParentTokenExpiryTimestamp)
	prometheus.MustRegister(ParentTokenIssuedTimestamp)
	prometheus.MustRegister(ParentTokensActiveTotal)
	prometheus.MustRegister(RevokedTokensTotal)
}

// Collector provides methods to update metrics from storage
type Collector struct {
	store *storage.RedisStore
}

// NewCollector creates a new metrics collector
func NewCollector(store *storage.RedisStore) *Collector {
	return &Collector{
		store: store,
	}
}

// UpdateMetrics refreshes all metrics from current storage state
// This is called on each /metrics scrape to ensure fresh data
func (c *Collector) UpdateMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Reset gauge vectors to remove stale entries
	ParentTokenExpiryTimestamp.Reset()
	ParentTokenIssuedTimestamp.Reset()

	// Get all active auto-renewal configurations
	configs, err := c.store.GetAllAutoRenewalConfigs(ctx)
	if err != nil {
		log.Printf("Warning: Failed to get auto-renewal configs for metrics: %v", err)
		// Don't fail the metrics request - serve stale/zero metrics
		ParentTokensActiveTotal.Set(0)
		return
	}

	// Update per-token metrics
	for _, config := range configs {
		labels := prometheus.Labels{
			"user_id":    config.UserID,
			"network":    config.Network,
			"parent_jti": config.ParentJTI,
		}

		ParentTokenExpiryTimestamp.With(labels).Set(float64(config.ParentExpiry.Unix()))
		ParentTokenIssuedTimestamp.With(labels).Set(float64(config.CreatedAt.Unix()))
	}

	// Update total active tokens
	ParentTokensActiveTotal.Set(float64(len(configs)))
}
