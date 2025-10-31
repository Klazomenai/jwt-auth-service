package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Key prefix for revoked tokens
	revokedTokenPrefix = "revoked:token:"
	// Key prefix for user token tracking
	userTokenPrefix = "user:tokens:"
	// Key prefix for auto-renewal configurations
	autoRenewalConfigPrefix = "auto_renew:config:"
	// Key prefix for latest access tokens
	latestAccessTokenPrefix = "auto_renew:latest:"
	// Key for set of all active auto-renewal renewal JTIs
	autoRenewalSetKey = "auto_renew:active_set"
)

// RedisStore handles token storage and revocation
type RedisStore struct {
	client *redis.Client
}

// AutoRenewalConfig stores configuration for server-side auto-renewal
type AutoRenewalConfig struct {
	ParentJTI    string    `json:"parent_jti"`
	UserID       string    `json:"user_id"`
	Network      string    `json:"network"`
	RateLimit    int       `json:"rate_limit"`
	ChildExpiry  int64     `json:"child_expiry"`   // Duration in seconds
	ParentExpiry time.Time `json:"parent_expiry"`  // Absolute expiry time
	CreatedAt    time.Time `json:"created_at"`
}

// LatestChildToken stores the latest auto-renewed child token
type LatestChildToken struct {
	ChildToken string    `json:"child_token"`
	ChildJTI   string    `json:"child_jti"`
	ExpiresAt  time.Time `json:"expires_at"`
	RenewedAt  time.Time `json:"renewed_at"`
}

// NewRedisStore creates a new Redis storage client
func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStore{
		client: client,
	}, nil
}

// RevokeToken marks a token as revoked with TTL matching token expiry
func (s *RedisStore) RevokeToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	key := revokedTokenPrefix + tokenID
	return s.client.Set(ctx, key, "1", ttl).Err()
}

// IsTokenRevoked checks if a token has been revoked
func (s *RedisStore) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	key := revokedTokenPrefix + tokenID
	val, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil // Token not found = not revoked
	}
	if err != nil {
		return false, fmt.Errorf("failed to check token revocation: %w", err)
	}
	return val == "1", nil
}

// TrackUserToken associates a token with a user for listing/revoking all user tokens
func (s *RedisStore) TrackUserToken(ctx context.Context, userID, tokenID string, ttl time.Duration) error {
	key := userTokenPrefix + userID

	// Add token to user's set
	if err := s.client.SAdd(ctx, key, tokenID).Err(); err != nil {
		return fmt.Errorf("failed to track user token: %w", err)
	}

	// Set expiry on the set
	if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set expiry on user tokens: %w", err)
	}

	return nil
}

// GetUserTokens retrieves all active tokens for a user
func (s *RedisStore) GetUserTokens(ctx context.Context, userID string) ([]string, error) {
	key := userTokenPrefix + userID
	tokens, err := s.client.SMembers(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user tokens: %w", err)
	}
	return tokens, nil
}

// RevokeUserTokens revokes all tokens for a specific user
func (s *RedisStore) RevokeUserTokens(ctx context.Context, userID string, ttl time.Duration) error {
	tokens, err := s.GetUserTokens(ctx, userID)
	if err != nil {
		return err
	}

	for _, tokenID := range tokens {
		if err := s.RevokeToken(ctx, tokenID, ttl); err != nil {
			return err
		}
	}

	// Clear user token set
	key := userTokenPrefix + userID
	return s.client.Del(ctx, key).Err()
}

// RemoveTokenFromUser removes a token from user's active token list
func (s *RedisStore) RemoveTokenFromUser(ctx context.Context, userID, tokenID string) error {
	key := userTokenPrefix + userID
	return s.client.SRem(ctx, key, tokenID).Err()
}

// StoreAutoRenewalConfig stores configuration for server-side auto-renewal
func (s *RedisStore) StoreAutoRenewalConfig(ctx context.Context, config *AutoRenewalConfig) error {
	key := autoRenewalConfigPrefix + config.ParentJTI

	// Serialize config to JSON
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal auto-renewal config: %w", err)
	}

	// Store config with TTL matching parent token expiry
	ttl := time.Until(config.ParentExpiry)
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store auto-renewal config: %w", err)
	}

	// Add to active set for quick lookup
	if err := s.client.SAdd(ctx, autoRenewalSetKey, config.ParentJTI).Err(); err != nil {
		return fmt.Errorf("failed to add to auto-renewal set: %w", err)
	}

	return nil
}

// GetAutoRenewalConfig retrieves auto-renewal configuration for a parent token
func (s *RedisStore) GetAutoRenewalConfig(ctx context.Context, parentJTI string) (*AutoRenewalConfig, error) {
	key := autoRenewalConfigPrefix + parentJTI

	data, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil // Config not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get auto-renewal config: %w", err)
	}

	var config AutoRenewalConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auto-renewal config: %w", err)
	}

	return &config, nil
}

// GetAllAutoRenewalConfigs retrieves all active auto-renewal configurations
func (s *RedisStore) GetAllAutoRenewalConfigs(ctx context.Context) ([]*AutoRenewalConfig, error) {
	// Get all parent JTIs from set
	parentJTIs, err := s.client.SMembers(ctx, autoRenewalSetKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get auto-renewal set: %w", err)
	}

	configs := make([]*AutoRenewalConfig, 0, len(parentJTIs))
	for _, jti := range parentJTIs {
		config, err := s.GetAutoRenewalConfig(ctx, jti)
		if err != nil {
			return nil, err
		}
		if config != nil {
			configs = append(configs, config)
		} else {
			// Config expired, remove from set
			s.client.SRem(ctx, autoRenewalSetKey, jti)
		}
	}

	return configs, nil
}

// DeleteAutoRenewalConfig removes auto-renewal configuration (called when parent token revoked)
func (s *RedisStore) DeleteAutoRenewalConfig(ctx context.Context, parentJTI string) error {
	key := autoRenewalConfigPrefix + parentJTI

	// Delete config
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete auto-renewal config: %w", err)
	}

	// Remove from active set
	if err := s.client.SRem(ctx, autoRenewalSetKey, parentJTI).Err(); err != nil {
		return fmt.Errorf("failed to remove from auto-renewal set: %w", err)
	}

	// Delete latest child token
	latestKey := latestAccessTokenPrefix + parentJTI
	if err := s.client.Del(ctx, latestKey).Err(); err != nil {
		return fmt.Errorf("failed to delete latest child token: %w", err)
	}

	return nil
}

// StoreLatestChildToken stores the latest auto-renewed child token
func (s *RedisStore) StoreLatestChildToken(ctx context.Context, parentJTI string, token *LatestChildToken) error {
	key := latestAccessTokenPrefix + parentJTI

	// Serialize token to JSON
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal latest child token: %w", err)
	}

	// Store with TTL matching child token expiry
	ttl := time.Until(token.ExpiresAt)
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store latest child token: %w", err)
	}

	return nil
}

// GetLatestChildToken retrieves the latest auto-renewed child token
func (s *RedisStore) GetLatestChildToken(ctx context.Context, parentJTI string) (*LatestChildToken, error) {
	key := latestAccessTokenPrefix + parentJTI

	data, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil // Token not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest child token: %w", err)
	}

	var token LatestChildToken
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal latest child token: %w", err)
	}

	return &token, nil
}

// Close closes the Redis connection
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// Health checks Redis connection health
func (s *RedisStore) Health(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}
