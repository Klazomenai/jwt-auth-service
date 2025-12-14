package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/klazomenai/jwt-auth-service/pkg/api"
	"github.com/klazomenai/jwt-auth-service/pkg/auth"
	"github.com/klazomenai/jwt-auth-service/pkg/renewal"
	"github.com/klazomenai/jwt-auth-service/pkg/storage"
)

func main() {
	// Load configuration from environment
	port := getEnv("PORT", "8080")
	issuer := os.Getenv("JWT_ISSUER")
	audience := os.Getenv("JWT_AUDIENCE")
	redisAddr := getEnv("REDIS_ADDR", "redis:6379")
	redisPassword := getEnv("REDIS_PASSWORD", "")
	redisDB := 0

	// Validate required configuration
	if issuer == "" || audience == "" {
		log.Fatal("JWT_ISSUER and JWT_AUDIENCE environment variables are required")
	}

	// Load or generate RSA private key
	privateKeyPEM, err := loadOrGeneratePrivateKey()
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// Initialize JWT service
	jwtService, err := auth.NewJWTService(issuer, audience, privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to initialize JWT service: %v", err)
	}

	log.Printf("JWT Service initialized with issuer: %s, audience: %s", issuer, audience)

	// Initialize Redis store
	redisStore, err := storage.NewRedisStore(redisAddr, redisPassword, redisDB)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisStore.Close()

	log.Printf("Connected to Redis at %s", redisAddr)

	// Create API server
	server := api.NewServer(jwtService, redisStore)

	// Get auto-renewal worker configuration
	renewalThreshold := getEnvDuration("AUTO_RENEW_THRESHOLD_SECONDS", 120)       // Default: 120 seconds (2 min)
	renewalInterval := getEnvDuration("AUTO_RENEW_WORKER_INTERVAL", 30)          // Default: 30 seconds

	// Create and start auto-renewal worker
	workerConfig := &renewal.WorkerConfig{
		CheckInterval:    renewalInterval,
		RenewalThreshold: renewalThreshold,
	}
	renewalWorker := renewal.NewWorker(workerConfig, jwtService, redisStore)

	// Start worker in goroutine
	go renewalWorker.Start()
	log.Printf("Auto-renewal worker started (check_interval=%s, renewal_threshold=%s)", renewalInterval, renewalThreshold)

	// Start HTTP server
	addr := ":" + port
	log.Printf("Starting JWT Token Service on %s", addr)
	log.Printf("Endpoints:")
	log.Printf("  POST   /tokens - Create new token")
	log.Printf("  POST   /token-pairs - Create token family (parent + optional child)")
	log.Printf("  POST   /renew - Manual child token generation")
	log.Printf("  GET    /tokens/latest?parent_jti=<jti> - Get latest auto-renewed child token (polling)")
	log.Printf("  GET    /tokens/stream?parent_jti=<jti> - Stream child token updates (SSE)")
	log.Printf("  DELETE /tokens/:parent_jti - Revoke parent token")
	log.Printf("  DELETE /users/:userID/tokens - Revoke all user tokens")
	log.Printf("  GET    /.well-known/jwks.json - JWK Set")
	log.Printf("  GET    /health - Health check")
	log.Printf("  GET    /metrics - Prometheus metrics")

	srv := &http.Server{
		Addr:         addr,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, stopping services...")

	// Stop renewal worker
	renewalWorker.Stop()

	// Close Redis connection
	redisStore.Close()

	log.Println("Shutdown complete")
}

// loadOrGeneratePrivateKey loads private key from file or generates new one
func loadOrGeneratePrivateKey() ([]byte, error) {
	keyPath := getEnv("PRIVATE_KEY_PATH", "/etc/jwt-service/private-key.pem")

	// Try to load existing key
	if _, err := os.Stat(keyPath); err == nil {
		log.Printf("Loading private key from %s", keyPath)
		return os.ReadFile(keyPath)
	}

	// Generate new key for development/testing
	log.Printf("Generating new RSA private key...")
	privateKey, err := auth.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	privateKeyPEM := auth.ExportPrivateKeyPEM(privateKey)

	// Save key if directory exists
	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		log.Printf("Warning: Could not save private key to %s: %v", keyPath, err)
	} else {
		log.Printf("Saved private key to %s", keyPath)
	}

	// Export public key for reference
	publicKeyPEM, err := auth.ExportPublicKeyPEM(&privateKey.PublicKey)
	if err == nil {
		publicKeyPath := getEnv("PUBLIC_KEY_PATH", "/etc/jwt-service/public-key.pem")
		if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err == nil {
			log.Printf("Saved public key to %s", publicKeyPath)
		}
	}

	return privateKeyPEM, nil
}

// getEnv gets environment variable or returns default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvDuration gets duration from environment variable (in seconds) or returns default
func getEnvDuration(key string, defaultSeconds int) time.Duration {
	if value := os.Getenv(key); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
		log.Printf("Warning: Invalid value for %s, using default %d seconds", key, defaultSeconds)
	}
	return time.Duration(defaultSeconds) * time.Second
}
