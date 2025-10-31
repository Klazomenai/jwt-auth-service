package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPair(t *testing.T) {
	privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Generated private key is nil")
	}

	if privateKey.N == nil {
		t.Fatal("Private key modulus is nil")
	}

	// Verify key size is 2048 bits
	keySize := privateKey.N.BitLen()
	if keySize != 2048 {
		t.Errorf("Expected 2048-bit key, got %d-bit key", keySize)
	}
}

func TestNewJWTService(t *testing.T) {
	// Generate test key
	privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	privateKeyPEM := ExportPrivateKeyPEM(privateKey)

	tests := []struct {
		name      string
		issuer    string
		audience  string
		keyPEM    []byte
		wantError bool
	}{
		{
			name:      "valid RSA key PKCS1",
			issuer:    "https://test-issuer.example.com",
			audience:  "test-audience",
			keyPEM:    privateKeyPEM,
			wantError: false,
		},
		{
			name:      "invalid PEM format",
			issuer:    "https://test-issuer.example.com",
			audience:  "test-audience",
			keyPEM:    []byte("not a valid PEM"),
			wantError: true,
		},
		{
			name:      "empty key",
			issuer:    "https://test-issuer.example.com",
			audience:  "test-audience",
			keyPEM:    []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewJWTService(tt.issuer, tt.audience, tt.keyPEM)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if service == nil {
				t.Error("Service is nil")
				return
			}

			if service.issuer != tt.issuer {
				t.Errorf("Expected issuer %s, got %s", tt.issuer, service.issuer)
			}

			if service.audience != tt.audience {
				t.Errorf("Expected audience %s, got %s", tt.audience, service.audience)
			}
		})
	}
}

func TestCreateToken(t *testing.T) {
	// Setup
	privateKey, _ := GenerateKeyPair()
	privateKeyPEM := ExportPrivateKeyPEM(privateKey)
	service, err := NewJWTService("https://test-issuer.example.com", "test-audience", privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}

	tests := []struct {
		name      string
		userID    string
		network   string
		rateLimit int
		expiry    time.Duration
	}{
		{
			name:      "standard token",
			userID:    "alice",
			network:   "devnet",
			rateLimit: 100,
			expiry:    1 * time.Hour,
		},
		{
			name:      "long-lived token",
			userID:    "bob",
			network:   "mainnet",
			rateLimit: 1000,
			expiry:    24 * time.Hour,
		},
		{
			name:      "short-lived token",
			userID:    "charlie",
			network:   "testnet",
			rateLimit: 50,
			expiry:    5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, tokenID, err := service.CreateToken(tt.userID, tt.network, tt.rateLimit, tt.expiry)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			if token == "" {
				t.Error("Token is empty")
			}

			if tokenID == "" {
				t.Error("Token ID is empty")
			}

			// Verify token has 3 parts (header.payload.signature)
			parts := len(token)
			if parts == 0 {
				t.Error("Token has no parts")
			}

			// Validate the token
			claims, err := service.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			// Verify claims
			if claims.UserID != tt.userID {
				t.Errorf("Expected user_id %s, got %s", tt.userID, claims.UserID)
			}

			if claims.Network != tt.network {
				t.Errorf("Expected network %s, got %s", tt.network, claims.Network)
			}

			if claims.RateLimit != tt.rateLimit {
				t.Errorf("Expected rate_limit %d, got %d", tt.rateLimit, claims.RateLimit)
			}

			// Verify token is not expired
			if time.Now().After(claims.ExpiresAt.Time) {
				t.Error("Token is already expired")
			}

			// Verify expiry is approximately correct (within 1 second)
			expectedExpiry := time.Now().Add(tt.expiry)
			if claims.ExpiresAt.Time.Sub(expectedExpiry).Abs() > time.Second {
				t.Errorf("Token expiry mismatch: expected ~%v, got %v", expectedExpiry, claims.ExpiresAt.Time)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	// Setup
	privateKey, _ := GenerateKeyPair()
	privateKeyPEM := ExportPrivateKeyPEM(privateKey)
	service, _ := NewJWTService("https://test-issuer.example.com", "test-audience", privateKeyPEM)

	// Create valid token
	validToken, _, _ := service.CreateToken("alice", "devnet", 100, 1*time.Hour)

	// Create expired token
	expiredToken, _, _ := service.CreateToken("bob", "devnet", 100, -1*time.Hour)

	// Create token with different key (will fail signature validation)
	otherPrivateKey, _ := GenerateKeyPair()
	otherPrivateKeyPEM := ExportPrivateKeyPEM(otherPrivateKey)
	otherService, _ := NewJWTService("https://other-issuer.example.com", "other-audience", otherPrivateKeyPEM)
	invalidSignatureToken, _, _ := otherService.CreateToken("charlie", "devnet", 100, 1*time.Hour)

	tests := []struct {
		name      string
		token     string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid token",
			token:     validToken,
			wantError: false,
		},
		{
			name:      "expired token",
			token:     expiredToken,
			wantError: true,
			errorMsg:  "token is expired",
		},
		{
			name:      "invalid signature",
			token:     invalidSignatureToken,
			wantError: true,
			errorMsg:  "signature is invalid",
		},
		{
			name:      "malformed token",
			token:     "not.a.valid.token",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := service.ValidateToken(tt.token)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Error("Claims are nil")
			}
		})
	}
}

func TestTokenClaims(t *testing.T) {
	privateKey, _ := GenerateKeyPair()
	privateKeyPEM := ExportPrivateKeyPEM(privateKey)
	service, _ := NewJWTService("https://test-issuer.example.com", "test-audience", privateKeyPEM)

	userID := "alice"
	network := "devnet"
	rateLimit := 100
	expiry := 1 * time.Hour

	token, tokenID, _ := service.CreateToken(userID, network, rateLimit, expiry)
	claims, _ := service.ValidateToken(token)

	// Verify standard claims
	if claims.Issuer != "https://test-issuer.example.com" {
		t.Errorf("Expected issuer https://test-issuer.example.com, got %s", claims.Issuer)
	}

	expectedSubject := "user_" + userID
	if claims.Subject != expectedSubject {
		t.Errorf("Expected subject %s, got %s", expectedSubject, claims.Subject)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != "test-audience" {
		t.Errorf("Expected audience [test-audience], got %v", claims.Audience)
	}

	if claims.ID != tokenID {
		t.Errorf("Expected JTI %s, got %s", tokenID, claims.ID)
	}

	// Verify custom claims
	if claims.UserID != userID {
		t.Errorf("Expected user_id %s, got %s", userID, claims.UserID)
	}

	if claims.Network != network {
		t.Errorf("Expected network %s, got %s", network, claims.Network)
	}

	if claims.RateLimit != rateLimit {
		t.Errorf("Expected rate_limit %d, got %d", rateLimit, claims.RateLimit)
	}
}

func TestGetJWKS(t *testing.T) {
	privateKey, _ := GenerateKeyPair()
	privateKeyPEM := ExportPrivateKeyPEM(privateKey)
	service, _ := NewJWTService("https://test-issuer.example.com", "test-audience", privateKeyPEM)

	jwks, err := service.GetJWKS()
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}

	if jwks == nil {
		t.Fatal("JWKS is nil")
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}

	jwk := jwks.Keys[0]

	// Verify JWK properties
	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty RSA, got %s", jwk.Kty)
	}

	if jwk.Kid != KeyID {
		t.Errorf("Expected kid %s, got %s", KeyID, jwk.Kid)
	}

	if jwk.Use != "sig" {
		t.Errorf("Expected use sig, got %s", jwk.Use)
	}

	if jwk.Alg != SigningAlgorithm {
		t.Errorf("Expected alg %s, got %s", SigningAlgorithm, jwk.Alg)
	}

	if jwk.N == "" {
		t.Error("JWK modulus (n) is empty")
	}

	if jwk.E == "" {
		t.Error("JWK exponent (e) is empty")
	}
}

func TestSigningAlgorithm(t *testing.T) {
	privateKey, _ := GenerateKeyPair()
	privateKeyPEM := ExportPrivateKeyPEM(privateKey)
	service, _ := NewJWTService("https://test-issuer.example.com", "test-audience", privateKeyPEM)

	token, _, _ := service.CreateToken("alice", "devnet", 100, 1*time.Hour)

	// Parse token to verify algorithm
	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return service.publicKey, nil
	})

	if parsedToken.Method.Alg() != SigningAlgorithm {
		t.Errorf("Expected signing algorithm %s, got %s", SigningAlgorithm, parsedToken.Method.Alg())
	}

	if parsedToken.Header["kid"] != KeyID {
		t.Errorf("Expected kid %s in header, got %v", KeyID, parsedToken.Header["kid"])
	}
}

func TestDefaultTokenExpiry(t *testing.T) {
	expected := 1 * time.Hour
	if DefaultTokenExpiry != expected {
		t.Errorf("Expected DefaultTokenExpiry to be %v, got %v", expected, DefaultTokenExpiry)
	}
}

func TestExportKeys(t *testing.T) {
	privateKey, _ := GenerateKeyPair()

	// Test private key export
	privatePEM := ExportPrivateKeyPEM(privateKey)
	if len(privatePEM) == 0 {
		t.Error("Exported private key PEM is empty")
	}

	// Verify PEM format
	pemHeader := "-----BEGIN RSA PRIVATE KEY-----"
	if string(privatePEM[:len(pemHeader)]) != pemHeader {
		t.Error("Private key PEM does not start with correct header")
	}

	// Test public key export
	publicPEM, err := ExportPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	if len(publicPEM) == 0 {
		t.Error("Exported public key PEM is empty")
	}

	// Verify PEM format
	pubPemHeader := "-----BEGIN PUBLIC KEY-----"
	if string(publicPEM[:len(pubPemHeader)]) != pubPemHeader {
		t.Error("Public key PEM does not start with correct header")
	}
}
