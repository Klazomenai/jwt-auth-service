package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// RS256 algorithm for JWT signing
	SigningAlgorithm = "RS256"
	// Default token expiry: 1 hour (short-lived tokens for security)
	// This limits the window of opportunity if a token is compromised
	// See JWT-NOTES.md for rationale and future roadmap
	DefaultTokenExpiry = 1 * time.Hour
	// Key ID for JWK rotation
	KeyID = "autonity-jwt-key-1"

	// Token Family defaults
	DefaultChildTokenExpiry   = 15 * time.Minute  // Short-lived child tokens
	DefaultParentTokenExpiry  = 30 * 24 * time.Hour  // 30 days
	DefaultRenewalIntervalFactor = 0.67  // Renew at 2/3 of child token lifetime

	// Token types
	TokenTypeChild  = "child"
	TokenTypeParent = "parent"
)

// TokenClaims represents the JWT claims structure
type TokenClaims struct {
	jwt.RegisteredClaims
	Network     string `json:"network"`
	RateLimit   int    `json:"rate_limit,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	TokenType   string `json:"token_type,omitempty"`   // "child" or "parent"
	ParentJTI   string `json:"parent_jti,omitempty"`   // Links child token to parent token
}

// JWTService handles JWT token operations
type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// NewJWTService creates a new JWT service with RSA key pair
func NewJWTService(issuer, audience string, privateKeyPEM []byte) (*JWTService, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return &JWTService{
		privateKey: rsaKey,
		publicKey:  &rsaKey.PublicKey,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

// GenerateKeyPair generates a new RSA key pair for testing
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// CreateToken creates a new JWT token with specified claims
func (s *JWTService) CreateToken(userID, network string, rateLimit int, expiry time.Duration) (string, string, error) {
	now := time.Now()
	tokenID := uuid.New().String()

	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("user_%s", userID),
			Audience:  jwt.ClaimStrings{s.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
		Network:   network,
		RateLimit: rateLimit,
		UserID:    userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = KeyID

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, tokenID, nil
}

// TokenPairResponse represents a parent + child token pair
type TokenPairResponse struct {
	ParentToken  string `json:"parent_token"`
	ChildToken   string `json:"child_token,omitempty"`  // Optional, only when include_child=true
	ParentJTI    string `json:"parent_jti"`
	ChildJTI     string `json:"child_jti,omitempty"`    // Optional, only when include_child=true
	ParentExpiry int64  `json:"parent_expiry"`          // Parent token expiry in seconds
	ChildExpiry  int64  `json:"child_expiry,omitempty"` // Child token expiry in seconds (if included)
}

// CreateTokenPair creates a parent token + optional child token pair
func (s *JWTService) CreateTokenPair(userID, network string, rateLimit int, childExpiry, parentExpiry time.Duration, includeChild bool) (*TokenPairResponse, error) {
	now := time.Now()

	// Generate unique IDs for both tokens
	parentJTI := uuid.New().String()

	// Create parent token (long-lived)
	parentClaims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("user_%s", userID),
			Audience:  jwt.ClaimStrings{s.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(parentExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        parentJTI,
		},
		Network:   network,
		RateLimit: rateLimit,
		UserID:    userID,
		TokenType: TokenTypeParent,
	}

	parentTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, parentClaims)
	parentTokenObj.Header["kid"] = KeyID

	parentToken, err := parentTokenObj.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign parent token: %w", err)
	}

	response := &TokenPairResponse{
		ParentToken:  parentToken,
		ParentJTI:    parentJTI,
		ParentExpiry: int64(parentExpiry.Seconds()),
	}

	// Optionally create child token (short-lived) linked to parent token
	if includeChild {
		childJTI := uuid.New().String()

		childClaims := TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    s.issuer,
				Subject:   fmt.Sprintf("user_%s", userID),
				Audience:  jwt.ClaimStrings{s.audience},
				ExpiresAt: jwt.NewNumericDate(now.Add(childExpiry)),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        childJTI,
			},
			Network:   network,
			RateLimit: rateLimit,
			UserID:    userID,
			TokenType: TokenTypeChild,
			ParentJTI: parentJTI, // Link to parent token
		}

		childTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, childClaims)
		childTokenObj.Header["kid"] = KeyID

		childToken, err := childTokenObj.SignedString(s.privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign child token: %w", err)
		}

		response.ChildToken = childToken
		response.ChildJTI = childJTI
		response.ChildExpiry = int64(childExpiry.Seconds())
	}

	return response, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing algorithm
		if token.Method.Alg() != SigningAlgorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetJWKS returns the JSON Web Key Set for public key distribution
func (s *JWTService) GetJWKS() (*JWKSet, error) {
	// Encode the public key modulus (n) and exponent (e) in base64url
	nBytes := s.publicKey.N.Bytes()
	eBytes := big.NewInt(int64(s.publicKey.E)).Bytes()

	jwk := JWK{
		Kty: "RSA",
		Kid: KeyID,
		Use: "sig",
		Alg: SigningAlgorithm,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	return &JWKSet{
		Keys: []JWK{jwk},
	}, nil
}

// ExportPrivateKeyPEM exports the private key as PEM
func ExportPrivateKeyPEM(key *rsa.PrivateKey) []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return privateKeyPEM
}

// ExportPublicKeyPEM exports the public key as PEM
func ExportPublicKeyPEM(key *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return publicKeyPEM, nil
}

// MarshalJWKS marshals the JWKS to JSON
func (jwks *JWKSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Keys []JWK `json:"keys"`
	}{
		Keys: jwks.Keys,
	})
}
