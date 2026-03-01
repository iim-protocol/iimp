package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iim-protocol/iimp/server/config"
	"github.com/iim-protocol/iimp/server/iimpserver"
)

var (
	privateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
)

// JWK Set Memory Storage for JWKS endpoint
var JWKSet *jwkset.MemoryJWKSet

func Init(ctx context.Context, privateKeyFile, publicKeyFile string) error {
	privateKeyFileBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("error reading private key file: %w", err)
	}
	publicKeyFileBytes, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("error reading public key file: %w", err)
	}

	privateKeyBlock, _ := pem.Decode(privateKeyFileBytes)
	if privateKeyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM block")
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}

	var ok bool
	privateKey, ok = privateKeyAny.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an Ed25519 key")
	}

	publicKeyBlock, _ := pem.Decode(publicKeyFileBytes)
	if publicKeyBlock == nil {
		return fmt.Errorf("failed to decode public key PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	PublicKey, ok = publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an Ed25519 key")
	}

	// Init JWKSet
	JWKSet = jwkset.NewMemoryStorage()

	metadata := jwkset.JWKMetadataOptions{
		KID:    GetCurrentKeyID(), // needs to return the current key's ID
		ALG:    jwkset.AlgEdDSA,
		USE:    jwkset.UseSig,
		KEYOPS: []jwkset.KEYOPS{jwkset.KeyOpsVerify},
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(PublicKey, options)
	if err != nil {
		return fmt.Errorf("error creating JWK: %w", err)
	}

	// Write the key to jwkset storage
	err = JWKSet.KeyWrite(ctx, jwk)
	if err != nil {
		return fmt.Errorf("error writing JWK to storage: %w", err)
	}

	return nil
}

type SessionClaims struct{ jwt.RegisteredClaims }

type ServerClaims struct{ jwt.RegisteredClaims }

// GenerateSessionToken generates a JWT session token for the given user ID.
//
// Returns the signed JWT token string, the expiration time of the token, and any error that occurred during token generation.
func GenerateSessionToken(userId string) (sessionToken, jti string, expiresAt time.Time, err error) {
	jti, err = generateJTI()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("error generating JTI: %w", err)
	}
	issuer := config.C.Domain
	issuedAt := time.Now()
	expiresAt = issuedAt.Add(time.Second * time.Duration(config.C.JWTExpirationSeconds))
	notBefore := issuedAt.Add(-time.Second * time.Duration(config.C.JWTClockSkewSeconds)) // allow for clock skew

	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    issuer,
			Subject:   userId,
			Audience:  jwt.ClaimStrings{issuer}, // set audience to the issuer since this token is only intended for the server itself
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(notBefore),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = GetCurrentKeyID() // needs to return the current key's ID so that the client can look up the correct key in JWKS
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("error signing token: %w", err)
	}

	return signedToken, jti, expiresAt, nil
}

func ValidateSessionToken(tokenString string) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return PublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	if claims, ok := token.Claims.(*SessionClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

// GenerateServerToken generates a JWT token for server-to-server communication. The audience parameter should be set to the intended recipient of the token (e.g. "https://<receipient-domain>:<receipt-port>")
func GenerateServerToken(audience string) (string, error) {
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("error generating JTI: %w", err)
	}
	issuer := config.C.Domain
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Second * time.Duration(config.C.JWTServerTokenExpirationSeconds))
	notBefore := issuedAt.Add(-time.Second * time.Duration(config.C.JWTClockSkewSeconds)) // allow for clock skew

	claims := ServerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(notBefore),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	// Add kid to header so remote server can look up the correct key in JWKS
	token.Header["kid"] = GetCurrentKeyID()
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return signedToken, nil
}

func ValidateServerToken(ctx context.Context, tokenString string) (*ServerClaims, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &ServerClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	issuer, err := unverified.Claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("error getting issuer from token claims: %w", err)
	}

	jwksURL := fmt.Sprintf("%s%s", issuer, iimpserver.GetJWKSStoreRequestRoutePath)
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("error creating JWKS from URL: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &ServerClaims{}, jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("error parsing token with JWKS keyfunc: %w", err)
	}

	if claims, ok := token.Claims.(*ServerClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// GenerateRefreshToken generates a refresh token that can be used to obtain new session tokens without requiring the user to re-authenticate.
//
// The generated token is a 32 byte random string, encoded in raw base64url format.
func GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes for refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func ValidateRefreshToken(refreshToken, refreshTokenHash string) bool {
	return HashRefreshToken(refreshToken) == refreshTokenHash
}

func HashRefreshToken(refreshToken string) string {
	hash := sha256.Sum256([]byte(refreshToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func generateJTI() (string, error) {
	if jti, err := uuid.NewV7(); err != nil {
		return "", fmt.Errorf("error generating JTI: %w", err)
	} else {
		return jti.String(), nil
	}
}

func GetCurrentKeyID() string {
	hash := sha256.Sum256(PublicKey)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
