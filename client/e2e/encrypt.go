package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// EncryptedMessage is the result of encrypting a message
type EncryptedMessage struct {
	EncryptedContent string // base64url encoded
	Nonce            string // base64url encoded
	EncryptionData   []RecipientEncryptionData

	// needed for attachment encryption!
	//
	// DO NOT EXPOSE THIS KEY!
	SymmetricKey []byte
}

// RecipientEncryptionData is the per-recipient encryption data
type RecipientEncryptionData struct {
	RecipientId        string
	KeyId              string
	EphemeralPublicKey string // base64url encoded
	EncryptedKey       string // base64url encoded
	EncryptedKeyNonce  string // base64url encoded
}

// EncryptedAttachment is the result of encrypting an attachment
type EncryptedAttachment struct {
	EncryptedBytes []byte
	Nonce          string // base64url encoded
}

// EncryptMessage encrypts a message for a list of recipients
// recipientPublicKeys is a map of recipientId -> base64url encoded public key + keyId
func EncryptMessage(plaintext string, recipients []RecipientPublicKey) (*EncryptedMessage, error) {
	// generate random 32-byte symmetric key
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// encrypt message content with symmetric key
	encryptedContent, nonce, err := aesGCMEncrypt([]byte(plaintext), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message content: %w", err)
	}

	// encrypt symmetric key for each recipient
	encryptionData := make([]RecipientEncryptionData, len(recipients))
	for i, recipient := range recipients {
		ed, err := encryptKeyForRecipient(symmetricKey, recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key for recipient '%s': %w", recipient.RecipientId, err)
		}
		encryptionData[i] = *ed
	}

	return &EncryptedMessage{
		EncryptedContent: base64.RawURLEncoding.EncodeToString(encryptedContent),
		Nonce:            base64.RawURLEncoding.EncodeToString(nonce),
		EncryptionData:   encryptionData,
		SymmetricKey:     symmetricKey,
	}, nil
}

// EncryptAttachment encrypts an attachment using the same symmetric key as the message
func EncryptAttachment(plaintext []byte, symmetricKey []byte) (*EncryptedAttachment, error) {
	encryptedBytes, nonce, err := aesGCMEncrypt(plaintext, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt attachment: %w", err)
	}
	return &EncryptedAttachment{
		EncryptedBytes: encryptedBytes,
		Nonce:          base64.RawURLEncoding.EncodeToString(nonce),
	}, nil
}

// RecipientPublicKey is a recipient's public key info
type RecipientPublicKey struct {
	RecipientId     string
	KeyId           string
	PublicKeyBase64 string // base64url encoded X25519 public key
}

// encryptKeyForRecipient encrypts the symmetric key for a single recipient
func encryptKeyForRecipient(symmetricKey []byte, recipient RecipientPublicKey) (*RecipientEncryptionData, error) {
	// decode recipient's public key
	recipientPublicKey, err := base64.RawURLEncoding.DecodeString(recipient.PublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient public key: %w", err)
	}

	// generate ephemeral X25519 keypair
	ephemeralPrivateKey := make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(ephemeralPrivateKey); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}

	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ephemeral public key: %w", err)
	}

	// DH(ephemeral_private, recipient_public) → shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivateKey, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// HKDF(shared_secret) → encryption key
	encryptionKey, err := deriveEncryptionKey(sharedSecret, ephemeralPublicKey, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// AES-GCM encrypt symmetric key with encryption key
	encryptedKey, keyNonce, err := aesGCMEncrypt(symmetricKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	return &RecipientEncryptionData{
		RecipientId:        recipient.RecipientId,
		KeyId:              recipient.KeyId,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephemeralPublicKey),
		EncryptedKey:       base64.RawURLEncoding.EncodeToString(encryptedKey),
		EncryptedKeyNonce:  base64.RawURLEncoding.EncodeToString(keyNonce),
	}, nil
}

// deriveEncryptionKey derives a 32-byte encryption key from the shared secret using HKDF
func deriveEncryptionKey(sharedSecret, ephemeralPublicKey, recipientPublicKey []byte) ([]byte, error) {
	// use ephemeral public key + recipient public key as HKDF info
	info := append(ephemeralPublicKey, recipientPublicKey...)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encryptionKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	return encryptionKey, nil
}

// aesGCMEncrypt encrypts plaintext with AES-GCM using the given key
// returns ciphertext and nonce
func aesGCMEncrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}
