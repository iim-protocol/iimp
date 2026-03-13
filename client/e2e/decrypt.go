package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DecryptMessage decrypts a message using the recipient's private key
func DecryptMessage(
	encryptedContent string, // base64url encoded
	nonce string, // base64url encoded
	encryptionData []RecipientEncryptionData,
	recipientId string,
	privateKey []byte, // X25519 private key bytes
) (string, error) {
	symmetricKey, err := recoverSymmetricKey(encryptionData, recipientId, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to recover symmetric key: %w", err)
	}
	// decode + decrypt message content
	encryptedContentBytes, err := base64.RawURLEncoding.DecodeString(encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted content: %w", err)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}
	plaintext, err := aesGCMDecrypt(encryptedContentBytes, symmetricKey, nonceBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message content: %w", err)
	}

	return string(plaintext), nil
}

// DecryptAttachment decrypts an attachment using the message's symmetric key
func DecryptAttachment(
	encryptedBytes []byte,
	nonce string, // base64url encoded
	encryptionData []RecipientEncryptionData,
	recipientId string,
	privateKey []byte, // X25519 private key bytes
) ([]byte, error) {
	// first recover the symmetric key
	symmetricKey, err := recoverSymmetricKey(encryptionData, recipientId, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to recover symmetric key: %w", err)
	}

	// decode nonce
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// decrypt attachment
	plaintext, err := aesGCMDecrypt(encryptedBytes, symmetricKey, nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attachment: %w", err)
	}

	return plaintext, nil
}

// recoverSymmetricKey recovers the symmetric key from the encryption data
func recoverSymmetricKey(
	encryptionData []RecipientEncryptionData,
	recipientId string,
	privateKey []byte, // X25519 private key bytes
) ([]byte, error) {
	var ourED *RecipientEncryptionData
	for _, ed := range encryptionData {
		if ed.RecipientId == recipientId {
			ourED = &ed
			break
		}
	}
	if ourED == nil {
		return nil, fmt.Errorf("no encryption data found for recipient '%s'", recipientId)
	}

	// decode ephemeral public key
	ephemeralPublicKey, err := base64.RawURLEncoding.DecodeString(ourED.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	// DH(own_private, ephemeral_public) → shared secret
	sharedSecret, err := curve25519.X25519(privateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// derive own public key from private key for HKDF info
	ownPublicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive own public key: %w", err)
	}

	// HKDF(shared_secret) → encryption key
	encryptionKey, err := deriveEncryptionKey(sharedSecret, ephemeralPublicKey, ownPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// decode + decrypt symmetric key
	encryptedKeyBytes, err := base64.RawURLEncoding.DecodeString(ourED.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}
	keyNonce, err := base64.RawURLEncoding.DecodeString(ourED.EncryptedKeyNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key nonce: %w", err)
	}
	return aesGCMDecrypt(encryptedKeyBytes, encryptionKey, keyNonce)
}

// aesGCMDecrypt decrypts ciphertext with AES-GCM using the given key and nonce
func aesGCMDecrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
