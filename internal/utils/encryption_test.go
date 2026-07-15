package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt_Success(t *testing.T) {
	key := "12345678901234567890123456789012" // 32 bytes
	plaintext := "secret-oauth-client-secret-or-token"

	encrypted, err := Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := Decrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	key := "12345678901234567890123456789012"

	enc, err := Encrypt("", key)
	assert.NoError(t, err)
	assert.Equal(t, "", enc)

	dec, err := Decrypt("", key)
	assert.NoError(t, err)
	assert.Equal(t, "", dec)
}

func TestEncryptDecrypt_InvalidKeyLength(t *testing.T) {
	shortKey := "short-key"
	_, err := Encrypt("test", shortKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key must be exactly 32 bytes")

	_, err = Decrypt("QUJDRA==", shortKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key must be exactly 32 bytes")
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := "12345678901234567890123456789012"
	_, err := Decrypt("not-base64-!@#$", key)
	assert.Error(t, err)
}

func TestDecrypt_TooShortCiphertext(t *testing.T) {
	key := "12345678901234567890123456789012"
	// Encode something shorter than nonce (12 bytes for GCM)
	shortCipher := "AAAA" // 3 decoded bytes
	_, err := Decrypt(shortCipher, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := "12345678901234567890123456789012"
	plaintext := "original text"
	encrypted, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	// Tamper with encrypted text
	tampered := encrypted[:len(encrypted)-2] + "AA"
	_, err = Decrypt(tampered, key)
	assert.Error(t, err)
}
