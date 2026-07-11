package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const pepperedHashPrefix = "$argon2id-hmac-sha256$"

type PasswordManager struct {
	pepper [32]byte
}

func NewPasswordManager(keys *KeyMaterial) (*PasswordManager, error) {
	if keys == nil {
		return nil, errors.New("key material is required for password management")
	}
	manager := &PasswordManager{}
	copy(manager.pepper[:], keys.password[:])
	return manager, nil
}

func (m *PasswordManager) Hash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	p := defaultPasswordParams
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(m.pepperedInput(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	encoded := encodeHash(p, salt, key)
	return strings.Replace(encoded, "$argon2id$", pepperedHashPrefix, 1), nil
}

func (m *PasswordManager) Verify(password, encoded string) (bool, error) {
	if !strings.HasPrefix(encoded, pepperedHashPrefix) {
		return VerifyPassword(password, encoded)
	}
	argonEncoding := strings.Replace(encoded, pepperedHashPrefix, "$argon2id$", 1)
	p, salt, expected, err := decodeHash(argonEncoding)
	if err != nil {
		return false, err
	}
	password = normalizePassword(password)
	if len(password) > maxPasswordBytes {
		return false, nil
	}
	actual := argon2.IDKey(m.pepperedInput(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func (m *PasswordManager) NeedsUpgrade(encoded string) bool {
	if !strings.HasPrefix(encoded, pepperedHashPrefix) {
		return true
	}
	argonEncoding := strings.Replace(encoded, pepperedHashPrefix, "$argon2id$", 1)
	return PasswordHashNeedsUpgrade(argonEncoding)
}

func (m *PasswordManager) pepperedInput(password string) []byte {
	mac := hmac.New(sha256.New, m.pepper[:])
	_, _ = mac.Write([]byte(normalizePassword(password)))
	return mac.Sum(nil)
}
