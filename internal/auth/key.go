package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const installationKeyBytes = 32

var ErrInvalidInstallationKey = errors.New("invalid installation authentication key")

type KeyMaterial struct {
	credential cipher.AEAD
	ceremony   cipher.AEAD
	recovery   [32]byte
	handle     [32]byte
	password   [32]byte
}

func NewKeyMaterial(raw []byte) (*KeyMaterial, error) {
	if len(raw) != installationKeyBytes {
		return nil, ErrInvalidInstallationKey
	}
	credentialKey, err := hkdf.Key(sha256.New, raw, nil, "wispdeck credential encryption v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive credential key: %w", err)
	}
	ceremonyKey, err := hkdf.Key(sha256.New, raw, nil, "wispdeck ceremony encryption v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive ceremony key: %w", err)
	}
	recoveryKey, err := hkdf.Key(sha256.New, raw, nil, "wispdeck recovery digest v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive recovery key: %w", err)
	}
	handleKey, err := hkdf.Key(sha256.New, raw, nil, "wispdeck webauthn handle v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive user-handle key: %w", err)
	}
	passwordKey, err := hkdf.Key(sha256.New, raw, nil, "wispdeck password pepper v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive password pepper: %w", err)
	}
	credential, err := newAEAD(credentialKey)
	if err != nil {
		return nil, err
	}
	ceremony, err := newAEAD(ceremonyKey)
	if err != nil {
		return nil, err
	}
	key := &KeyMaterial{credential: credential, ceremony: ceremony}
	copy(key.recovery[:], recoveryKey)
	copy(key.handle[:], handleKey)
	copy(key.password[:], passwordKey)
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}

func GenerateInstallationKey(path string) error {
	if path == "" {
		return errors.New("installation key path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create installation key directory: %w", err)
	}
	raw := make([]byte, installationKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generate installation key: %w", err)
	}
	// #nosec G304 -- path is an explicit local operator CLI/config value, never remote input.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create installation key: %w", err)
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	encoded := base64.RawURLEncoding.EncodeToString(raw) + "\n"
	if _, err := io.WriteString(file, encoded); err != nil {
		return fmt.Errorf("write installation key: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync installation key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close installation key: %w", err)
	}
	succeeded = true
	return nil
}

func LoadInstallationKey(path string) (*KeyMaterial, error) {
	// #nosec G304 -- path is an explicit local operator CLI/config value, never remote input.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open installation key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect installation key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: key file must be regular and inaccessible to group and other users", ErrInvalidInstallationKey)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 256))
	if err != nil {
		return nil, fmt.Errorf("read installation key: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed encoding", ErrInvalidInstallationKey)
	}
	return NewKeyMaterial(raw)
}

func (k *KeyMaterial) EncryptCredential(plaintext []byte, userID, rpID string) ([]byte, error) {
	return seal(k.credential, plaintext, []byte("credential\x00"+rpID+"\x00"+userID))
}

func (k *KeyMaterial) DecryptCredential(ciphertext []byte, userID, rpID string) ([]byte, error) {
	return open(k.credential, ciphertext, []byte("credential\x00"+rpID+"\x00"+userID))
}

func (k *KeyMaterial) EncryptCeremony(plaintext []byte, userID, kind string) ([]byte, error) {
	return seal(k.ceremony, plaintext, []byte("ceremony\x00"+kind+"\x00"+userID))
}

func (k *KeyMaterial) DecryptCeremony(ciphertext []byte, userID, kind string) ([]byte, error) {
	return open(k.ceremony, ciphertext, []byte("ceremony\x00"+kind+"\x00"+userID))
}

func seal(aead cipher.AEAD, plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	result := make([]byte, 1, 1+len(nonce)+len(plaintext)+aead.Overhead())
	result[0] = 1
	result = append(result, nonce...)
	result = aead.Seal(result, nonce, plaintext, additionalData)
	return result, nil
}

func open(aead cipher.AEAD, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < 1+aead.NonceSize()+aead.Overhead() || ciphertext[0] != 1 {
		return nil, errors.New("invalid encrypted record")
	}
	nonce := ciphertext[1 : 1+aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext[1+aead.NonceSize():], additionalData)
	if err != nil {
		return nil, errors.New("authenticate encrypted record")
	}
	return plaintext, nil
}

func (k *KeyMaterial) WebAuthnUserHandle(userID, rpID string) []byte {
	mac := hmac.New(sha256.New, k.handle[:])
	_, _ = io.WriteString(mac, "webauthn-handle\x00"+rpID+"\x00"+userID)
	return mac.Sum(nil)
}

func (k *KeyMaterial) RecoveryCodeDigest(userID, code string) [32]byte {
	mac := hmac.New(sha256.New, k.recovery[:])
	_, _ = io.WriteString(mac, "recovery-code\x00"+userID+"\x00"+NormalizeRecoveryCode(code))
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func GenerateRecoveryCodes(count int) ([]string, error) {
	if count < 1 || count > 100 {
		return nil, errors.New("recovery code count must be between 1 and 100")
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, count)
	for i := range codes {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		plain := encoding.EncodeToString(raw)
		codes[i] = groupRecoveryCode(plain)
	}
	return codes, nil
}

func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}

func groupRecoveryCode(code string) string {
	var builder strings.Builder
	for i, r := range code {
		if i > 0 && i%5 == 0 {
			builder.WriteByte('-')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
