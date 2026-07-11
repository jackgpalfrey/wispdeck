package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationKeyFileAndCryptographicSeparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "auth.key")
	if err := GenerateInstallationKey(path); err != nil {
		t.Fatal(err)
	}
	if err := GenerateInstallationKey(path); err == nil {
		t.Fatal("installation key was overwritten")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %#o", info.Mode().Perm())
	}
	key, err := LoadInstallationKey(path)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"credential":"record"}`)
	ciphertext, err := key.EncryptCredential(plaintext, "user-1", "admin.example.test")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := key.DecryptCredential(ciphertext, "user-1", "admin.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q", decrypted)
	}
	if _, err := key.DecryptCredential(ciphertext, "user-2", "admin.example.test"); err == nil {
		t.Fatal("credential decrypted under a different user")
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := key.DecryptCredential(ciphertext, "user-1", "admin.example.test"); err == nil {
		t.Fatal("tampered credential decrypted")
	}

	totpSecret := bytes.Repeat([]byte{0x24}, 20)
	totpCiphertext, err := key.EncryptTOTPSecret(totpSecret, "user-1", totpEnrollmentPurpose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.DecryptTOTPSecret(totpCiphertext, "user-1", totpCredentialPurpose); err == nil {
		t.Fatal("TOTP enrollment secret decrypted as a credential")
	}
	if _, err := key.DecryptTOTPSecret(totpCiphertext, "user-2", totpEnrollmentPurpose); err == nil {
		t.Fatal("TOTP secret decrypted for a different user")
	}
	decryptedTOTP, err := key.DecryptTOTPSecret(totpCiphertext, "user-1", totpEnrollmentPurpose)
	if err != nil || !bytes.Equal(decryptedTOTP, totpSecret) {
		t.Fatalf("TOTP round trip = (%x, %v)", decryptedTOTP, err)
	}
}

func TestInstallationKeyRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.key")
	if err := GenerateInstallationKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInstallationKey(path); !errors.Is(err, ErrInvalidInstallationKey) {
		t.Fatalf("LoadInstallationKey error = %v", err)
	}
}

func TestRecoveryCodesAreUniqueAndKeyed(t *testing.T) {
	key, err := NewKeyMaterial(bytes.Repeat([]byte{0x42}, installationKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{})
	for _, code := range codes {
		normalized := NormalizeRecoveryCode(code)
		if len(normalized) != 26 {
			t.Fatalf("normalized recovery code length = %d", len(normalized))
		}
		if _, found := seen[normalized]; found {
			t.Fatalf("duplicate recovery code %q", code)
		}
		seen[normalized] = struct{}{}
		if key.RecoveryCodeDigest("user-1", code) != key.RecoveryCodeDigest("user-1", normalized) {
			t.Fatal("formatted and normalized recovery code digests differ")
		}
		if key.RecoveryCodeDigest("user-1", code) == key.RecoveryCodeDigest("user-2", code) {
			t.Fatal("recovery digest is not scoped to a user")
		}
	}
	first := key.WebAuthnUserHandle("user-1", "admin.example.test")
	second := key.WebAuthnUserHandle("user-1", "admin.example.test")
	if !bytes.Equal(first, second) || len(first) != 32 {
		t.Fatal("WebAuthn handle is not stable")
	}
}
