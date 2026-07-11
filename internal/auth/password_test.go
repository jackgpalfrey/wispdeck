package auth

import (
	"errors"
	"strings"
	"testing"
)

func useFastPasswordParams(t *testing.T) {
	t.Helper()
	original := defaultPasswordParams
	defaultPasswordParams = PasswordParams{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}
	t.Cleanup(func() { defaultPasswordParams = original })
}

func TestPasswordRoundTrip(t *testing.T) {
	useFastPasswordParams(t)
	password := "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("password did not match its hash")
	}
	matched, err = VerifyPassword("incorrect password phrase", hash)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("incorrect password matched")
	}
	if PasswordHashNeedsUpgrade(hash) {
		t.Fatal("new hash unexpectedly needs an upgrade")
	}
}

func TestPasswordHashesUseUniqueSalts(t *testing.T) {
	useFastPasswordParams(t)
	first, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two hashes unexpectedly used the same salt")
	}
}

func TestPasswordPolicyCountsUnicodeCodePoints(t *testing.T) {
	if err := ValidatePassword(strings.Repeat("界", MinPasswordRunes)); err != nil {
		t.Fatalf("valid Unicode passphrase rejected: %v", err)
	}
	if err := ValidatePassword(strings.Repeat("界", MinPasswordRunes-1)); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short passphrase error = %v", err)
	}
	if err := ValidatePassword(strings.Repeat("x", MaxPasswordRunes+1)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("long passphrase error = %v", err)
	}
}

func TestPasswordHashNormalizesUnicodeNFC(t *testing.T) {
	useFastPasswordParams(t)
	composed := "caf\u00e9-caf\u00e9-caf\u00e9-caf\u00e9"
	decomposed := "cafe\u0301-cafe\u0301-cafe\u0301-cafe\u0301"
	hash, err := HashPassword(composed)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := VerifyPassword(decomposed, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("canonically equivalent password did not match")
	}
}

func TestVerifyRejectsUnsafeHashParameters(t *testing.T) {
	tests := []string{
		"not-a-hash",
		"$argon2id$v=19$m=1048576,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY",
		"$argon2id$v=19$m=8192,t=99,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY",
	}
	for _, encoded := range tests {
		if _, err := VerifyPassword("irrelevant password", encoded); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("VerifyPassword(%q) error = %v", encoded, err)
		}
	}
}
