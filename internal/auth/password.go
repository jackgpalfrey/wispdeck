// Package auth implements Wispdeck's authentication primitives.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	MinPasswordRunes = 15
	MaxPasswordRunes = 256
	maxPasswordBytes = MaxPasswordRunes * utf8.UTFMax
)

var (
	ErrInvalidHash      = errors.New("invalid password hash")
	ErrPasswordInvalid  = errors.New("password must be valid UTF-8")
	ErrPasswordTooShort = fmt.Errorf("password must contain at least %d characters", MinPasswordRunes)
	ErrPasswordTooLong  = fmt.Errorf("password must contain at most %d characters", MaxPasswordRunes)
)

// PasswordParams are the resource costs used to create an Argon2id hash.
// Memory is expressed in KiB.
type PasswordParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var defaultPasswordParams = PasswordParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// ValidatePassword applies Wispdeck's password-size policy. It deliberately
// does not trim, normalize, or impose character-composition rules.
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrPasswordInvalid
	}
	password = normalizePassword(password)
	if len(password) > maxPasswordBytes {
		return ErrPasswordTooLong
	}
	n := utf8.RuneCountInString(password)
	if n < MinPasswordRunes {
		return ErrPasswordTooShort
	}
	if n > MaxPasswordRunes {
		return ErrPasswordTooLong
	}
	return nil
}

// HashPassword returns a PHC-style Argon2id encoding.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	password = normalizePassword(password)
	p := defaultPasswordParams
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return encodeHash(p, salt, key), nil
}

// VerifyPassword compares password with an encoded Argon2id hash. It returns
// false for a mismatch and an error only when the stored encoding is invalid.
func VerifyPassword(password, encoded string) (bool, error) {
	p, salt, expected, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	password = normalizePassword(password)
	if len(password) > maxPasswordBytes {
		return false, nil
	}
	actual := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func normalizePassword(password string) string {
	return norm.NFC.String(password)
}

// PasswordHashNeedsUpgrade reports whether encoded uses different resource
// parameters from newly-created hashes.
func PasswordHashNeedsUpgrade(encoded string) bool {
	p, _, _, err := decodeHash(encoded)
	return err != nil || p != defaultPasswordParams
}

func encodeHash(p PasswordParams, salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Iterations,
		p.Parallelism,
		b64.EncodeToString(salt),
		b64.EncodeToString(key),
	)
}

func decodeHash(encoded string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	version, err := parsePrefixedUint(parts[2], "v=", 8)
	if err != nil || version != argon2.Version {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}

	var p PasswordParams
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	memory, errM := parsePrefixedUint(fields[0], "m=", 32)
	iterations, errT := parsePrefixedUint(fields[1], "t=", 32)
	parallelism, errP := parsePrefixedUint(fields[2], "p=", 8)
	if errM != nil || errT != nil || errP != nil ||
		memory < 8*1024 || memory > 256*1024 ||
		iterations < 1 || iterations > 10 ||
		parallelism < 1 || parallelism > 16 {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	p.Memory = uint32(memory)
	p.Iterations = uint32(iterations)
	p.Parallelism = uint8(parallelism)

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 32 || len(key) > 64 {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	// #nosec G115 -- the decoded lengths are constrained to 16-64 and 32-64 bytes above.
	p.SaltLength = uint32(len(salt))
	// #nosec G115 -- the decoded lengths are constrained to 16-64 and 32-64 bytes above.
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}

func parsePrefixedUint(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, ErrInvalidHash
	}
	return strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
}
