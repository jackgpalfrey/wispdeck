package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const InitialSetupCodeLength = 6

// The alphabet deliberately omits 0, 1, I, and O so codes remain easy to copy
// from a terminal. Its 32 symbols give a six-character code 30 bits of entropy.
const initialSetupAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func NewInitialSetupCode() (string, error) {
	random := make([]byte, InitialSetupCodeLength)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate initial setup code: %w", err)
	}
	code := make([]byte, InitialSetupCodeLength)
	for i, value := range random {
		code[i] = initialSetupAlphabet[int(value)&(len(initialSetupAlphabet)-1)]
	}
	return string(code), nil
}

func NormalizeInitialSetupCode(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func ValidInitialSetupCode(value string) bool {
	value = NormalizeInitialSetupCode(value)
	if len(value) != InitialSetupCodeLength {
		return false
	}
	for _, char := range []byte(value) {
		if !strings.ContainsRune(initialSetupAlphabet, rune(char)) {
			return false
		}
	}
	return true
}
