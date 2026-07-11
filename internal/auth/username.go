package auth

import (
	"errors"
	"regexp"
	"strings"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return errors.New("username must be 1-64 lowercase letters, digits, dots, underscores, or hyphens and start with a letter or digit")
	}
	return nil
}
