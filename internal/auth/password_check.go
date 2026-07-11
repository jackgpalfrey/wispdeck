package auth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the HIBP range API; never used for password storage.
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrCompromisedPassword = errors.New("password appears in a common or compromised-password list")
	ErrPasswordCheckFailed = errors.New("could not check the compromised-password service")
)

//go:embed common_passwords.txt
var commonPasswordData string

type PasswordChecker interface {
	Check(context.Context, string, PasswordContext) error
}

type PasswordContext struct {
	Username string
	Service  string
	Domain   string
}

type StaticPasswordChecker struct {
	blocked map[string]struct{}
}

func NewStaticPasswordChecker() *StaticPasswordChecker {
	checker := &StaticPasswordChecker{blocked: make(map[string]struct{})}
	scanner := bufio.NewScanner(strings.NewReader(commonPasswordData))
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value != "" && !strings.HasPrefix(value, "#") {
			checker.blocked[passwordComparisonKey(value)] = struct{}{}
		}
	}
	return checker
}

func (c *StaticPasswordChecker) Check(_ context.Context, password string, context PasswordContext) error {
	key := passwordComparisonKey(password)
	if _, found := c.blocked[key]; found {
		return ErrCompromisedPassword
	}
	for _, value := range contextualPasswords(context) {
		if subtle.ConstantTimeCompare([]byte(key), []byte(passwordComparisonKey(value))) == 1 {
			return ErrCompromisedPassword
		}
	}
	return nil
}

func contextualPasswords(context PasswordContext) []string {
	base := []string{context.Username, context.Service, context.Domain}
	values := make([]string, 0, len(base)*6)
	for _, value := range base {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		values = append(values,
			value,
			value+"1",
			value+"123",
			value+"2026",
			value+"password",
			"password"+value,
		)
	}
	return values
}

func passwordComparisonKey(password string) string {
	return strings.ToLower(normalizePassword(password))
}

type PwnedPasswordChecker struct {
	client  *http.Client
	baseURL string
}

func NewPwnedPasswordChecker(client *http.Client) *PwnedPasswordChecker {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &PwnedPasswordChecker{
		client:  client,
		baseURL: "https://api.pwnedpasswords.com/range/",
	}
}

func (c *PwnedPasswordChecker) Check(ctx context.Context, password string, _ PasswordContext) error {
	// HIBP defines this API in terms of an uppercase SHA-1 hash. Only the first
	// five hexadecimal characters leave the process.
	digest := sha1.Sum([]byte(normalizePassword(password))) // #nosec G401 -- protocol-mandated lookup digest.
	hexDigest := strings.ToUpper(hex.EncodeToString(digest[:]))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+hexDigest[:5], nil)
	if err != nil {
		return fmt.Errorf("%w: create request: %v", ErrPasswordCheckFailed, err)
	}
	request.Header.Set("Add-Padding", "true")
	request.Header.Set("User-Agent", "Wispdeck password screening")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPasswordCheckFailed, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return fmt.Errorf("%w: unexpected HTTP status %d", ErrPasswordCheckFailed, response.StatusCode)
	}
	const maximumResponseBytes = 2 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrPasswordCheckFailed, err)
	}
	if len(body) > maximumResponseBytes {
		return fmt.Errorf("%w: response exceeds size limit", ErrPasswordCheckFailed)
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	suffix := hexDigest[5:]
	for scanner.Scan() {
		candidate, _, found := strings.Cut(scanner.Text(), ":")
		if found && len(candidate) == len(suffix) && subtle.ConstantTimeCompare([]byte(strings.ToUpper(candidate)), []byte(suffix)) == 1 {
			return ErrCompromisedPassword
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%w: parse response: %v", ErrPasswordCheckFailed, err)
	}
	return nil
}

type CombinedPasswordChecker struct {
	checkers []PasswordChecker
}

func NewCombinedPasswordChecker(checkers ...PasswordChecker) *CombinedPasswordChecker {
	return &CombinedPasswordChecker{checkers: checkers}
}

func (c *CombinedPasswordChecker) Check(ctx context.Context, password string, passwordContext PasswordContext) error {
	for _, checker := range c.checkers {
		if err := checker.Check(ctx, password, passwordContext); err != nil {
			return err
		}
	}
	return nil
}
