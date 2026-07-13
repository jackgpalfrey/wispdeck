package shortlink

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   error
	}{
		{input: " Launch-Notes ", want: "launch-notes"},
		{input: "x", want: "x"},
		{input: "", err: ErrInvalidSlug},
		{input: "-leading", err: ErrInvalidSlug},
		{input: "trailing-", err: ErrInvalidSlug},
		{input: "not_ok", err: ErrInvalidSlug},
		{input: "login", err: ErrReservedSlug},
		{input: "SECURITY", err: ErrReservedSlug},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeSlug(test.input)
			if !errors.Is(err, test.err) {
				t.Fatalf("NormalizeSlug(%q) error = %v, want %v", test.input, err, test.err)
			}
			if got != test.want {
				t.Fatalf("NormalizeSlug(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"https://example.com",
		"http://127.0.0.1:8080/path?query=value#fragment",
		"https://[::1]/private",
		"https://example.com/%0d%0aencoded-is-data",
	}
	for _, value := range valid {
		if got, err := ValidateTarget(value); err != nil || got != value {
			t.Errorf("ValidateTarget(%q) = (%q, %v)", value, got, err)
		}
	}

	invalid := []string{
		"",
		"/relative",
		"javascript:alert(1)",
		"ftp://example.com/file",
		"https://user:password@example.com",
		"https://",
		"https://example.com/path with spaces",
		"https://example.com\r\nX-Test: injected",
	}
	for _, value := range invalid {
		if _, err := ValidateTarget(value); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ValidateTarget(%q) error = %v", value, err)
		}
	}

	if _, err := ValidateTarget("https://example.com/" + strings.Repeat("a", MaxTargetLength)); !errors.Is(err, ErrTargetTooLong) {
		t.Fatalf("oversized target error = %v", err)
	}
}

func TestRandomSlugUsesValidAlphabet(t *testing.T) {
	for range 100 {
		slug, err := randomSlug()
		if err != nil {
			t.Fatal(err)
		}
		if len(slug) != automaticLength {
			t.Fatalf("random slug length = %d", len(slug))
		}
		if normalized, err := NormalizeSlug(slug); err != nil || normalized != slug {
			t.Fatalf("random slug = %q, normalize error = %v", slug, err)
		}
	}
}
