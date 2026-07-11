package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStaticPasswordChecker(t *testing.T) {
	checker := NewStaticPasswordChecker()
	for _, password := range []string{
		"correct horse battery staple",
		"WISPDECKPASSWORD",
		"alice2026",
	} {
		err := checker.Check(context.Background(), password, PasswordContext{
			Username: "alice", Service: "wispdeck", Domain: "admin.example.test",
		})
		if !errors.Is(err, ErrCompromisedPassword) {
			t.Errorf("Check(%q) error = %v", password, err)
		}
	}
	if err := checker.Check(context.Background(), "saffron-planetary-cello-woodland", PasswordContext{
		Username: "alice", Service: "wispdeck", Domain: "admin.example.test",
	}); err != nil {
		t.Fatalf("unlisted password rejected: %v", err)
	}
}

func TestPwnedPasswordCheckerUsesPaddedRangeRequest(t *testing.T) {
	password := "a known compromised passphrase"
	digest := sha1.Sum([]byte(password)) // #nosec G401 -- test fixture for the HIBP protocol.
	hexDigest := strings.ToUpper(hex.EncodeToString(digest[:]))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/range/"+hexDigest[:5] {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Add-Padding") != "true" {
			t.Errorf("Add-Padding = %q", r.Header.Get("Add-Padding"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("00000000000000000000000000000000000:0\n" + hexDigest[5:] + ":42\n")),
			Header:     make(http.Header),
		}, nil
	})}
	checker := NewPwnedPasswordChecker(client)
	if err := checker.Check(context.Background(), password, PasswordContext{}); !errors.Is(err, ErrCompromisedPassword) {
		t.Fatalf("Check error = %v", err)
	}
}

func TestPwnedPasswordCheckerFailsClosed(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	checker := NewPwnedPasswordChecker(client)
	if err := checker.Check(context.Background(), "saffron-planetary-cello-woodland", PasswordContext{}); !errors.Is(err, ErrPasswordCheckFailed) {
		t.Fatalf("Check error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
