package main

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func TestCreateAdminFromExplicitStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "wispdeck.db")
	keyPath := filepath.Join(t.TempDir(), "secrets", "auth.key")
	if err := auth.GenerateInstallationKey(keyPath); err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader("saffron-planetary-cello-woodland\nsaffron-planetary-cello-woodland\n")
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run([]string{
		"admin", "create", "--database", path, "--auth-key", keyPath, "--username", "Alice",
		"--password-stdin", "--skip-compromised-password-check",
	}, input, &output, logger)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `Created administrator "alice"`) {
		t.Fatalf("output = %q", output.String())
	}
}

func TestGenerateAuthKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "auth.key")
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run([]string{"auth-key", "generate", "--path", path}, strings.NewReader(""), &output, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Back it up securely") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestPasswordStdinRejectsUnexpectedInput(t *testing.T) {
	_, _, err := readPasswords(strings.NewReader("one\ntwo\nthree\n"), io.Discard, true)
	if err == nil {
		t.Fatal("accepted an unexpected third line")
	}
}

func TestLoopbackAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if !loopbackAddress(address) {
			t.Errorf("loopbackAddress(%q) = false", address)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", ":8080", "192.0.2.1:8080", "invalid"} {
		if loopbackAddress(address) {
			t.Errorf("loopbackAddress(%q) = true", address)
		}
	}
}
