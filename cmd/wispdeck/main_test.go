package main

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAdminFromExplicitStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "wispdeck.db")
	input := strings.NewReader("correct horse battery staple\ncorrect horse battery staple\n")
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run([]string{"admin", "create", "--database", path, "--username", "Alice", "--password-stdin"}, input, &output, logger)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `Created administrator "alice"`) {
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
