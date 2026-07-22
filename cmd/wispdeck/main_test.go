package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/buildinfo"
)

func TestVersionOutput(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run([]string{"version"}, strings.NewReader(""), &output, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "wispdeck "+buildinfo.Current().Version+" (") {
		t.Fatalf("version output = %q", output.String())
	}

	output.Reset()
	if err := run([]string{"version", "--json"}, strings.NewReader(""), &output, logger); err != nil {
		t.Fatal(err)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info != buildinfo.Current() {
		t.Fatalf("JSON version = %+v, want %+v", info, buildinfo.Current())
	}
}

func TestBackupCLIRequiresExplicitConfirmation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{
		{"backup", "create"},
		{"backup", "restore", "--input", "backup.tar.gz"},
	} {
		if err := run(args, strings.NewReader(""), io.Discard, logger); err == nil {
			t.Fatalf("run(%q) accepted incomplete backup command", args)
		}
	}
}

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
	if !strings.Contains(output.String(), `Created superuser "alice"`) {
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

func TestUnconfiguredUpdateClientIsNil(t *testing.T) {
	t.Parallel()
	client, err := configuredUpdateClient("", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if client != nil {
		t.Fatalf("configuredUpdateClient() = %#v, want nil", client)
	}
}

func TestServeRejectsInvalidResourceLimitsBeforeOpeningState(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, test := range []struct {
		flag string
		want string
	}{
		{"--max-links-per-user=0", "max-links-per-user"},
		{"--max-sites-per-user=0", "max-sites-per-user"},
		{"--max-releases-per-site=1", "max-releases-per-site"},
		{"--max-site-storage-mib-per-user=49", "max-site-storage-mib-per-user"},
		{"--auth-event-retention-days=0", "auth-event-retention-days"},
		{"--max-auth-events=0", "max-auth-events"},
		{"--retained-update-backups=0", "retained-update-backups"},
		{"--retained-update-downloads=101", "retained-update-downloads"},
	} {
		t.Run(test.want, func(t *testing.T) {
			err := serve([]string{
				"--development", "--app-origin=http://localhost:8080", test.flag,
			}, logger)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("serve error = %v", err)
			}
		})
	}
}
