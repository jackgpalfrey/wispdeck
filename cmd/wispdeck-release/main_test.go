package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wispdeck/wispdeck/internal/updater"
)

func TestKeygenAndManifest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	privatePath := filepath.Join(root, "private.key")
	publicPath := filepath.Join(root, "public.key")
	var output bytes.Buffer
	if err := run([]string{"keygen", "--private", privatePath, "--public", publicPath}, &output); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v", privateInfo.Mode())
	}
	publicBody, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := updater.ParsePublicKey(string(publicBody))
	if err != nil {
		t.Fatal(err)
	}
	privateBody, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	decodedPrivate, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(privateBody)))
	if err != nil || !bytes.Equal(ed25519.PrivateKey(decodedPrivate).Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("generated key pair does not match")
	}

	notesPath := filepath.Join(root, "notes.md")
	assetPath := filepath.Join(root, "wispdeck-linux-amd64")
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(notesPath, []byte("A stable release."), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetPath, []byte("release binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{
		"manifest", "--private-key", privatePath, "--version", "v1.2.3",
		"--published-at", "2026-07-22T12:00:00Z", "--notes", notesPath,
		"--asset", "linux/amd64," + assetPath + ",https://updates.example/wispdeck-linux-amd64",
		"--output", manifestPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := updater.VerifyEnvelope(manifestBody, publicKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Release.Version != "v1.2.3" || len(manifest.Release.Assets) != 1 ||
		manifest.Release.Notes != "A stable release." {
		t.Fatalf("manifest = %+v", manifest)
	}
	output.Reset()
	if err := run([]string{
		"verify", "--public-key", publicPath, "--manifest", manifestPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Verified signed manifest") {
		t.Fatalf("verify output = %q", output.String())
	}

	otherPrivatePath := filepath.Join(root, "other-private.key")
	otherPublicPath := filepath.Join(root, "other-public.key")
	if err := run([]string{
		"keygen", "--private", otherPrivatePath, "--public", otherPublicPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"verify", "--public-key", otherPublicPath, "--manifest", manifestPath,
	}, &output); err == nil {
		t.Fatal("verified manifest with an unrelated public key")
	}
	if err := run([]string{
		"manifest", "--private-key", privatePath, "--version", "v1.2.3-rc1",
		"--notes", notesPath,
		"--asset", "linux/amd64," + assetPath + ",https://updates.example/wispdeck",
		"--output", filepath.Join(root, "prerelease.json"),
	}, &output); err == nil {
		t.Fatal("created a prerelease update manifest")
	}
}
