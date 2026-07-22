package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/installation"
	"github.com/wispdeck/wispdeck/internal/store"
)

func TestDoctorAcceptsHardenedInstallation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic activation is Linux-only")
	}
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := installation.Paths{
		Database: filepath.Join(root, "wispdeck.db"), WispistData: filepath.Join(root, "wispist"),
		AuthKey: filepath.Join(root, "auth.key"),
	}
	if err := auth.GenerateInstallationKey(paths.AuthKey); err != nil {
		t.Fatal(err)
	}
	database, err := store.OpenSQLite(context.Background(), paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.WispistData, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "wispdeck")
	if err := os.WriteFile(executable, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report := inspectDoctor(context.Background(), doctorConfig{
		Build: buildinfo.Info{
			Version: "v1.0.0", Commit: "0123456789abcdef", BuiltAt: "2026-07-22T20:00:00Z",
		},
		AppOrigin: "https://wispdeck.example.com", SiteDomain: "sites.example.com",
		PreviewDomain: "preview.sites.example.com", TrustedProxies: []string{"127.0.0.1/32"},
		Paths: paths, UpdateData: filepath.Join(root, "updates"),
		UpdateManifestURL: "https://updates.example.com/stable.json",
		UpdatePublicKey:   base64.StdEncoding.EncodeToString(publicKey), Executable: executable,
	})
	if report.Failures != 0 || report.Warnings != 0 {
		t.Fatalf("doctor report = %+v", report)
	}
}

func TestDoctorRejectsDevelopmentBuildAndInsecureOrigin(t *testing.T) {
	t.Parallel()
	report := inspectDoctor(context.Background(), doctorConfig{
		Build:     buildinfo.Info{Version: "dev", Commit: "unknown", BuiltAt: "unknown"},
		AppOrigin: "http://example.com", TrustedProxies: []string{"not-a-cidr"},
		Paths: installation.Paths{
			Database:    filepath.Join(t.TempDir(), "missing.db"),
			WispistData: filepath.Join(t.TempDir(), "wispist"),
			AuthKey:     filepath.Join(t.TempDir(), "auth.key"),
		},
		UpdateData: filepath.Join(t.TempDir(), "updates"), Executable: filepath.Join(t.TempDir(), "missing"),
	})
	if report.Failures < 5 {
		t.Fatalf("doctor failures = %d, report = %+v", report.Failures, report)
	}
}

func TestDoctorReportJSON(t *testing.T) {
	t.Parallel()
	report := doctorReport{Checks: []doctorCheck{{Name: "release build", Status: doctorPass, Detail: "v1.0.0"}}}
	var output bytes.Buffer
	if err := writeDoctorReport(&output, report, true); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\"checks\":[{\"name\":\"release build\",\"status\":\"pass\",\"detail\":\"v1.0.0\"}],\"failures\":0,\"warnings\":0}\n" {
		t.Fatalf("doctor JSON = %q", output.String())
	}
}

func TestInspectWispistDataRejectsOrphanedJournalFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "site.db-wal"), []byte("orphaned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectWispistData(context.Background(), directory); err == nil {
		t.Fatal("inspectWispistData() accepted an orphaned WAL file")
	}
}

func TestInspectPrivateCreatableDirectoryRejectsUntrustedWritableParent(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := inspectPrivateCreatableDirectory(filepath.Join(directory, "updates")); err == nil {
		t.Fatal("inspectPrivateCreatableDirectory() accepted an untrusted writable parent")
	}
}
