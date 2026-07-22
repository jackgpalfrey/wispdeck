package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/installation"
	"github.com/wispdeck/wispdeck/internal/store"
)

func TestActivationRollbackRestoresBinaryAndState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	paths := installation.Paths{
		Database:    filepath.Join(root, "state", "wispdeck.db"),
		WispistData: filepath.Join(root, "state", "wispist"),
		AuthKey:     filepath.Join(root, "state", "auth.key"),
	}
	if err := auth.GenerateInstallationKey(paths.AuthKey); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 18, 0, 0, 0, time.UTC)
	database, err := store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser(ctx, "alice", "hash", now); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	oldBinary := []byte("old executable")
	newBinary := []byte("new signed executable")
	executable := filepath.Join(root, "bin", "wispdeck")
	staged := filepath.Join(root, "downloads", "wispdeck-v1.1.0")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, newBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(newBinary)
	release := Release{
		Version: "v1.1.0", PublishedAt: now,
		Assets: []Asset{{
			OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://updates.example/wispdeck",
			SHA256: hex.EncodeToString(digest[:]), Size: int64(len(newBinary)),
		}},
	}
	recovery, err := Activate(ctx, ActivationConfig{
		Paths: paths, UpdateDir: filepath.Join(root, "updates"),
		Release: release, StagedPath: staged,
		Current: buildinfo.Info{Version: "v1.0.0"}, Executable: executable,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, executable, newBinary)
	started, err := BeginStartup(paths.Database, "v1.1.0", executable)
	if err != nil || started == nil {
		t.Fatalf("BeginStartup() = (%+v, %v)", started, err)
	}
	if _, err := BeginStartup(paths.Database, "v1.1.0", executable); !errors.Is(err, ErrRollbackRequired) {
		t.Fatalf("second BeginStartup error = %v", err)
	}

	database, err = store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateManagedUser(ctx, "bob", "hash", auth.RoleUser, auth.UserActive, now); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, executable, oldBinary)
	database, err = store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.UserByUsername(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UserByUsername(ctx, "bob"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("post-backup user survived rollback: %v", err)
	}
}

func TestConfirmStartupRemovesRecoveryMaterial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	paths := installation.Paths{
		Database:    filepath.Join(root, "state", "wispdeck.db"),
		WispistData: filepath.Join(root, "state", "wispist"),
		AuthKey:     filepath.Join(root, "state", "auth.key"),
	}
	if err := auth.GenerateInstallationKey(paths.AuthKey); err != nil {
		t.Fatal(err)
	}
	database, err := store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "wispdeck")
	staged := filepath.Join(root, "staged")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("new"))
	recovery, err := Activate(ctx, ActivationConfig{
		Paths: paths, UpdateDir: filepath.Join(root, "updates"), StagedPath: staged,
		Current: buildinfo.Info{Version: "v1.0.0"}, Executable: executable,
		Release: Release{Version: "v1.1.0", PublishedAt: time.Now().UTC(), Assets: []Asset{{
			OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://updates.example/wispdeck",
			SHA256: hex.EncodeToString(digest[:]), Size: 3,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfirmStartup(recovery); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(recovery.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery marker remains: %v", err)
	}
	if _, err := os.Lstat(recovery.marker.Previous); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous executable remains: %v", err)
	}
}

func TestBeginStartupRecoversCrashAfterExchangeBeforeMarkerUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	recovery, executable, oldBinary := activateFixture(t, ctx)
	recovery.marker.Phase = "prepared"
	if err := writeRecovery(recovery.path, recovery.marker, true); err != nil {
		t.Fatal(err)
	}

	started, err := BeginStartup(recovery.marker.Paths.Database, recovery.marker.NewVersion, executable)
	if !errors.Is(err, ErrRollbackRequired) || started == nil {
		t.Fatalf("BeginStartup() = (%+v, %v)", started, err)
	}
	if _, err := Rollback(ctx, started); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, executable, oldBinary)
}

func TestBeginStartupFinishesRollbackInterruptedAfterBinaryRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	recovery, executable, oldBinary := activateFixture(t, ctx)
	if err := exchangeFiles(recovery.marker.Executable, recovery.marker.Previous); err != nil {
		t.Fatal(err)
	}

	started, err := BeginStartup(recovery.marker.Paths.Database, recovery.marker.OldVersion, executable)
	if !errors.Is(err, ErrRollbackRequired) || started == nil {
		t.Fatalf("BeginStartup() = (%+v, %v)", started, err)
	}
	if _, err := Rollback(ctx, started); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, executable, oldBinary)
}

func TestValidateDataDirectoryRejectsInstallationState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := installation.Paths{
		Database:    filepath.Join(root, "state", "wispdeck.db"),
		WispistData: filepath.Join(root, "state", "wispist"),
		AuthKey:     filepath.Join(root, "state", "auth.key"),
	}
	tests := []string{
		paths.Database,
		paths.Database + "-wal",
		filepath.Join(paths.WispistData, "updates"),
		paths.AuthKey,
	}
	for _, value := range tests {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ValidateDataDirectory(value, paths); err == nil {
				t.Fatal("ValidateDataDirectory() succeeded for installation state")
			}
		})
	}
	allowed := filepath.Join(root, "state", "updates")
	got, err := ValidateDataDirectory(allowed, paths)
	if err != nil {
		t.Fatal(err)
	}
	if got != allowed {
		t.Fatalf("ValidateDataDirectory() = %q, want %q", got, allowed)
	}
	if err := os.MkdirAll(paths.WispistData, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "wispist-alias")
	if err := os.Symlink(paths.WispistData, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDataDirectory(filepath.Join(alias, "updates"), paths); err == nil {
		t.Fatal("ValidateDataDirectory() accepted a path resolving into Wispist state")
	}
}

func activateFixture(t *testing.T, ctx context.Context) (*Recovery, string, []byte) {
	t.Helper()
	root := t.TempDir()
	paths := installation.Paths{
		Database:    filepath.Join(root, "state", "wispdeck.db"),
		WispistData: filepath.Join(root, "state", "wispist"),
		AuthKey:     filepath.Join(root, "state", "auth.key"),
	}
	if err := auth.GenerateInstallationKey(paths.AuthKey); err != nil {
		t.Fatal(err)
	}
	database, err := store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	oldBinary := []byte("old executable")
	newBinary := []byte("new executable")
	executable := filepath.Join(root, "bin", "wispdeck")
	staged := filepath.Join(root, "staged", "wispdeck-v1.1.0")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, newBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(newBinary)
	recovery, err := Activate(ctx, ActivationConfig{
		Paths: paths, UpdateDir: filepath.Join(root, "updates"), StagedPath: staged,
		Current: buildinfo.Info{Version: "v1.0.0"}, Executable: executable,
		Release: Release{Version: "v1.1.0", PublishedAt: time.Now().UTC(), Assets: []Asset{{
			OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://updates.example/wispdeck",
			SHA256: hex.EncodeToString(digest[:]), Size: int64(len(newBinary)),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return recovery, executable, oldBinary
}

func assertFileBody(t *testing.T, path string, expected []byte) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, expected) {
		t.Fatalf("%s = %q, want %q", path, body, expected)
	}
}
