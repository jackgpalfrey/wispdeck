package installation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/wispist"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
)

func TestBackupRoundTripRestoresCompleteInstallation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	paths := Paths{
		Database:    filepath.Join(root, "state", "wispdeck.db"),
		WispistData: filepath.Join(root, "state", "wispist"),
		AuthKey:     filepath.Join(root, "state", "auth.key"),
	}
	if err := auth.GenerateInstallationKey(paths.AuthKey); err != nil {
		t.Fatal(err)
	}
	originalKey, err := os.ReadFile(paths.AuthKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
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
	factory, err := wispistsqlite.NewFactory(paths.WispistData)
	if err != nil {
		t.Fatal(err)
	}
	wispistStore, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wispistStore.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "passport",
		Data: []byte(`{"done":false}`), CreateOnly: true, Now: now,
		Limits: wispist.MutationLimits{
			MaxDocuments: 100, MaxDocumentBytes: 1024, MaxNamespaceBytes: 1 << 20,
			MaxIdempotencyRecords: 100, ChangeRetentionEntries: 100,
			ChangeRetentionAge: 7 * 24 * time.Hour, IdempotencyRetention: 24 * time.Hour,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := wispistStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := factory.Close(); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(root, "backup.tar.gz")
	summary, err := CreateBackup(ctx, paths, archive, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Files != 3 || summary.Bytes == 0 {
		t.Fatalf("backup summary = %+v", summary)
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o", info.Mode().Perm())
	}
	if _, err := CreateBackup(ctx, paths, archive, "v1.2.3"); err == nil {
		t.Fatal("backup overwrote an existing archive")
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
	if err := os.WriteFile(paths.AuthKey, bytes.Repeat([]byte{0x7f}, len(originalKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(paths.WispistData); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.WispistData, 0o700); err != nil {
		t.Fatal(err)
	}

	restored, err := RestoreBackup(ctx, paths, archive)
	if err != nil {
		t.Fatal(err)
	}
	if restored != summary {
		t.Fatalf("restore summary = %+v, want %+v", restored, summary)
	}
	restoredKey, err := os.ReadFile(paths.AuthKey)
	if err != nil || !bytes.Equal(restoredKey, originalKey) {
		t.Fatalf("restored authentication key differs: %v", err)
	}
	database, err = store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UserByUsername(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UserByUsername(ctx, "bob"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("post-backup user survived restore: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	factory, err = wispistsqlite.NewFactory(paths.WispistData)
	if err != nil {
		t.Fatal(err)
	}
	wispistStore, err = factory.Open(ctx, "site", false)
	if err != nil {
		t.Fatal(err)
	}
	document, err := wispistStore.Get(ctx, "live", "items", "passport")
	if err != nil || string(document.Data) != `{"done":false}` {
		t.Fatalf("restored Wispist document = (%+v, %v)", document, err)
	}
	_ = wispistStore.Close()
	_ = factory.Close()
}

func TestBackupAndRestoreRefuseActiveInstallation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := Paths{
		Database:    filepath.Join(root, "wispdeck.db"),
		WispistData: filepath.Join(root, "wispist"),
		AuthKey:     filepath.Join(root, "auth.key"),
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
	archive := filepath.Join(root, "backup.tar.gz")
	if _, err := CreateBackup(context.Background(), paths, archive, "dev"); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := CreateBackup(context.Background(), paths, filepath.Join(root, "second.tar.gz"), "dev"); !errors.Is(err, ErrInUse) {
		t.Fatalf("backup lock error = %v", err)
	}
	if _, err := RestoreBackup(context.Background(), paths, archive); !errors.Is(err, ErrInUse) {
		t.Fatalf("restore lock error = %v", err)
	}
}

func TestCorruptBackupDoesNotReplaceExistingState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	paths := Paths{
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
	if _, err := database.CreateUser(ctx, "alice", "hash", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	archive := filepath.Join(root, "backup.tar.gz")
	if _, err := CreateBackup(ctx, paths, archive, "dev"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 0xff
	corrupt := filepath.Join(root, "corrupt.tar.gz")
	if err := os.WriteFile(corrupt, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(ctx, paths, corrupt); err == nil {
		t.Fatal("restored a corrupt archive")
	}
	database, err = store.OpenSQLite(ctx, paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.UserByUsername(ctx, "alice"); err != nil {
		t.Fatalf("failed restore changed existing state: %v", err)
	}
}

func TestBackupRejectsSQLiteStatePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := Paths{
		Database:    filepath.Join(root, "wispdeck.db"),
		WispistData: filepath.Join(root, "wispist"),
		AuthKey:     filepath.Join(root, "auth.key"),
	}
	for _, output := range databaseStatePaths(paths.Database) {
		if _, err := CreateBackup(context.Background(), paths, output, "dev"); err == nil {
			t.Fatalf("accepted database state path as backup output: %q", output)
		}
	}
}

func TestInstallationPathsCannotOverlap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, paths := range []Paths{
		{
			Database: filepath.Join(root, "state"), WispistData: filepath.Join(root, "state", "wispist"),
			AuthKey: filepath.Join(root, "auth.key"),
		},
		{
			Database: filepath.Join(root, "wispdeck.db"), WispistData: filepath.Join(root, "auth.key", "wispist"),
			AuthKey: filepath.Join(root, "auth.key"),
		},
		{
			Database: filepath.Join(root, "wispdeck.db"), WispistData: filepath.Join(root, "wispdeck.db-wal"),
			AuthKey: filepath.Join(root, "auth.key"),
		},
	} {
		if _, err := paths.clean(); err == nil {
			t.Fatalf("accepted overlapping installation paths: %+v", paths)
		}
	}
}
