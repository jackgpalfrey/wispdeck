package installation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationLockIsExclusiveAndReusable(t *testing.T) {
	database := filepath.Join(t.TempDir(), "state", "wispdeck.db")
	first, err := AcquireLock(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(database); !errors.Is(err, ErrInUse) {
		t.Fatalf("second lock error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireLock(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	info, err := os.Stat(database + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %o", info.Mode().Perm())
	}
}

func TestInstallationLockRejectsNonFilesystemDatabase(t *testing.T) {
	if _, err := AcquireLock(":memory:"); err == nil {
		t.Fatal("locked an in-memory database")
	}
}

func TestInstallationLockRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "wispdeck.db")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("do not touch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, database+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(database); err == nil {
		t.Fatal("opened a symlink as the installation lock")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "do not touch" {
		t.Fatalf("symlink target changed to %q", body)
	}
}
