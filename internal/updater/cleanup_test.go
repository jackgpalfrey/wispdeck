package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupArtifactsRetainsNewestKnownFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	backups := filepath.Join(root, "backups")
	downloads := filepath.Join(root, "downloads")
	for _, directory := range []string{backups, downloads} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	for index := 1; index <= 5; index++ {
		backup := filepath.Join(backups, fmt.Sprintf("pre-v1.0.%d-%d.tar.gz", index, index))
		download := filepath.Join(downloads, fmt.Sprintf("wispdeck-v1.0.%d-linux-amd64", index))
		for _, path := range []string{backup, download} {
			if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
				t.Fatal(err)
			}
			modified := now.Add(time.Duration(index) * time.Minute)
			if err := os.Chtimes(path, modified, modified); err != nil {
				t.Fatal(err)
			}
		}
	}
	unknown := filepath.Join(backups, "operator-note.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(downloads, ".wispdeck-download-stale")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(temporary, old, old); err != nil {
		t.Fatal(err)
	}

	summary, err := CleanupArtifacts(root, ArtifactRetention{
		Backups: 3, Downloads: 3, TemporaryMaxAge: 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Backups != 2 || summary.Downloads != 2 || summary.Temporary != 1 {
		t.Fatalf("cleanup summary = %+v", summary)
	}
	for _, path := range []string{
		filepath.Join(backups, "pre-v1.0.3-3.tar.gz"),
		filepath.Join(backups, "pre-v1.0.4-4.tar.gz"),
		filepath.Join(backups, "pre-v1.0.5-5.tar.gz"),
		filepath.Join(downloads, "wispdeck-v1.0.3-linux-amd64"),
		filepath.Join(downloads, "wispdeck-v1.0.4-linux-amd64"),
		filepath.Join(downloads, "wispdeck-v1.0.5-linux-amd64"),
		unknown,
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("retained artifact %q: %v", path, err)
		}
	}
}

func TestCleanupArtifactsRefusesMatchingSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	directory := filepath.Join(root, "backups")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "pre-v1.0.0-1.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupArtifacts(root, ArtifactRetention{Backups: 1, Downloads: 1}); err == nil {
		t.Fatal("CleanupArtifacts() accepted a matching symbolic link")
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatal("cleanup altered the symlink target")
	}
}

func TestCleanupArtifactsValidatesAllArtifactsBeforePruning(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	backups := filepath.Join(root, "backups")
	downloads := filepath.Join(root, "downloads")
	for _, directory := range []string{backups, downloads} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldBackup := filepath.Join(backups, "pre-v1.0.0-1.tar.gz")
	newBackup := filepath.Join(backups, "pre-v1.0.1-2.tar.gz")
	for _, path := range []string{oldBackup, newBackup} {
		if err := os.WriteFile(path, []byte("backup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(oldBackup, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(downloads, "wispdeck-v1.0.0-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupArtifacts(root, ArtifactRetention{Backups: 1, Downloads: 1}); err == nil {
		t.Fatal("CleanupArtifacts() accepted a matching download symlink")
	}
	if _, err := os.Lstat(oldBackup); err != nil {
		t.Fatal("cleanup pruned a backup before validating all artifact directories")
	}
}
