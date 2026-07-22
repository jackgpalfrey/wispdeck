package updater

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRetainedBackups   = 3
	DefaultRetainedDownloads = 3
	defaultTemporaryMaxAge   = 24 * time.Hour
)

type ArtifactRetention struct {
	Backups         int
	Downloads       int
	TemporaryMaxAge time.Duration
	Now             func() time.Time
}

type CleanupSummary struct {
	Backups   int
	Downloads int
	Temporary int
}

func (s CleanupSummary) Removed() int {
	return s.Backups + s.Downloads + s.Temporary
}

func CleanupArtifacts(updateDirectory string, retention ArtifactRetention) (CleanupSummary, error) {
	if retention.Backups == 0 {
		retention.Backups = DefaultRetainedBackups
	}
	if retention.Downloads == 0 {
		retention.Downloads = DefaultRetainedDownloads
	}
	if retention.TemporaryMaxAge == 0 {
		retention.TemporaryMaxAge = defaultTemporaryMaxAge
	}
	if retention.Now == nil {
		retention.Now = time.Now
	}
	if retention.Backups < 1 || retention.Backups > 100 ||
		retention.Downloads < 1 || retention.Downloads > 100 ||
		retention.TemporaryMaxAge < time.Hour || retention.TemporaryMaxAge > 30*24*time.Hour {
		return CleanupSummary{}, errors.New("update artifact retention is invalid")
	}
	if strings.TrimSpace(updateDirectory) == "" {
		return CleanupSummary{}, errors.New("update data directory is required")
	}
	directory, err := filepath.Abs(filepath.Clean(updateDirectory))
	if err != nil {
		return CleanupSummary{}, err
	}
	if info, statErr := os.Lstat(directory); errors.Is(statErr, os.ErrNotExist) {
		return CleanupSummary{}, nil
	} else if statErr != nil {
		return CleanupSummary{}, fmt.Errorf("inspect update data directory: %w", statErr)
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return CleanupSummary{}, errors.New("update data path is not a real directory")
	}

	backupDirectory := filepath.Join(directory, "backups")
	downloadDirectory := filepath.Join(directory, "downloads")
	backupFiles, err := matchingArtifacts(backupDirectory, validBackupArtifact)
	if err != nil {
		return CleanupSummary{}, err
	}
	downloadFiles, err := matchingArtifacts(downloadDirectory, validDownloadArtifact)
	if err != nil {
		return CleanupSummary{}, err
	}
	temporaryFiles, err := matchingArtifacts(downloadDirectory, func(name string) bool {
		return strings.HasPrefix(name, ".wispdeck-download-")
	})
	if err != nil {
		return CleanupSummary{}, err
	}

	backups, err := pruneArtifactFiles(backupDirectory, backupFiles, retention.Backups)
	if err != nil {
		return CleanupSummary{}, err
	}
	downloads, err := pruneArtifactFiles(downloadDirectory, downloadFiles, retention.Downloads)
	if err != nil {
		return CleanupSummary{}, err
	}
	temporary, err := pruneTemporaryFiles(
		downloadDirectory, temporaryFiles,
		retention.Now().UTC().Add(-retention.TemporaryMaxAge),
	)
	if err != nil {
		return CleanupSummary{}, err
	}
	return CleanupSummary{Backups: backups, Downloads: downloads, Temporary: temporary}, nil
}

type artifactFile struct {
	name     string
	path     string
	modified time.Time
}

func pruneArtifactFiles(directory string, files []artifactFile, keep int) (int, error) {
	sort.Slice(files, func(i, j int) bool {
		if files[i].modified.Equal(files[j].modified) {
			return files[i].name > files[j].name
		}
		return files[i].modified.After(files[j].modified)
	})
	removed := 0
	for _, file := range files[min(keep, len(files)):] {
		if err := os.Remove(file.path); err != nil {
			return removed, fmt.Errorf("remove retained update artifact %q: %w", file.name, err)
		}
		removed++
	}
	if removed > 0 {
		if err := syncDirectory(directory); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func pruneTemporaryFiles(directory string, files []artifactFile, cutoff time.Time) (int, error) {
	removed := 0
	for _, file := range files {
		if !file.modified.Before(cutoff) {
			continue
		}
		if err := os.Remove(file.path); err != nil {
			return removed, fmt.Errorf("remove stale update download %q: %w", file.name, err)
		}
		removed++
	}
	if removed > 0 {
		if err := syncDirectory(directory); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func matchingArtifacts(directory string, matches func(string) bool) ([]artifactFile, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read update artifact directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("update artifact path is not a real directory")
	}
	files := make([]artifactFile, 0, len(entries))
	for _, entry := range entries {
		if !matches(entry.Name()) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("update artifact %q is a symbolic link", entry.Name())
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect update artifact %q: %w", entry.Name(), err)
		}
		if !entryInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("update artifact %q is not a regular file", entry.Name())
		}
		files = append(files, artifactFile{
			name: entry.Name(), path: filepath.Join(directory, entry.Name()), modified: entryInfo.ModTime(),
		})
	}
	return files, nil
}

func validBackupArtifact(name string) bool {
	if !strings.HasPrefix(name, "pre-v") || !strings.HasSuffix(name, ".tar.gz") {
		return false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(name, "pre-"), ".tar.gz")
	separator := strings.LastIndexByte(value, '-')
	if separator < 1 {
		return false
	}
	if _, err := ParseVersion(value[:separator]); err != nil {
		return false
	}
	timestamp, err := strconv.ParseInt(value[separator+1:], 10, 64)
	return err == nil && timestamp > 0
}

func validDownloadArtifact(name string) bool {
	parts := strings.Split(name, "-")
	if len(parts) != 4 || parts[0] != "wispdeck" {
		return false
	}
	if _, err := ParseVersion(parts[1]); err != nil {
		return false
	}
	return validPlatformPart(parts[2]) && validPlatformPart(parts[3])
}

func validPlatformPart(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range []byte(value) {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}
