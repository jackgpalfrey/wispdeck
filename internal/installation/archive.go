package installation

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupFormat        = "wispdeck-backup"
	backupFormatVersion = 1
	manifestName        = "manifest.json"
	maxManifestBytes    = 1 << 20
	maxArchiveFiles     = 100_000
	maxArchiveBytes     = int64(1 << 40)
)

type Paths struct {
	Database    string
	WispistData string
	AuthKey     string
}

type Summary struct {
	Files int
	Bytes int64
}

type manifest struct {
	Format          string         `json:"format"`
	Version         int            `json:"version"`
	CreatedAt       time.Time      `json:"createdAt"`
	WispdeckVersion string         `json:"wispdeckVersion"`
	Files           []manifestFile `json:"files"`
}

type manifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type cleanPaths struct {
	database    string
	wispistData string
	authKey     string
}

type sourceFile struct {
	logical string
	actual  string
}

func (p Paths) clean() (cleanPaths, error) {
	if strings.TrimSpace(p.Database) == "" || p.Database == ":memory:" ||
		strings.TrimSpace(p.WispistData) == "" || strings.TrimSpace(p.AuthKey) == "" {
		return cleanPaths{}, errors.New("database, Wispist data, and authentication key paths are required")
	}
	absolute := func(value string) (string, error) {
		path, err := filepath.Abs(filepath.Clean(value))
		if err != nil {
			return "", err
		}
		return path, nil
	}
	database, err := absolute(p.Database)
	if err != nil {
		return cleanPaths{}, fmt.Errorf("resolve control database path: %w", err)
	}
	wispistData, err := absolute(p.WispistData)
	if err != nil {
		return cleanPaths{}, fmt.Errorf("resolve Wispist data path: %w", err)
	}
	authKey, err := absolute(p.AuthKey)
	if err != nil {
		return cleanPaths{}, fmt.Errorf("resolve authentication key path: %w", err)
	}
	for _, databaseFile := range databaseStatePaths(database) {
		if databaseFile == authKey || pathWithin(databaseFile, wispistData) ||
			pathWithin(wispistData, databaseFile) {
			return cleanPaths{}, errors.New("installation state paths overlap")
		}
	}
	if pathWithin(authKey, wispistData) || pathWithin(wispistData, authKey) {
		return cleanPaths{}, errors.New("installation state paths overlap")
	}
	return cleanPaths{database: database, wispistData: wispistData, authKey: authKey}, nil
}

func databaseStatePaths(database string) []string {
	return []string{
		database,
		database + "-wal",
		database + "-shm",
		database + "-journal",
		database + ".lock",
	}
}

func conflictsWithState(path string, state cleanPaths) bool {
	if path == state.authKey || pathWithin(path, state.wispistData) {
		return true
	}
	for _, databaseFile := range databaseStatePaths(state.database) {
		if path == databaseFile {
			return true
		}
	}
	return false
}

func pathWithin(value, directory string) bool {
	relative, err := filepath.Rel(directory, value)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

// CreateBackup writes a new, owner-only archive. It never overwrites an
// existing path and includes the authentication key because encrypted account
// state is unusable without it.
func CreateBackup(
	ctx context.Context,
	paths Paths,
	outputPath, applicationVersion string,
) (Summary, error) {
	cleaned, err := paths.clean()
	if err != nil {
		return Summary{}, err
	}
	if strings.TrimSpace(outputPath) == "" {
		return Summary{}, errors.New("backup output path is required")
	}
	outputPath, err = filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return Summary{}, fmt.Errorf("resolve backup output path: %w", err)
	}
	if conflictsWithState(outputPath, cleaned) {
		return Summary{}, errors.New("backup output must be outside installation state")
	}
	lock, err := AcquireLock(cleaned.database)
	if err != nil {
		return Summary{}, fmt.Errorf("backup requires Wispdeck to be stopped: %w", err)
	}
	defer lock.Close()

	sources, err := backupSources(cleaned)
	if err != nil {
		return Summary{}, err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return Summary{}, fmt.Errorf("create backup directory: %w", err)
	}
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Summary{}, fmt.Errorf("create backup archive: %w", err)
	}
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = os.Remove(outputPath)
		}
	}()
	if err := os.Chmod(outputPath, 0o600); err != nil {
		return Summary{}, fmt.Errorf("restrict backup archive: %w", err)
	}
	summary, err := writeBackupArchive(ctx, output, sources, applicationVersion)
	if err != nil {
		return Summary{}, err
	}
	if err := output.Sync(); err != nil {
		return Summary{}, fmt.Errorf("sync backup archive: %w", err)
	}
	if err := output.Close(); err != nil {
		return Summary{}, fmt.Errorf("close backup archive: %w", err)
	}
	complete = true
	return summary, nil
}

func backupSources(paths cleanPaths) ([]sourceFile, error) {
	sources := make([]sourceFile, 0)
	addRequired := func(logical, actual string) error {
		if err := requireRegularFile(actual); err != nil {
			return err
		}
		sources = append(sources, sourceFile{logical: logical, actual: actual})
		return nil
	}
	if err := addRequired("auth.key", paths.authKey); err != nil {
		return nil, fmt.Errorf("inspect authentication key: %w", err)
	}
	if err := addRequired("control.db", paths.database); err != nil {
		return nil, fmt.Errorf("inspect control database: %w", err)
	}
	if err := addOptionalRegular(&sources, "control.db-wal", paths.database+"-wal"); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(paths.wispistData)
	if errors.Is(err, os.ErrNotExist) {
		entries = nil
	} else if err != nil {
		return nil, fmt.Errorf("read Wispist data directory: %w", err)
	} else {
		info, statErr := os.Lstat(paths.wispistData)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Wispist data path is not a real directory")
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".db-shm") {
			continue
		}
		if !validWispistBackupName(name) {
			return nil, fmt.Errorf("unexpected file in Wispist data directory: %q", name)
		}
		actual := filepath.Join(paths.wispistData, name)
		if err := requireRegularFile(actual); err != nil {
			return nil, fmt.Errorf("inspect Wispist file %q: %w", name, err)
		}
		sources = append(sources, sourceFile{logical: "wispist/" + name, actual: actual})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].logical < sources[j].logical })
	return sources, nil
}

func addOptionalRegular(sources *[]sourceFile, logical, actual string) error {
	if err := requireRegularFile(actual); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect %s: %w", logical, err)
	}
	*sources = append(*sources, sourceFile{logical: logical, actual: actual})
	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a regular file")
	}
	return nil
}

func validWispistBackupName(name string) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), ".db")
	if base == name || len(base) < 1 || len(base) > 128 {
		return false
	}
	suffix := strings.TrimPrefix(name, base)
	if suffix != ".db" && suffix != ".db-wal" {
		return false
	}
	for _, char := range []byte(base) {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func writeBackupArchive(
	ctx context.Context,
	output io.Writer,
	sources []sourceFile,
	applicationVersion string,
) (Summary, error) {
	createdAt := time.Now().UTC()
	compressed := gzip.NewWriter(output)
	compressed.Header.Name = ""
	compressed.Header.Comment = ""
	compressed.Header.ModTime = createdAt
	archive := tar.NewWriter(compressed)
	metadata := manifest{
		Format: backupFormat, Version: backupFormatVersion, CreatedAt: createdAt,
		WispdeckVersion: strings.TrimSpace(applicationVersion), Files: make([]manifestFile, 0, len(sources)),
	}
	if metadata.WispdeckVersion == "" {
		metadata.WispdeckVersion = "unknown"
	}
	var summary Summary
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		file, err := os.Open(source.actual)
		if err != nil {
			return Summary{}, fmt.Errorf("open backup source %q: %w", source.logical, err)
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return Summary{}, fmt.Errorf("inspect backup source %q: %w", source.logical, err)
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return Summary{}, fmt.Errorf("backup source %q is not a regular file", source.logical)
		}
		header := &tar.Header{
			Name: source.logical, Mode: 0o600, Size: info.Size(),
			ModTime: info.ModTime().UTC(), Typeflag: tar.TypeReg,
		}
		if err := archive.WriteHeader(header); err != nil {
			_ = file.Close()
			return Summary{}, fmt.Errorf("write backup header %q: %w", source.logical, err)
		}
		hasher := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(archive, hasher), file, info.Size())
		after, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || written != info.Size() || after.Size() != info.Size() ||
			!after.ModTime().Equal(info.ModTime()) {
			return Summary{}, fmt.Errorf("backup source %q changed while being read", source.logical)
		}
		metadata.Files = append(metadata.Files, manifestFile{
			Path: source.logical, Size: written, SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
		summary.Files++
		summary.Bytes += written
	}
	manifestBody, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return Summary{}, fmt.Errorf("encode backup manifest: %w", err)
	}
	manifestBody = append(manifestBody, '\n')
	if err := archive.WriteHeader(&tar.Header{
		Name: manifestName, Mode: 0o600, Size: int64(len(manifestBody)),
		ModTime: createdAt, Typeflag: tar.TypeReg,
	}); err != nil {
		return Summary{}, fmt.Errorf("write backup manifest header: %w", err)
	}
	if _, err := archive.Write(manifestBody); err != nil {
		return Summary{}, fmt.Errorf("write backup manifest: %w", err)
	}
	if err := archive.Close(); err != nil {
		return Summary{}, fmt.Errorf("close backup tar stream: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return Summary{}, fmt.Errorf("close compressed backup stream: %w", err)
	}
	return summary, nil
}
