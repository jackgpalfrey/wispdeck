package installation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
)

type extractedBackup struct {
	manifest manifest
	files    map[string]string
	records  map[string]manifestFile
}

type replacement struct {
	target       string
	staged       string
	rollback     string
	movedOld     bool
	installedNew bool
}

// RestoreBackup validates an entire archive before replacing any state. The
// caller must provide explicit confirmation at the CLI boundary; this function
// additionally requires the serving process to be offline via the installation
// lock.
func RestoreBackup(ctx context.Context, paths Paths, inputPath string) (Summary, error) {
	cleaned, err := paths.clean()
	if err != nil {
		return Summary{}, err
	}
	if strings.TrimSpace(inputPath) == "" {
		return Summary{}, errors.New("backup input path is required")
	}
	inputPath, err = filepath.Abs(filepath.Clean(inputPath))
	if err != nil {
		return Summary{}, fmt.Errorf("resolve backup input path: %w", err)
	}
	if conflictsWithState(inputPath, cleaned) {
		return Summary{}, errors.New("backup input must be outside installation state")
	}
	if err := requireRegularFile(inputPath); err != nil {
		return Summary{}, fmt.Errorf("inspect backup archive: %w", err)
	}
	lock, err := AcquireLock(cleaned.database)
	if err != nil {
		return Summary{}, fmt.Errorf("restore requires Wispdeck to be stopped: %w", err)
	}
	defer lock.Close()

	staging, err := os.MkdirTemp("", "wispdeck-restore-")
	if err != nil {
		return Summary{}, fmt.Errorf("create restore staging directory: %w", err)
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		_ = os.RemoveAll(staging)
		return Summary{}, fmt.Errorf("restrict restore staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	extracted, summary, err := extractBackup(ctx, inputPath, staging)
	if err != nil {
		return Summary{}, err
	}
	if err := validateExtractedBackup(ctx, extracted); err != nil {
		return Summary{}, err
	}
	if err := installExtractedBackup(extracted, cleaned); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func extractBackup(ctx context.Context, inputPath, staging string) (extractedBackup, Summary, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return extractedBackup{}, Summary{}, fmt.Errorf("open backup archive: %w", err)
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return extractedBackup{}, Summary{}, fmt.Errorf("open compressed backup: %w", err)
	}
	archive := tar.NewReader(compressed)
	result := extractedBackup{
		files: make(map[string]string), records: make(map[string]manifestFile),
	}
	var summary Summary
	manifestSeen := false
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("read backup archive: %w", err)
		}
		entries++
		if entries > maxArchiveFiles+1 {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, errors.New("backup contains too many entries")
		}
		if manifestSeen {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, errors.New("backup manifest must be the final entry")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("backup entry %q is not a regular file", header.Name)
		}
		if header.Name == manifestName {
			if header.Size < 1 || header.Size > maxManifestBytes {
				_ = compressed.Close()
				return extractedBackup{}, Summary{}, errors.New("backup manifest size is invalid")
			}
			body, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
			if err != nil || int64(len(body)) != header.Size {
				_ = compressed.Close()
				return extractedBackup{}, Summary{}, errors.New("read complete backup manifest")
			}
			if err := decodeManifest(body, &result.manifest); err != nil {
				_ = compressed.Close()
				return extractedBackup{}, Summary{}, err
			}
			manifestSeen = true
			continue
		}
		if !validArchivePath(header.Name) {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("invalid backup entry path %q", header.Name)
		}
		if _, duplicate := result.records[header.Name]; duplicate {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("duplicate backup entry %q", header.Name)
		}
		if header.Size < 0 || header.Size > maxArchiveBytes || summary.Bytes > maxArchiveBytes-header.Size {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, errors.New("backup archive is too large")
		}
		destination := filepath.Join(staging, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("create restore staging path: %w", err)
		}
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("create staged backup entry %q: %w", header.Name, err)
		}
		hasher := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(file, hasher), archive, header.Size)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			_ = compressed.Close()
			return extractedBackup{}, Summary{}, fmt.Errorf("extract complete backup entry %q", header.Name)
		}
		record := manifestFile{
			Path: header.Name, Size: written, SHA256: hex.EncodeToString(hasher.Sum(nil)),
		}
		result.files[header.Name] = destination
		result.records[header.Name] = record
		summary.Files++
		summary.Bytes += written
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		_ = compressed.Close()
		return extractedBackup{}, Summary{}, fmt.Errorf("verify compressed backup: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return extractedBackup{}, Summary{}, fmt.Errorf("close compressed backup: %w", err)
	}
	if !manifestSeen {
		return extractedBackup{}, Summary{}, errors.New("backup manifest is missing")
	}
	return result, summary, nil
}

func decodeManifest(body []byte, destination *manifest) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode backup manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("backup manifest contains trailing data")
	}
	return nil
}

func validArchivePath(name string) bool {
	switch name {
	case "auth.key", "control.db", "control.db-wal":
		return true
	}
	if !strings.HasPrefix(name, "wispist/") || strings.Count(name, "/") != 1 {
		return false
	}
	return validWispistBackupName(strings.TrimPrefix(name, "wispist/"))
}

func validateExtractedBackup(ctx context.Context, backup extractedBackup) error {
	metadata := backup.manifest
	if metadata.Format != backupFormat || metadata.Version != backupFormatVersion ||
		metadata.CreatedAt.IsZero() || strings.TrimSpace(metadata.WispdeckVersion) == "" {
		return errors.New("backup manifest identity is invalid")
	}
	if len(metadata.Files) != len(backup.records) || len(metadata.Files) > maxArchiveFiles {
		return errors.New("backup manifest file count does not match archive")
	}
	declared := make(map[string]struct{}, len(metadata.Files))
	for _, expected := range metadata.Files {
		actual, exists := backup.records[expected.Path]
		if !exists || expected != actual {
			return fmt.Errorf("backup manifest does not match %q", expected.Path)
		}
		if _, duplicate := declared[expected.Path]; duplicate {
			return fmt.Errorf("backup manifest repeats %q", expected.Path)
		}
		if len(expected.SHA256) != sha256.Size*2 {
			return fmt.Errorf("backup checksum for %q is invalid", expected.Path)
		}
		declared[expected.Path] = struct{}{}
	}
	if backup.files["auth.key"] == "" || backup.files["control.db"] == "" {
		return errors.New("backup is missing the authentication key or control database")
	}
	for name := range backup.files {
		if !strings.HasSuffix(name, ".db-wal") && name != "control.db-wal" {
			continue
		}
		database := strings.TrimSuffix(name, "-wal")
		if backup.files[database] == "" {
			return fmt.Errorf("backup contains WAL without database %q", database)
		}
	}
	if _, err := auth.LoadInstallationKey(backup.files["auth.key"]); err != nil {
		return fmt.Errorf("validate backup authentication key: %w", err)
	}
	if err := CheckSQLite(ctx, backup.files["control.db"], store.SchemaVersion); err != nil {
		return fmt.Errorf("validate backup control database: %w", err)
	}
	dropCheckpointedWAL(backup.files, "control.db")
	for name, file := range backup.files {
		if !strings.HasPrefix(name, "wispist/") || !strings.HasSuffix(name, ".db") {
			continue
		}
		if err := CheckSQLite(ctx, file, wispistsqlite.SchemaVersion); err != nil {
			return fmt.Errorf("validate backup Wispist database %q: %w", name, err)
		}
		dropCheckpointedWAL(backup.files, name)
	}
	return nil
}

func dropCheckpointedWAL(files map[string]string, databaseName string) {
	walName := databaseName + "-wal"
	walPath := files[walName]
	if walPath == "" {
		return
	}
	if _, err := os.Lstat(walPath); errors.Is(err, os.ErrNotExist) {
		delete(files, walName)
	}
}

// CheckSQLite performs read-only integrity, foreign-key, and compatible-schema
// checks against an existing SQLite database.
func CheckSQLite(ctx context.Context, path string, maximumSchema int) error {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	defer database.Close()
	if _, err := database.ExecContext(ctx, `PRAGMA query_only = ON`); err != nil {
		return err
	}
	rows, err := database.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return err
	}
	checked := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			_ = rows.Close()
			return err
		}
		checked = true
		if result != "ok" {
			_ = rows.Close()
			return fmt.Errorf("SQLite quick check: %s", result)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !checked {
		return errors.New("SQLite quick check returned no result")
	}
	foreignKeys, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if foreignKeys.Next() {
		_ = foreignKeys.Close()
		return errors.New("SQLite foreign-key check failed")
	}
	if err := foreignKeys.Err(); err != nil {
		_ = foreignKeys.Close()
		return err
	}
	if err := foreignKeys.Close(); err != nil {
		return err
	}
	var count, minimum, maximum int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0)
		FROM schema_version
	`).Scan(&count, &minimum, &maximum); err != nil {
		return err
	}
	if count != 1 || minimum != maximum {
		return fmt.Errorf("schema version table contains %d rows; expected exactly one", count)
	}
	if maximum < 1 || maximum > maximumSchema {
		return fmt.Errorf("schema version %d is not supported by this binary", maximum)
	}
	return nil
}

func installExtractedBackup(backup extractedBackup, paths cleanPaths) error {
	replacements, err := prepareReplacements(backup, paths)
	if err != nil {
		return err
	}
	defer func() {
		for _, replacement := range replacements {
			if replacement.staged != "" {
				_ = os.RemoveAll(replacement.staged)
			}
		}
	}()
	rollbackDirectories := make(map[string]string)
	cleanupRollback := true
	removeRollbackDirectories := func() error {
		var result error
		for _, directory := range rollbackDirectories {
			if err := os.RemoveAll(directory); err != nil {
				result = errors.Join(result, err)
			}
		}
		return result
	}
	defer func() {
		if cleanupRollback {
			_ = removeRollbackDirectories()
		}
	}()
	failAfterMutation := func(cause error) error {
		if rollbackErr := rollbackReplacements(replacements); rollbackErr != nil {
			cleanupRollback = false
			directories := make([]string, 0, len(rollbackDirectories))
			for _, directory := range rollbackDirectories {
				directories = append(directories, directory)
			}
			sort.Strings(directories)
			return errors.Join(
				cause,
				fmt.Errorf(
					"automatic restore rollback was incomplete; prior state remains under %s: %w",
					strings.Join(directories, ", "), rollbackErr,
				),
			)
		}
		return cause
	}
	for _, replacement := range replacements {
		if err := validateExistingTarget(replacement.target, replacement.target == paths.wispistData); err != nil {
			return err
		}
		parent := filepath.Dir(replacement.target)
		if rollbackDirectories[parent] != "" {
			continue
		}
		rollbackDirectory, err := os.MkdirTemp(parent, ".wispdeck-restore-rollback-")
		if err != nil {
			return fmt.Errorf("create restore rollback directory: %w", err)
		}
		if err := os.Chmod(rollbackDirectory, 0o700); err != nil {
			_ = os.RemoveAll(rollbackDirectory)
			return fmt.Errorf("restrict restore rollback directory: %w", err)
		}
		rollbackDirectories[parent] = rollbackDirectory
	}
	for index := range replacements {
		replacement := &replacements[index]
		parent := filepath.Dir(replacement.target)
		rollbackDirectory := rollbackDirectories[parent]
		replacement.rollback = filepath.Join(
			rollbackDirectory, fmt.Sprintf("%02d-%s", index, filepath.Base(replacement.target)),
		)
		if _, err := os.Lstat(replacement.target); err == nil {
			if err := os.Rename(replacement.target, replacement.rollback); err != nil {
				return failAfterMutation(fmt.Errorf("preserve existing state %q: %w", replacement.target, err))
			}
			replacement.movedOld = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return failAfterMutation(fmt.Errorf("inspect existing state %q: %w", replacement.target, err))
		}
		if replacement.staged != "" {
			if err := os.Rename(replacement.staged, replacement.target); err != nil {
				return failAfterMutation(fmt.Errorf("install restored state %q: %w", replacement.target, err))
			}
			replacement.staged = ""
			replacement.installedNew = true
		}
	}
	for parent := range rollbackDirectories {
		if err := syncDirectory(parent); err != nil {
			return failAfterMutation(err)
		}
	}
	cleanupRollback = false
	if err := removeRollbackDirectories(); err != nil {
		return fmt.Errorf("restored state but could not remove prior-state rollback files: %w", err)
	}
	for parent := range rollbackDirectories {
		if err := syncDirectory(parent); err != nil {
			return err
		}
	}
	return nil
}

func prepareReplacements(backup extractedBackup, paths cleanPaths) ([]replacement, error) {
	control, err := stageFileNear(backup.files["control.db"], paths.database)
	if err != nil {
		return nil, err
	}
	prepared := []replacement{{target: paths.database, staged: control}}
	cleanup := func() {
		for _, item := range prepared {
			if item.staged != "" {
				_ = os.RemoveAll(item.staged)
			}
		}
	}
	authKey, err := stageFileNear(backup.files["auth.key"], paths.authKey)
	if err != nil {
		cleanup()
		return nil, err
	}
	prepared = append(prepared, replacement{target: paths.authKey, staged: authKey})
	if source := backup.files["control.db-wal"]; source != "" {
		wal, err := stageFileNear(source, paths.database+"-wal")
		if err != nil {
			cleanup()
			return nil, err
		}
		prepared = append(prepared, replacement{target: paths.database + "-wal", staged: wal})
	} else {
		prepared = append(prepared, replacement{target: paths.database + "-wal"})
	}
	prepared = append(prepared,
		replacement{target: paths.database + "-shm"},
		replacement{target: paths.database + "-journal"},
	)
	wispistDirectory, err := stageWispistNear(backup, paths.wispistData)
	if err != nil {
		cleanup()
		return nil, err
	}
	prepared = append(prepared, replacement{target: paths.wispistData, staged: wispistDirectory})
	return prepared, nil
}

func stageFileNear(source, target string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", fmt.Errorf("create restored state directory: %w", err)
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".restore-")
	if err != nil {
		return "", err
	}
	path := output.Name()
	success := false
	defer func() {
		_ = output.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := io.Copy(output, input); err != nil {
		return "", err
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	success = true
	return path, nil
}

func stageWispistNear(backup extractedBackup, target string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(filepath.Dir(target), "."+filepath.Base(target)+".restore-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(directory)
		}
	}()
	names := make([]string, 0)
	for name := range backup.files {
		if strings.HasPrefix(name, "wispist/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		destination := filepath.Join(directory, strings.TrimPrefix(name, "wispist/"))
		staged, err := stageFileNear(backup.files[name], destination)
		if err != nil {
			return "", err
		}
		if err := os.Rename(staged, destination); err != nil {
			return "", err
		}
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	success = true
	return directory, nil
}

func validateExistingTarget(path string, directory bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("existing restore target %q has an unexpected type", path)
	}
	return nil
}

func rollbackReplacements(replacements []replacement) error {
	var result error
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		if replacement.installedNew {
			if err := os.RemoveAll(replacement.target); err != nil {
				result = errors.Join(result, fmt.Errorf("remove partially restored %q: %w", replacement.target, err))
				continue
			}
		}
		if replacement.movedOld {
			if err := os.Rename(replacement.rollback, replacement.target); err != nil {
				result = errors.Join(result, fmt.Errorf("restore prior state %q: %w", replacement.target, err))
			}
		}
	}
	return result
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync restored state directory: %w", err)
	}
	return nil
}
