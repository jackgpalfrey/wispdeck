package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/installation"
)

const (
	recoveryFormat  = "wispdeck-update-recovery"
	recoveryVersion = 1
	maxRecoverySize = 32 << 10
)

var ErrRollbackRequired = errors.New("the previous update startup did not reach health readiness")

type ActivationConfig struct {
	Paths      installation.Paths
	UpdateDir  string
	Release    Release
	StagedPath string
	Current    buildinfo.Info
	Executable string
	Now        func() time.Time
}

type Recovery struct {
	marker         recoveryMarker
	path           string
	binaryRestored bool
}

func (r *Recovery) Executable() string {
	if r == nil {
		return ""
	}
	return r.marker.Executable
}

type recoveryMarker struct {
	Format        string             `json:"format"`
	Version       int                `json:"version"`
	Phase         string             `json:"phase"`
	OldVersion    string             `json:"oldVersion"`
	NewVersion    string             `json:"newVersion"`
	Executable    string             `json:"executable"`
	Previous      string             `json:"previous"`
	Backup        string             `json:"backup"`
	Paths         installation.Paths `json:"paths"`
	CreatedAt     time.Time          `json:"createdAt"`
	StartAttempts int                `json:"startAttempts"`
}

func Activate(ctx context.Context, config ActivationConfig) (*Recovery, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if _, err := ParseVersion(config.Current.Version); err != nil {
		return nil, errors.New("only tagged release builds can activate updates")
	}
	if _, err := ParseVersion(config.Release.Version); err != nil {
		return nil, err
	}
	paths, err := absoluteInstallationPaths(config.Paths)
	if err != nil {
		return nil, err
	}
	config.Paths = paths
	asset, err := config.Release.AssetFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if err := verifyFile(config.StagedPath, asset); err != nil {
		return nil, fmt.Errorf("revalidate staged update: %w", err)
	}
	executable, err := resolveExecutable(config.Executable)
	if err != nil {
		return nil, err
	}
	if err := validateRegular(executable); err != nil {
		return nil, fmt.Errorf("inspect current executable: %w", err)
	}
	updateDir, err := filepath.Abs(filepath.Clean(config.UpdateDir))
	if err != nil || strings.TrimSpace(config.UpdateDir) == "" {
		return nil, errors.New("update data directory is invalid")
	}
	updateDir, err = ValidateDataDirectory(updateDir, config.Paths)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(updateDir, "backups"), 0o700); err != nil {
		return nil, fmt.Errorf("create update backup directory: %w", err)
	}
	if err := os.Chmod(updateDir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict update data directory: %w", err)
	}
	markerPath, err := recoveryPath(config.Paths.Database)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(markerPath); err == nil {
		return nil, errors.New("an update recovery marker already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect update recovery marker: %w", err)
	}

	backupPath := filepath.Join(
		updateDir, "backups",
		fmt.Sprintf("pre-%s-%d.tar.gz", config.Release.Version, config.Now().UTC().UnixNano()),
	)
	if _, err := installation.CreateBackup(ctx, config.Paths, backupPath, config.Current.Version); err != nil {
		return nil, fmt.Errorf("create pre-update backup: %w", err)
	}
	previous, err := stageNextToExecutable(config.StagedPath, executable, asset)
	if err != nil {
		return nil, err
	}
	cleanupPrevious := true
	defer func() {
		if cleanupPrevious {
			_ = os.Remove(previous)
		}
	}()
	marker := recoveryMarker{
		Format: recoveryFormat, Version: recoveryVersion, Phase: "prepared",
		OldVersion: config.Current.Version, NewVersion: config.Release.Version,
		Executable: executable, Previous: previous, Backup: backupPath,
		Paths: config.Paths, CreatedAt: config.Now().UTC(),
	}
	if err := writeRecovery(markerPath, marker, false); err != nil {
		return nil, err
	}
	removeMarker := true
	defer func() {
		if removeMarker {
			_ = os.Remove(markerPath)
		}
	}()
	if err := exchangeFiles(executable, previous); err != nil {
		return nil, fmt.Errorf("atomically activate update: %w", err)
	}
	swapped := true
	defer func() {
		if swapped {
			_ = exchangeFiles(executable, previous)
		}
	}()
	if err := verifyFile(executable, asset); err != nil {
		return nil, fmt.Errorf("verify activated executable: %w", err)
	}
	marker.Phase = "activated"
	if err := writeRecovery(markerPath, marker, true); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(executable)); err != nil {
		return nil, fmt.Errorf("sync executable directory: %w", err)
	}
	cleanupPrevious = false
	removeMarker = false
	swapped = false
	return &Recovery{marker: marker, path: markerPath}, nil
}

func BeginStartup(databasePath, currentVersion, executableOverride string) (*Recovery, error) {
	path, err := recoveryPath(databasePath)
	if err != nil {
		return nil, err
	}
	marker, err := readRecovery(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	executable, err := resolveExecutable(executableOverride)
	if err != nil {
		return nil, err
	}
	if marker.Executable != executable {
		return nil, errors.New("update recovery marker targets a different executable")
	}
	if currentVersion == marker.OldVersion && marker.Phase == "prepared" {
		_ = os.Remove(marker.Previous)
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if currentVersion == marker.NewVersion && marker.Phase == "prepared" {
		return &Recovery{marker: marker, path: path}, ErrRollbackRequired
	}
	if currentVersion == marker.OldVersion && marker.Phase == "activated" {
		return &Recovery{marker: marker, path: path, binaryRestored: true}, ErrRollbackRequired
	}
	if currentVersion != marker.NewVersion || marker.Phase != "activated" {
		return nil, errors.New("running binary does not match the pending update recovery marker")
	}
	recovery := &Recovery{marker: marker, path: path}
	if marker.StartAttempts >= 1 {
		return recovery, ErrRollbackRequired
	}
	marker.StartAttempts++
	if err := writeRecovery(path, marker, true); err != nil {
		return nil, err
	}
	recovery.marker = marker
	return recovery, nil
}

func ConfirmStartup(recovery *Recovery) error {
	if recovery == nil {
		return nil
	}
	if err := os.Remove(recovery.path); err != nil {
		return fmt.Errorf("clear update recovery marker: %w", err)
	}
	if err := syncDirectory(filepath.Dir(recovery.path)); err != nil {
		return err
	}
	if err := os.Remove(recovery.marker.Previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove previous executable: %w", err)
	}
	return syncDirectory(filepath.Dir(recovery.marker.Executable))
}

func Rollback(ctx context.Context, recovery *Recovery) (string, error) {
	if recovery == nil {
		return "", errors.New("update recovery state is required")
	}
	marker := recovery.marker
	if err := validateRegular(marker.Executable); err != nil {
		return "", fmt.Errorf("inspect failed executable: %w", err)
	}
	if err := validateRegular(marker.Previous); err != nil {
		return "", fmt.Errorf("inspect previous executable: %w", err)
	}
	exchanged := false
	if !recovery.binaryRestored {
		if err := exchangeFiles(marker.Executable, marker.Previous); err != nil {
			return "", fmt.Errorf("restore previous executable: %w", err)
		}
		exchanged = true
	}
	if _, err := installation.RestoreBackup(ctx, marker.Paths, marker.Backup); err != nil {
		var exchangeErr error
		if exchanged || recovery.binaryRestored {
			exchangeErr = exchangeFiles(marker.Executable, marker.Previous)
		}
		return "", errors.Join(
			fmt.Errorf("restore pre-update backup: %w", err),
			func() error {
				if exchangeErr != nil {
					return fmt.Errorf("return to updated executable after failed state restore: %w", exchangeErr)
				}
				return nil
			}(),
		)
	}
	if err := os.Remove(recovery.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("clear update recovery marker after rollback: %w", err)
	}
	_ = os.Remove(marker.Previous)
	if err := syncDirectory(filepath.Dir(marker.Executable)); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(recovery.path)); err != nil {
		return "", err
	}
	return marker.Executable, nil
}

func recoveryPath(databasePath string) (string, error) {
	if strings.TrimSpace(databasePath) == "" || databasePath == ":memory:" {
		return "", errors.New("filesystem database path is required for update recovery")
	}
	databasePath, err := filepath.Abs(filepath.Clean(databasePath))
	if err != nil {
		return "", err
	}
	return databasePath + ".update-recovery.json", nil
}

func absoluteInstallationPaths(paths installation.Paths) (installation.Paths, error) {
	values := []*string{&paths.Database, &paths.WispistData, &paths.AuthKey}
	for _, value := range values {
		if strings.TrimSpace(*value) == "" || *value == ":memory:" {
			return installation.Paths{}, errors.New("filesystem installation paths are required for updates")
		}
		absolute, err := filepath.Abs(filepath.Clean(*value))
		if err != nil {
			return installation.Paths{}, err
		}
		*value = absolute
	}
	return paths, nil
}

func ValidateDataDirectory(value string, paths installation.Paths) (string, error) {
	paths, err := absoluteInstallationPaths(paths)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", errors.New("update data directory is required")
	}
	directory, err := filepath.Abs(filepath.Clean(value))
	if err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(directory); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("update data path is not a real directory")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect update data directory: %w", statErr)
	}
	statePaths := []string{
		paths.Database,
		paths.Database + "-wal",
		paths.Database + "-shm",
		paths.Database + "-journal",
		paths.Database + ".lock",
		paths.Database + ".update-recovery.json",
		paths.AuthKey,
	}
	for _, statePath := range statePaths {
		if directory == statePath || pathWithinUpdate(directory, statePath) {
			return "", errors.New("update data directory overlaps installation state")
		}
	}
	if pathWithinUpdate(directory, paths.WispistData) {
		return "", errors.New("update data directory overlaps Wispist state")
	}
	resolvedDirectory, err := resolveExistingPrefix(directory)
	if err != nil {
		return "", fmt.Errorf("resolve update data directory: %w", err)
	}
	for _, statePath := range statePaths {
		resolvedState, resolveErr := resolveExistingPrefix(statePath)
		if resolveErr != nil {
			return "", fmt.Errorf("resolve installation state: %w", resolveErr)
		}
		if resolvedDirectory == resolvedState || pathWithinUpdate(resolvedDirectory, resolvedState) {
			return "", errors.New("update data directory resolves inside installation state")
		}
	}
	resolvedWispist, err := resolveExistingPrefix(paths.WispistData)
	if err != nil {
		return "", fmt.Errorf("resolve Wispist state: %w", err)
	}
	if pathWithinUpdate(resolvedDirectory, resolvedWispist) {
		return "", errors.New("update data directory resolves inside Wispist state")
	}
	return directory, nil
}

func resolveExistingPrefix(path string) (string, error) {
	remaining := make([]string, 0, 4)
	current := path
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(remaining) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, remaining[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		remaining = append(remaining, filepath.Base(current))
		current = parent
	}
}

func pathWithinUpdate(value, directory string) bool {
	relative, err := filepath.Rel(directory, value)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func resolveExecutable(configured string) (string, error) {
	value := configured
	var err error
	if value == "" {
		value, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	value, err = filepath.Abs(filepath.Clean(value))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func stageNextToExecutable(source, executable string, asset Asset) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(executable), ".wispdeck-previous-")
	if err != nil {
		return "", fmt.Errorf("stage update beside executable: %w", err)
	}
	path := output.Name()
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0o755); err != nil {
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
	if err := verifyFile(path, asset); err != nil {
		return "", err
	}
	complete = true
	return path, nil
}

func validateRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a regular file")
	}
	return nil
}

func readRecovery(path string) (recoveryMarker, error) {
	if err := validateRegular(path); err != nil {
		return recoveryMarker{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return recoveryMarker{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxRecoverySize+1))
	if err != nil {
		return recoveryMarker{}, err
	}
	if len(body) == 0 || len(body) > maxRecoverySize {
		return recoveryMarker{}, errors.New("update recovery marker size is invalid")
	}
	var marker recoveryMarker
	if err := decodeStrict(body, &marker); err != nil {
		return recoveryMarker{}, err
	}
	if err := validateRecovery(marker); err != nil {
		return recoveryMarker{}, err
	}
	return marker, nil
}

func validateRecovery(marker recoveryMarker) error {
	if marker.Format != recoveryFormat || marker.Version != recoveryVersion ||
		(marker.Phase != "prepared" && marker.Phase != "activated") ||
		marker.StartAttempts < 0 || marker.StartAttempts > 1 || marker.CreatedAt.IsZero() {
		return errors.New("update recovery marker identity is invalid")
	}
	if _, err := ParseVersion(marker.OldVersion); err != nil {
		return err
	}
	if _, err := ParseVersion(marker.NewVersion); err != nil {
		return err
	}
	for _, value := range []string{
		marker.Executable, marker.Previous, marker.Backup,
		marker.Paths.Database, marker.Paths.WispistData, marker.Paths.AuthKey,
	} {
		if !filepath.IsAbs(value) {
			return errors.New("update recovery marker contains a relative path")
		}
	}
	return nil
}

func writeRecovery(path string, marker recoveryMarker, replace bool) error {
	if err := validateRecovery(marker); err != nil {
		return err
	}
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxRecoverySize {
		return errors.New("update recovery marker is too large")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wispdeck-update-recovery-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(body)); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("update recovery marker already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	complete = true
	return syncDirectory(filepath.Dir(path))
}
