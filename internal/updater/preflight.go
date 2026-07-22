package updater

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CheckActivationSupport verifies that the installed executable is a regular
// file and that its directory supports the same atomic exchange used by the
// updater. Temporary probe files are always removed.
func CheckActivationSupport(executableOverride string) (result error) {
	executable, err := resolveExecutable(executableOverride)
	if err != nil {
		return err
	}
	if err := validateRegular(executable); err != nil {
		return fmt.Errorf("inspect executable: %w", err)
	}
	directory := filepath.Dir(executable)
	first, err := os.CreateTemp(directory, ".wispdeck-doctor-a-")
	if err != nil {
		return fmt.Errorf("create update probe beside executable: %w", err)
	}
	firstPath := first.Name()
	var second *os.File
	var secondPath string
	defer func() {
		if first != nil {
			result = errors.Join(result, first.Close())
		}
		if second != nil {
			result = errors.Join(result, second.Close())
		}
		for _, path := range []string{firstPath, secondPath} {
			if path == "" {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("remove update probe %q: %w", path, err))
			}
		}
		result = errors.Join(result, syncDirectory(directory))
	}()
	second, err = os.CreateTemp(directory, ".wispdeck-doctor-b-")
	if err != nil {
		return fmt.Errorf("create second update probe beside executable: %w", err)
	}
	secondPath = second.Name()
	if _, err := first.WriteString("first"); err != nil {
		return fmt.Errorf("write first update probe: %w", err)
	}
	if _, err := second.WriteString("second"); err != nil {
		return fmt.Errorf("write second update probe: %w", err)
	}
	if err := first.Sync(); err != nil {
		return fmt.Errorf("sync first update probe: %w", err)
	}
	if err := second.Sync(); err != nil {
		return fmt.Errorf("sync second update probe: %w", err)
	}
	closeErr := errors.Join(first.Close(), second.Close())
	first = nil
	second = nil
	if closeErr != nil {
		return fmt.Errorf("close update probes: %w", closeErr)
	}
	if err := exchangeFiles(firstPath, secondPath); err != nil {
		return fmt.Errorf("atomic executable exchange is unavailable: %w", err)
	}
	firstBody, err := os.ReadFile(firstPath)
	if err != nil {
		return err
	}
	secondBody, err := os.ReadFile(secondPath)
	if err != nil {
		return err
	}
	if string(firstBody) != "second" || string(secondBody) != "first" {
		return errors.New("atomic executable exchange returned unexpected file contents")
	}
	return nil
}
