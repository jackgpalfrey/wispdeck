//go:build linux

package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckActivationSupportCleansUpProbeFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	executable := filepath.Join(directory, "wispdeck")
	if err := os.WriteFile(executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckActivationSupport(executable); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wispdeck-doctor-") {
			t.Fatalf("activation probe left temporary file %q", entry.Name())
		}
	}
}
