// Package buildinfo exposes immutable metadata injected into release binaries.
package buildinfo

import (
	"runtime"
	"strings"
)

var (
	version           = "dev"
	commit            = "unknown"
	builtAt           = "unknown"
	updateManifestURL = ""
	updatePublicKey   = ""
)

// Info is the stable machine-readable description printed by `wispdeck
// version --json` and later consumed by the tagged-release updater.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"builtAt"`
	GoVersion string `json:"goVersion"`
}

type UpdateConfig struct {
	ManifestURL string
	PublicKey   string
}

func Updates() UpdateConfig {
	return UpdateConfig{
		ManifestURL: strings.TrimSpace(updateManifestURL),
		PublicKey:   strings.TrimSpace(updatePublicKey),
	}
}

func Current() Info {
	return Info{
		Version:   valueOr(version, "dev"),
		Commit:    valueOr(commit, "unknown"),
		BuiltAt:   valueOr(builtAt, "unknown"),
		GoVersion: runtime.Version(),
	}
}

func valueOr(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
