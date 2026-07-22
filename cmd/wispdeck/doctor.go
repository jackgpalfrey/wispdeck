package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/installation"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/internal/updater"
	"github.com/wispdeck/wispdeck/internal/web"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
	"golang.org/x/sys/unix"
)

type doctorStatus string

const (
	doctorPass doctorStatus = "pass"
	doctorWarn doctorStatus = "warn"
	doctorFail doctorStatus = "fail"
)

type doctorCheck struct {
	Name   string       `json:"name"`
	Status doctorStatus `json:"status"`
	Detail string       `json:"detail"`
}

type doctorReport struct {
	Checks   []doctorCheck `json:"checks"`
	Failures int           `json:"failures"`
	Warnings int           `json:"warnings"`
}

func (r *doctorReport) add(name string, status doctorStatus, detail string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	switch status {
	case doctorFail:
		r.Failures++
	case doctorWarn:
		r.Warnings++
	}
}

type doctorConfig struct {
	Build               buildinfo.Info
	AppOrigin           string
	SiteDomain          string
	PreviewDomain       string
	TrustedProxies      []string
	Paths               installation.Paths
	UpdateData          string
	UpdateManifestURL   string
	UpdatePublicKey     string
	UpdatePublicKeyFile string
	Executable          string
}

func doctor(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	embeddedUpdates := buildinfo.Updates()
	appOrigin := flags.String("app-origin", "", "public HTTPS application origin (required)")
	siteDomain := flags.String("site-domain", "", "hosted-site domain suffix")
	previewDomain := flags.String("preview-domain", "", "isolated preview domain suffix")
	database := flags.String("database", "data/wispdeck.db", "control database path")
	wispistData := flags.String("wispist-data", "data/wispist", "Wispist site-data directory")
	authKey := flags.String("auth-key", "data/auth.key", "installation authentication key path")
	updateData := flags.String("update-data", "", "update downloads and pre-update backups directory")
	updateManifestURL := flags.String("update-manifest-url", embeddedUpdates.ManifestURL, "signed stable-release manifest URL")
	updatePublicKey := flags.String("update-public-key", embeddedUpdates.PublicKey, "base64 Ed25519 release-signing public key")
	updatePublicKeyFile := flags.String("update-public-key-file", "", "file containing the release-signing public key")
	executable := flags.String("executable", "", "installed Wispdeck executable (defaults to this process)")
	jsonOutput := flags.Bool("json", false, "print machine-readable results")
	var trustedProxies stringListFlag
	flags.Var(&trustedProxies, "trusted-proxy", "trusted reverse-proxy CIDR (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*appOrigin) == "" {
		return errors.New("doctor requires --app-origin and accepts no positional arguments")
	}
	if *updateData == "" {
		*updateData = filepath.Join(filepath.Dir(*database), "updates")
	}
	report := inspectDoctor(context.Background(), doctorConfig{
		Build: buildinfo.Current(), AppOrigin: *appOrigin,
		SiteDomain: *siteDomain, PreviewDomain: *previewDomain,
		TrustedProxies: trustedProxies,
		Paths: installation.Paths{
			Database: *database, WispistData: *wispistData, AuthKey: *authKey,
		},
		UpdateData: *updateData, UpdateManifestURL: *updateManifestURL,
		UpdatePublicKey: *updatePublicKey, UpdatePublicKeyFile: *updatePublicKeyFile,
		Executable: *executable,
	})
	if err := writeDoctorReport(stdout, report, *jsonOutput); err != nil {
		return err
	}
	if report.Failures > 0 {
		return fmt.Errorf("production preflight failed with %d failed check(s)", report.Failures)
	}
	return nil
}

func inspectDoctor(ctx context.Context, config doctorConfig) doctorReport {
	var report doctorReport
	if version, err := updater.ParseVersion(config.Build.Version); err != nil {
		report.add("release build", doctorFail, err.Error())
	} else if config.Build.Commit == "" || config.Build.Commit == "unknown" ||
		config.Build.BuiltAt == "" || config.Build.BuiltAt == "unknown" {
		report.add("release build", doctorFail, "tagged build is missing source commit or UTC build time")
	} else if _, err := time.Parse(time.RFC3339, config.Build.BuiltAt); err != nil {
		report.add("release build", doctorFail, "build time is not RFC3339")
	} else {
		report.add("release build", doctorPass, version.String()+" from commit "+config.Build.Commit)
	}

	origin, err := url.Parse(config.AppOrigin)
	if err != nil {
		report.add("origin boundary", doctorFail, "parse application origin: "+err.Error())
	} else {
		siteDomain, previewDomain, originErr := web.ResolveOriginConfiguration(
			origin, config.SiteDomain, config.PreviewDomain, false,
		)
		if originErr != nil {
			report.add("origin boundary", doctorFail, originErr.Error())
		} else {
			report.add(
				"origin boundary", doctorPass,
				fmt.Sprintf("application=%s sites=*.%s previews=*.%s", origin.Host, siteDomain, previewDomain),
			)
		}
	}

	if len(config.TrustedProxies) == 0 {
		report.add("trusted proxies", doctorWarn, "none configured; forwarded client addresses will be ignored")
	} else if err := validateDoctorProxies(config.TrustedProxies); err != nil {
		report.add("trusted proxies", doctorFail, err.Error())
	} else {
		report.add("trusted proxies", doctorPass, fmt.Sprintf("%d explicit CIDR(s)", len(config.TrustedProxies)))
	}

	if directories, err := inspectStateDirectories(config.Paths); err != nil {
		report.add("state directories", doctorFail, err.Error())
	} else {
		report.add(
			"state directories", doctorPass,
			fmt.Sprintf("%d state parent location(s) reject untrusted writes", directories),
		)
	}

	if err := inspectPrivateRegular(config.Paths.AuthKey); err != nil {
		report.add("authentication key", doctorFail, err.Error())
	} else if _, err := auth.LoadInstallationKey(config.Paths.AuthKey); err != nil {
		report.add("authentication key", doctorFail, err.Error())
	} else {
		report.add("authentication key", doctorPass, "valid owner-only installation key")
	}

	if err := inspectPrivateRegular(config.Paths.Database); err != nil {
		report.add("control database", doctorFail, err.Error())
	} else if err := installation.CheckSQLite(ctx, config.Paths.Database, store.SchemaVersion); err != nil {
		report.add("control database", doctorFail, err.Error())
	} else {
		report.add("control database", doctorPass, "integrity, foreign keys and schema are compatible")
	}

	if databases, warning, err := inspectWispistData(ctx, config.Paths.WispistData); err != nil {
		report.add("Wispist data", doctorFail, err.Error())
	} else if warning != "" {
		report.add("Wispist data", doctorWarn, warning)
	} else {
		report.add("Wispist data", doctorPass, fmt.Sprintf("%d database(s) are compatible", databases))
	}

	updateDirectory, err := updater.ValidateDataDirectory(config.UpdateData, config.Paths)
	if err != nil {
		report.add("update data", doctorFail, err.Error())
	} else if err := inspectPrivateCreatableDirectory(updateDirectory); err != nil {
		report.add("update data", doctorFail, err.Error())
	} else {
		report.add("update data", doctorPass, updateDirectory)
	}

	client, err := configuredUpdateClientFor(
		config.Build, config.UpdateManifestURL, config.UpdatePublicKey,
		config.UpdatePublicKeyFile, false,
	)
	if err != nil {
		report.add("signed updates", doctorFail, err.Error())
	} else if client == nil {
		report.add("signed updates", doctorWarn, "no release manifest and public key are configured")
	} else {
		report.add("signed updates", doctorPass, "stable HTTPS manifest and Ed25519 public key are configured")
	}

	if err := updater.CheckActivationSupport(config.Executable); err != nil {
		report.add("update activation", doctorFail, err.Error())
	} else {
		report.add("update activation", doctorPass, "executable directory permits atomic replacement")
	}
	return report
}

func validateDoctorProxies(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("trusted proxy %q is not a CIDR", value)
		}
		canonical := network.String()
		if _, duplicate := seen[canonical]; duplicate {
			return fmt.Errorf("trusted proxy %q is repeated", canonical)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func inspectPrivateRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%q is accessible by group or other users", path)
	}
	return nil
}

func inspectPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is not a real directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%q is accessible by group or other users", path)
	}
	return nil
}

func inspectStateDirectories(paths installation.Paths) (int, error) {
	directories := make(map[string]struct{})
	for _, path := range []string{paths.Database, paths.AuthKey, paths.WispistData} {
		directory, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return 0, fmt.Errorf("resolve state directory for %q: %w", path, err)
		}
		directories[directory] = struct{}{}
	}
	for directory := range directories {
		if err := inspectProtectedDirectory(directory); err != nil {
			return 0, err
		}
	}
	return len(directories), nil
}

func inspectPrivateCreatableDirectory(path string) error {
	target, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", path, err)
	}
	current := target
	for {
		_, err := os.Lstat(current)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %q: %w", current, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("no existing parent directory for %q", path)
		}
		current = parent
	}
	if current == target {
		if err := inspectPrivateDirectory(current); err != nil {
			return err
		}
	} else if err := inspectProtectedDirectory(current); err != nil {
		return err
	}
	if err := unix.Access(current, unix.W_OK|unix.X_OK); err != nil {
		return fmt.Errorf("update directory parent %q is not writable by this process: %w", current, err)
	}
	return nil
}

func inspectProtectedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q is not a real directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%q is writable by group or other users", path)
	}
	return nil
}

func inspectWispistData(ctx context.Context, directory string) (int, string, error) {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "directory does not exist yet; it will be created on first use", nil
	}
	if err != nil {
		return 0, "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("Wispist data path is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return 0, "", errors.New("Wispist data directory is accessible by group or other users")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, "", err
	}
	databases := 0
	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = struct{}{}
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".db-wal") || strings.HasSuffix(name, ".db-shm") {
			path := filepath.Join(directory, name)
			if err := inspectPrivateRegular(path); err != nil {
				return 0, "", err
			}
			base := strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm")
			if _, exists := names[base]; !exists {
				return 0, "", fmt.Errorf("Wispist state %q has no matching database", name)
			}
			continue
		}
		if !strings.HasSuffix(name, ".db") {
			return 0, "", fmt.Errorf("unexpected file in Wispist data directory: %q", name)
		}
		path := filepath.Join(directory, name)
		if err := inspectPrivateRegular(path); err != nil {
			return 0, "", err
		}
		if err := installation.CheckSQLite(ctx, path, wispistsqlite.SchemaVersion); err != nil {
			return 0, "", fmt.Errorf("check Wispist database %q: %w", name, err)
		}
		databases++
	}
	return databases, "", nil
}

func writeDoctorReport(output io.Writer, report doctorReport, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(report)
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(output, "%-4s  %-20s %s\n", strings.ToUpper(string(check.Status)), check.Name, check.Detail); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "\n%d failed, %d warning(s).\n", report.Failures, report.Warnings)
	return err
}
