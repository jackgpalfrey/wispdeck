// wispdeck-release creates the offline signing key and signed manifest used by
// Wispdeck's tagged-release updater. It is an operator tool, not a server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wispdeck/wispdeck/internal/updater"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "wispdeck-release:", err)
		os.Exit(1)
	}
}

const usage = `Usage:
  wispdeck-release keygen --private FILE --public FILE
  wispdeck-release manifest --private-key FILE --version vMAJOR.MINOR.PATCH \
    --notes FILE --asset GOOS/GOARCH,FILE,HTTPS_URL [--asset ...] --output FILE
`

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(usage))
	}
	switch args[0] {
	case "keygen":
		return generateKey(args[1:], stdout)
	case "manifest":
		return createManifest(args[1:], stdout)
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, usage)
		return nil
	default:
		return errors.New(strings.TrimSpace(usage))
	}
}

func generateKey(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := flags.String("private", "", "new private signing-key path")
	publicPath := flags.String("public", "", "new public verification-key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *publicPath == "" || filepath.Clean(*privatePath) == filepath.Clean(*publicPath) {
		return errors.New("keygen requires distinct --private and --public paths")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 key: %w", err)
	}
	if err := writeExclusive(*privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeExclusive(*publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key (private key was already created): %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Created signing key %q and public key %q. Keep the signing key offline or in CI secrets.\n", *privatePath, *publicPath)
	return err
}

type assetFlags []string

func (values *assetFlags) String() string { return strings.Join(*values, ";") }
func (values *assetFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func createManifest(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	privatePath := flags.String("private-key", "", "base64 Ed25519 private-key file")
	version := flags.String("version", "", "stable release tag")
	notesPath := flags.String("notes", "", "UTF-8 release-notes file")
	outputPath := flags.String("output", "", "new signed manifest path")
	published := flags.String("published-at", "", "RFC3339 publication time (defaults to now)")
	var assets assetFlags
	flags.Var(&assets, "asset", "GOOS/GOARCH,FILE,HTTPS_URL (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *version == "" || *notesPath == "" || *outputPath == "" || len(assets) == 0 {
		return errors.New("manifest requires --private-key, --version, --notes, at least one --asset, and --output")
	}
	privateKey, err := readPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	notes, err := readSmallRegular(*notesPath, updater.MaxReleaseNotes)
	if err != nil {
		return fmt.Errorf("read release notes: %w", err)
	}
	if !utf8.Valid(notes) {
		return errors.New("release notes must be valid UTF-8")
	}
	publishedAt := time.Now().UTC()
	if *published != "" {
		publishedAt, err = time.Parse(time.RFC3339, *published)
		if err != nil {
			return fmt.Errorf("parse publication time: %w", err)
		}
	}
	releaseAssets := make([]updater.Asset, 0, len(assets))
	for _, encoded := range assets {
		parts := strings.SplitN(encoded, ",", 3)
		platform := strings.Split(parts[0], "/")
		if len(parts) != 3 || len(platform) != 2 || platform[0] == "" || platform[1] == "" {
			return fmt.Errorf("invalid --asset %q", encoded)
		}
		info, digest, err := hashRegular(parts[1])
		if err != nil {
			return fmt.Errorf("inspect asset %q: %w", parts[1], err)
		}
		releaseAssets = append(releaseAssets, updater.Asset{
			OS: platform[0], Arch: platform[1], URL: parts[2],
			SHA256: digest, Size: info.Size(),
		})
	}
	body, err := updater.SignManifest(updater.Manifest{
		Format: updater.ManifestFormat, Version: updater.ProtocolVersion,
		Release: updater.Release{
			Version: *version, PublishedAt: publishedAt.UTC(), Notes: string(notes), Assets: releaseAssets,
		},
	}, privateKey)
	if err != nil {
		return fmt.Errorf("sign release manifest: %w", err)
	}
	if err := writeExclusive(*outputPath, body, 0o644); err != nil {
		return fmt.Errorf("write release manifest: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Created signed manifest %q for %s with %d assets.\n", *outputPath, *version, len(releaseAssets))
	return err
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, errors.New("private key must be a small owner-only regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("private key encoding is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

func readSmallRegular(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(maximum) {
		return nil, errors.New("path is not a suitably sized regular file")
	}
	return os.ReadFile(path)
}

func hashRegular(path string) (os.FileInfo, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > updater.MaxReleaseBytes {
		return nil, "", errors.New("asset is not a suitably sized regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, "", err
	}
	return info, hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeExclusive(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
