package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wispdeck/wispdeck/internal/buildinfo"
)

type ClientConfig struct {
	ManifestURL     string
	PublicKey       ed25519.PublicKey
	Current         buildinfo.Info
	HTTPClient      *http.Client
	AllowHTTP       bool
	GOOS            string
	GOARCH          string
	VerifyCandidate func(context.Context, string, string) error
}

type Client struct {
	config ClientConfig
}

func NewClient(config ClientConfig) (*Client, error) {
	manifestURL, err := url.Parse(config.ManifestURL)
	if err != nil || manifestURL.User != nil || manifestURL.Host == "" || manifestURL.Fragment != "" ||
		(manifestURL.Scheme != "https" && !(config.AllowHTTP && manifestURL.Scheme == "http")) {
		return nil, errors.New("update manifest URL is invalid")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("update public key is invalid")
	}
	if _, err := ParseVersion(config.Current.Version); err != nil {
		return nil, errors.New("development or invalid builds cannot be updated")
	}
	if config.GOOS == "" {
		config.GOOS = runtime.GOOS
	}
	if config.GOARCH == "" {
		config.GOARCH = runtime.GOARCH
	}
	if config.HTTPClient == nil {
		config.HTTPClient = secureHTTPClient(config.AllowHTTP)
	}
	if config.VerifyCandidate == nil {
		config.VerifyCandidate = verifyCandidate
	}
	return &Client{config: config}, nil
}

func secureHTTPClient(allowHTTP bool) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many update redirects")
			}
			if request.URL.User != nil || (request.URL.Scheme != "https" && !(allowHTTP && request.URL.Scheme == "http")) {
				return errors.New("unsafe update redirect")
			}
			return nil
		},
	}
}

func (c *Client) Check(ctx context.Context) (Release, bool, error) {
	body, err := c.fetch(ctx, c.config.ManifestURL, MaxManifestBytes)
	if err != nil {
		return Release{}, false, err
	}
	manifest, err := VerifyEnvelope(body, c.config.PublicKey, c.config.AllowHTTP)
	if err != nil {
		return Release{}, false, err
	}
	if _, err := manifest.Release.AssetFor(c.config.GOOS, c.config.GOARCH); err != nil {
		return Release{}, false, err
	}
	current, _ := ParseVersion(c.config.Current.Version)
	latest, _ := ParseVersion(manifest.Release.Version)
	return manifest.Release, latest.Compare(current) > 0, nil
}

func (c *Client) Stage(ctx context.Context, release Release, directory string) (string, error) {
	asset, err := release.AssetFor(c.config.GOOS, c.config.GOARCH)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create update staging directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("restrict update staging directory: %w", err)
	}
	destination := filepath.Join(directory, fmt.Sprintf("wispdeck-%s-%s-%s", release.Version, asset.OS, asset.Arch))
	if err := verifyFile(destination, asset); err == nil {
		if err := c.config.VerifyCandidate(ctx, destination, release.Version); err != nil {
			return "", err
		}
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect existing staged update: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "Wispdeck/"+c.config.Current.Version)
	response, err := c.config.HTTPClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download release asset: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download release asset: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > asset.Size {
		return "", errors.New("release asset exceeds its signed size")
	}
	temporary, err := os.CreateTemp(directory, ".wispdeck-download-")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o700); err != nil {
		return "", err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, asset.Size+1))
	if copyErr != nil || written != asset.Size || hex.EncodeToString(hasher.Sum(nil)) != asset.SHA256 {
		return "", errors.New("downloaded release asset does not match its signed size and checksum")
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := c.config.VerifyCandidate(ctx, temporaryPath, release.Version); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return "", err
	}
	complete = true
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	return destination, nil
}

func (c *Client) fetch(ctx context.Context, source string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Wispdeck/"+c.config.Current.Version)
	response, err := c.config.HTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch update manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch update manifest: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, errors.New("update manifest is too large")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, errors.New("update manifest is too large")
	}
	return body, nil
}

func verifyFile(path string, asset Asset) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != asset.Size {
		return errors.New("staged update has an unexpected type or size")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != asset.SHA256 {
		return errors.New("staged update checksum is invalid")
	}
	return nil
}

func verifyCandidate(ctx context.Context, path, expectedVersion string) error {
	verifyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(verifyContext, path, "version", "--json")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("execute staged update: %w", err)
	}
	if len(output) > 16<<10 {
		return errors.New("staged update returned excessive version output")
	}
	var info buildinfo.Info
	if err := decodeStrict(output, &info); err != nil || info.Version != expectedVersion {
		return fmt.Errorf("staged update identifies as %q instead of %q", info.Version, expectedVersion)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
