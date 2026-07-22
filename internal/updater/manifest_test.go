package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/buildinfo"
)

func TestSignedManifestCheckAndStage(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("signed release binary")
	digest := sha256.Sum256(binary)
	manifestBody, err := SignManifest(Manifest{
		Format: ManifestFormat, Version: ProtocolVersion,
		Release: Release{
			Version: "v1.1.0", PublishedAt: time.Now().UTC(), Notes: "A careful release.",
			Assets: []Asset{{
				OS: "testos", Arch: "testarch", URL: "https://updates.example/wispdeck",
				SHA256: hex.EncodeToString(digest[:]), Size: int64(len(binary)),
			}},
		},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body []byte
		switch request.URL.Path {
		case "/manifest.json":
			body = manifestBody
		case "/wispdeck":
			body = binary
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: request}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(string(body))),
			Header: make(http.Header), Request: request,
		}, nil
	})}
	client, err := NewClient(ClientConfig{
		ManifestURL: "https://updates.example/manifest.json", PublicKey: publicKey,
		Current: buildinfo.Info{Version: "v1.0.0"}, HTTPClient: httpClient,
		GOOS: "testos", GOARCH: "testarch",
		VerifyCandidate: func(_ context.Context, path, version string) error {
			if version != "v1.1.0" {
				t.Fatalf("candidate version = %q", version)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	release, available, err := client.Check(context.Background())
	if err != nil || !available || release.Version != "v1.1.0" {
		t.Fatalf("Check() = (%+v, %t, %v)", release, available, err)
	}
	path, err := client.Stage(context.Background(), release, filepath.Join(t.TempDir(), "updates"))
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(path)
	if err != nil || string(staged) != string(binary) {
		t.Fatalf("staged = %q, %v", staged, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("staged mode = %v", info.Mode())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestSignedManifestRejectsTamperingAndPrereleases(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("binary"))
	valid := Manifest{
		Format: ManifestFormat, Version: ProtocolVersion,
		Release: Release{
			Version: "v2.0.0", PublishedAt: time.Now().UTC(),
			Assets: []Asset{{OS: "linux", Arch: "amd64", URL: "https://example.test/wispdeck", SHA256: hex.EncodeToString(digest[:]), Size: 6}},
		},
	}
	body, err := SignManifest(valid, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if _, err := VerifyEnvelope(body, publicKey, false); err == nil {
		t.Fatal("verified a tampered envelope")
	}
	valid.Release.Version = "v2.0.0-rc1"
	if _, err := SignManifest(valid, privateKey); err == nil {
		t.Fatal("signed a prerelease manifest")
	}
}
