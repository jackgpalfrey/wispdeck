package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	EnvelopeFormat   = "wispdeck-signed-update"
	ManifestFormat   = "wispdeck-update"
	ProtocolVersion  = 1
	MaxManifestBytes = 1 << 20
	MaxReleaseBytes  = 200 << 20
	MaxReleaseNotes  = 64 << 10
)

type Envelope struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	Signed    string `json:"signed"`
	Signature string `json:"signature"`
}

type Manifest struct {
	Format  string  `json:"format"`
	Version int     `json:"version"`
	Release Release `json:"release"`
}

type Release struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"publishedAt"`
	Notes       string    `json:"notes"`
	Assets      []Asset   `json:"assets"`
}

type Asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("decode update public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update public key must contain %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func VerifyEnvelope(body []byte, publicKey ed25519.PublicKey, allowHTTP bool) (Manifest, error) {
	if len(body) == 0 || len(body) > MaxManifestBytes {
		return Manifest{}, errors.New("update manifest envelope size is invalid")
	}
	var envelope Envelope
	if err := decodeStrict(body, &envelope); err != nil {
		return Manifest{}, fmt.Errorf("decode update envelope: %w", err)
	}
	if envelope.Format != EnvelopeFormat || envelope.Version != ProtocolVersion {
		return Manifest{}, errors.New("update manifest envelope identity is invalid")
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(envelope.Signed)
	if err != nil || len(signed) == 0 || len(signed) > MaxManifestBytes {
		return Manifest{}, errors.New("update manifest signed payload is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Manifest{}, errors.New("update manifest signature encoding is invalid")
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, signed, signature) {
		return Manifest{}, errors.New("update manifest signature is invalid")
	}
	var manifest Manifest
	if err := decodeStrict(signed, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode signed update manifest: %w", err)
	}
	if err := validateManifest(manifest, allowHTTP); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	if err := validateManifest(manifest, false); err != nil {
		return nil, err
	}
	signed, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	envelope := Envelope{
		Format: EnvelopeFormat, Version: ProtocolVersion,
		Signed:    base64.StdEncoding.EncodeToString(signed),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed)),
	}
	body, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func validateManifest(manifest Manifest, allowHTTP bool) error {
	if manifest.Format != ManifestFormat || manifest.Version != ProtocolVersion {
		return errors.New("signed update manifest identity is invalid")
	}
	if _, err := ParseVersion(manifest.Release.Version); err != nil {
		return fmt.Errorf("invalid release version: %w", err)
	}
	if manifest.Release.PublishedAt.IsZero() || len(manifest.Release.Notes) > MaxReleaseNotes {
		return errors.New("release metadata is invalid")
	}
	if len(manifest.Release.Assets) == 0 || len(manifest.Release.Assets) > 32 {
		return errors.New("release asset count is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Release.Assets))
	for _, asset := range manifest.Release.Assets {
		if asset.OS == "" || asset.Arch == "" || len(asset.OS) > 32 || len(asset.Arch) > 32 {
			return errors.New("release asset platform is invalid")
		}
		for _, value := range []string{asset.OS, asset.Arch} {
			for _, char := range []byte(value) {
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
					return errors.New("release asset platform is invalid")
				}
			}
		}
		key := asset.OS + "/" + asset.Arch
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("release repeats asset platform %q", key)
		}
		seen[key] = struct{}{}
		parsedURL, err := url.Parse(asset.URL)
		if err != nil || parsedURL.User != nil || parsedURL.Host == "" || parsedURL.Fragment != "" ||
			(parsedURL.Scheme != "https" && !(allowHTTP && parsedURL.Scheme == "http")) {
			return fmt.Errorf("release asset URL for %s is invalid", key)
		}
		digest, err := hex.DecodeString(asset.SHA256)
		if err != nil || len(digest) != 32 || strings.ToLower(asset.SHA256) != asset.SHA256 {
			return fmt.Errorf("release asset checksum for %s is invalid", key)
		}
		if asset.Size < 1 || asset.Size > MaxReleaseBytes {
			return fmt.Errorf("release asset size for %s is invalid", key)
		}
	}
	return nil
}

func (r Release) AssetFor(goos, goarch string) (Asset, error) {
	for _, asset := range r.Assets {
		if asset.OS == goos && asset.Arch == goarch {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("release %s has no asset for %s/%s", r.Version, goos, goarch)
}

func decodeStrict(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
