package site

import (
	"archive/zip"
	"bytes"
	"errors"
	"testing"
)

func TestReadZIPBuildsDeterministicSafeBundle(t *testing.T) {
	first := zipBytes(t, map[string]string{
		"assets/app.js": "console.log('hello')",
		"index.html":    "<!doctype html><h1>Hello</h1>",
	})
	second := zipBytes(t, map[string]string{
		"index.html":    "<!doctype html><h1>Hello</h1>",
		"assets/app.js": "console.log('hello')",
	})
	bundle, err := ReadZIP(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ReadZIP(bytes.NewReader(second), int64(len(second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Files) != 2 || bundle.Files[0].Path != "assets/app.js" || bundle.Files[1].Path != "index.html" {
		t.Fatalf("bundle files = %#v", bundle.Files)
	}
	if bundle.Digest != other.Digest {
		t.Fatal("bundle digest depends on ZIP entry order")
	}
	if bundle.Files[1].ContentType != "text/html; charset=utf-8" {
		t.Fatalf("index content type = %q", bundle.Files[1].ContentType)
	}
}

func TestReadZIPRejectsUnsafeAndAmbiguousArchives(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		err   error
	}{
		{name: "missing index", files: map[string]string{"app.js": "x"}, err: ErrInvalidBundle},
		{name: "traversal", files: map[string]string{"index.html": "x", "../secret": "x"}, err: ErrInvalidFile},
		{name: "backslash", files: map[string]string{"index.html": "x", `assets\app.js`: "x"}, err: ErrInvalidFile},
		{name: "reserved", files: map[string]string{"index.html": "x", "_wispdeck/data": "x"}, err: ErrInvalidFile},
		{name: "case collision", files: map[string]string{"index.html": "x", "A.js": "x", "a.js": "y"}, err: ErrInvalidFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := zipBytes(t, test.files)
			_, err := ReadZIP(bytes.NewReader(data), int64(len(data)))
			if !errors.Is(err, test.err) {
				t.Fatalf("ReadZIP error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestValidateBundleRejectsTampering(t *testing.T) {
	data := zipBytes(t, map[string]string{"index.html": "hello"})
	bundle, err := ReadZIP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Bundle)
		err    error
	}{
		{
			name: "file digest",
			mutate: func(value *Bundle) {
				value.Files[0].Digest[0] ^= 0xff
			},
			err: ErrInvalidFile,
		},
		{
			name: "bundle digest",
			mutate: func(value *Bundle) {
				value.Digest[0] ^= 0xff
			},
			err: ErrInvalidBundle,
		},
		{
			name: "response header",
			mutate: func(value *Bundle) {
				value.Files[0].ContentType = "text/html\r\nSet-Cookie: bad=1"
			},
			err: ErrInvalidFile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := bundle
			value.Files = append([]File(nil), bundle.Files...)
			test.mutate(&value)
			if err := ValidateBundle(value); !errors.Is(err, test.err) {
				t.Fatalf("ValidateBundle error = %v, want %v", err, test.err)
			}
		})
	}
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, contents := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
