package site

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

func ReadZIP(reader io.ReaderAt, size int64) (Bundle, error) {
	if reader == nil || size < 1 || size > MaxUploadBytes {
		return Bundle{}, ErrInvalidBundle
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return Bundle{}, ErrInvalidBundle
	}
	if len(archive.File) > MaxFiles*2 {
		return Bundle{}, ErrTooManyFiles
	}

	files := make([]File, 0, len(archive.File))
	seen := make(map[string]struct{}, len(archive.File))
	var total int64
	for _, zipped := range archive.File {
		if zipped.FileInfo().IsDir() {
			continue
		}
		if zipped.Flags&0x1 != 0 || !zipped.Mode().IsRegular() {
			return Bundle{}, fmt.Errorf("%w: %q is not a regular unencrypted file", ErrInvalidFile, zipped.Name)
		}
		name, err := normalizeFilePath(zipped.Name)
		if err != nil {
			return Bundle{}, err
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return Bundle{}, fmt.Errorf("%w: duplicate path %q", ErrInvalidFile, name)
		}
		seen[key] = struct{}{}
		if len(files) >= MaxFiles || zipped.UncompressedSize64 > MaxFileBytes {
			return Bundle{}, ErrBundleTooLarge
		}
		if zipped.UncompressedSize64 > uint64(MaxBundleBytes-int(total)) {
			return Bundle{}, ErrBundleTooLarge
		}
		body, err := readZipFile(zipped)
		if err != nil {
			return Bundle{}, err
		}
		if int64(len(body)) > MaxBundleBytes-total {
			return Bundle{}, ErrBundleTooLarge
		}
		digest := sha256.Sum256(body)
		files = append(files, File{
			Path: name, ContentType: contentType(name), Body: body, Digest: digest,
		})
		total += int64(len(body))
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	digest := calculateBundleDigest(files)
	bundle := Bundle{Files: files, TotalBytes: total, Digest: digest}
	if err := ValidateBundle(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func calculateBundleDigest(files []File) [32]byte {
	ordered := append([]File(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	hasher := sha256.New()
	for _, file := range ordered {
		_, _ = io.WriteString(hasher, file.Path)
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write(file.Digest[:])
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func normalizeFilePath(value string) (string, error) {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%w: invalid path %q", ErrInvalidFile, value)
	}
	clean := path.Clean(value)
	if clean == "." || clean != value || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: invalid path %q", ErrInvalidFile, value)
	}
	for _, char := range clean {
		if char < 0x20 || char == 0x7f {
			return "", fmt.Errorf("%w: invalid path %q", ErrInvalidFile, value)
		}
	}
	lower := strings.ToLower(clean)
	if lower == "_wispdeck" || strings.HasPrefix(lower, "_wispdeck/") {
		return "", fmt.Errorf("%w: path %q is reserved", ErrInvalidFile, value)
	}
	return clean, nil
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open ZIP file %q: %w", file.Name, err)
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read ZIP file %q: %w", file.Name, err)
	}
	if len(body) > MaxFileBytes {
		return nil, ErrBundleTooLarge
	}
	return body, nil
}

func contentType(name string) string {
	value := mime.TypeByExtension(strings.ToLower(path.Ext(name)))
	if value == "" {
		return "application/octet-stream"
	}
	return value
}
