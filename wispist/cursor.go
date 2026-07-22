package wispist

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

type portableChangeCursor struct {
	Namespace string `json:"n"`
	Sequence  uint64 `json:"s"`
}

func EncodeChangeCursor(namespace string, sequence uint64) string {
	encoded, err := json.Marshal(portableChangeCursor{
		Namespace: cursorNamespaceDigest(namespace), Sequence: sequence,
	})
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func DecodeChangeCursor(namespace, value string) (uint64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > 512 {
		return 0, ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor portableChangeCursor
	if err := decoder.Decode(&cursor); err != nil || cursor.Namespace != cursorNamespaceDigest(namespace) {
		return 0, ErrInvalidCursor
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return 0, ErrInvalidCursor
	}
	return cursor.Sequence, nil
}

func cursorNamespaceDigest(namespace string) string {
	digest := sha256.Sum256([]byte(namespace))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}
