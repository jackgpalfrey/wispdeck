package wispist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var errInvalidJSON = errors.New("invalid JSON object")

func normalizeJSONObject(raw []byte, maxBytes, maxDepth, maxKeyBytes int) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return nil, errInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return nil, errInvalidJSON
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return nil, errInvalidJSON
	}
	if err := consumeJSONObject(decoder, 1, maxDepth, maxKeyBytes); err != nil {
		return nil, errInvalidJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalidJSON
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || compact.Len() > maxBytes {
		return nil, errInvalidJSON
	}
	return append(json.RawMessage(nil), compact.Bytes()...), nil
}

func consumeJSONObject(decoder *json.Decoder, depth, maxDepth, maxKeyBytes int) error {
	if depth > maxDepth {
		return errInvalidJSON
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errInvalidJSON
		}
		key, ok := token.(string)
		if !ok || len(key) > maxKeyBytes {
			return errInvalidJSON
		}
		if _, duplicate := seen[key]; duplicate {
			return errInvalidJSON
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(decoder, depth+1, maxDepth, maxKeyBytes); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('}') {
		return errInvalidJSON
	}
	return nil
}

func consumeJSONArray(decoder *json.Decoder, depth, maxDepth, maxKeyBytes int) error {
	if depth > maxDepth {
		return errInvalidJSON
	}
	for decoder.More() {
		if err := consumeJSONValue(decoder, depth+1, maxDepth, maxKeyBytes); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim(']') {
		return errInvalidJSON
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth, maxDepth, maxKeyBytes int) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidJSON
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder, depth, maxDepth, maxKeyBytes)
	case '[':
		return consumeJSONArray(decoder, depth, maxDepth, maxKeyBytes)
	default:
		return errInvalidJSON
	}
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
