package wispist

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestParseDeclarationExpandsSharedProfile(t *testing.T) {
	t.Parallel()
	declaration, err := ParseDeclaration([]byte(`{
		"version":1,
		"collections":{"before-you-go":{"access":"shared","limits":{"maxDocuments":250,"maxDocumentBytes":4096}}}
	}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	policy := declaration.Collections["before-you-go"]
	if policy.MaxDocuments != 250 || policy.MaxDocumentBytes != 4096 {
		t.Fatalf("limits = %d documents, %d bytes", policy.MaxDocuments, policy.MaxDocumentBytes)
	}
	for _, operation := range allOperations {
		if policy.Access[operation] != AccessAnyone {
			t.Fatalf("access[%s] = %q, want anyone", operation, policy.Access[operation])
		}
	}
}

func TestParseDeclarationRejectsAmbiguousOrInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate key", body: `{"version":1,"version":1,"collections":{}}`},
		{name: "unknown field", body: `{"version":1,"collections":{},"secret":true}`},
		{name: "unsupported version", body: `{"version":2,"collections":{}}`},
		{name: "missing collections", body: `{"version":1}`},
		{name: "invalid collection", body: `{"version":1,"collections":{"_private":{"access":"shared"}}}`},
		{name: "unknown profile", body: `{"version":1,"collections":{"items":{"access":"public"}}}`},
		{name: "partial access", body: `{"version":1,"collections":{"items":{"access":{"read":"anyone"}}}}`},
		{name: "unknown access value", body: `{"version":1,"collections":{"items":{"access":{"list":"anyone","read":"anyone","create":"anyone","update":"anyone","delete":"anyone","subscribe":"sometimes"}}}}`},
		{name: "raises limit", body: `{"version":1,"collections":{"items":{"access":"shared","limits":{"maxDocuments":1001}}}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDeclaration([]byte(test.body), DefaultLimits())
			if !errors.Is(err, ErrInvalidDeclaration) {
				t.Fatalf("error = %v, want ErrInvalidDeclaration", err)
			}
		})
	}
}

func TestNormalizeJSONObjectRejectsDuplicateKeysAndExcessiveDepth(t *testing.T) {
	t.Parallel()
	if _, err := normalizeJSONObject([]byte(`{"outer":{"same":1,"same":2}}`), 1024, 32, 256); err == nil {
		t.Fatal("duplicate nested key accepted")
	}
	deep := `{"value":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`
	if _, err := normalizeJSONObject([]byte(deep), 1024, 32, 256); err == nil {
		t.Fatal("excessively nested JSON accepted")
	}
	if normalized, err := normalizeJSONObject([]byte(" { \"ok\" : [true, null] } \n"), 1024, 32, 256); err != nil {
		t.Fatal(err)
	} else if string(normalized) != `{"ok":[true,null]}` {
		t.Fatalf("normalized = %s", normalized)
	}
}

func TestChangeCursorRejectsNamespaceMismatchAndTrailingData(t *testing.T) {
	t.Parallel()
	cursor := EncodeChangeCursor("live", 42)
	if sequence, err := DecodeChangeCursor("live", cursor); err != nil || sequence != 42 {
		t.Fatalf("DecodeChangeCursor = %d, %v", sequence, err)
	}
	if _, err := DecodeChangeCursor("draft", cursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("namespace mismatch error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	trailing := base64.RawURLEncoding.EncodeToString(append(raw, []byte(`{}`)...))
	if _, err := DecodeChangeCursor("live", trailing); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("trailing-data error = %v", err)
	}
}
