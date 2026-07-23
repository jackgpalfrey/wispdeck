package web

import (
	"strings"
	"testing"
)

func TestAdminStylesheetUsesTouchSafeFormTextSize(t *testing.T) {
	t.Parallel()

	stylesheet, err := files.ReadFile("assets/admin.css")
	if err != nil {
		t.Fatalf("read admin stylesheet: %v", err)
	}
	css := string(stylesheet)
	const touchQuery = "@media (any-pointer: coarse)"
	start := strings.Index(css, touchQuery)
	if start < 0 {
		t.Fatalf("admin stylesheet does not contain %q", touchQuery)
	}
	end := strings.Index(css[start:], "\n@media (max-width: 900px)")
	if end < 0 {
		t.Fatal("touch-safe form rules are not bounded before responsive layout rules")
	}
	touchRules := css[start : start+end]
	for _, required := range []string{
		`input[type="text"]`,
		`input[type="password"]`,
		`input[type="url"]`,
		"select,",
		"textarea {",
		"font-size: 16px;",
	} {
		if !strings.Contains(touchRules, required) {
			t.Fatalf("admin stylesheet does not contain touch-safe rule %q", required)
		}
	}
}

func TestViewportKeepsUserZoomAvailable(t *testing.T) {
	t.Parallel()

	layout, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("read shared layout: %v", err)
	}
	source := string(layout)
	if !strings.Contains(source, `content="width=device-width, initial-scale=1"`) {
		t.Fatal("shared viewport is missing responsive device sizing")
	}
	for _, forbidden := range []string{"maximum-scale", "user-scalable"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("shared viewport disables accessible zoom with %q", forbidden)
		}
	}
}
