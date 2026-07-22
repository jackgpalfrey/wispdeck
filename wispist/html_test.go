package wispist

import (
	"bytes"
	"strings"
	"testing"
)

func htmlTestBinding() Binding {
	return Binding{
		StoreKey: "site", Namespace: "live", Origin: "https://example.test", ClientKey: "client",
		Principal: Principal{Kind: PrincipalAnonymous}, Declaration: EmptyDeclaration(), Mode: ModeLive,
	}
}

func TestTransformHTMLInjectsBootstrapFirstInHead(t *testing.T) {
	t.Parallel()
	engine := &Engine{limits: DefaultLimits()}
	body := []byte(`<!doctype html><html><head><meta charset="utf-8"><script src="app.js"></script></head><body>Hi</body></html>`)
	result, err := engine.TransformHTML(htmlTestBinding(), body)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := `<head><script src="/_wispist/client/v1.js" data-wispist-bootstrap data-wispist-mode="live" data-wispist-read-only="false"></script><meta`
	if !strings.Contains(string(result), bootstrap) {
		t.Fatalf("bootstrap was not first in head: %s", result)
	}
}

func TestTransformHTMLAddsMissingHead(t *testing.T) {
	t.Parallel()
	engine := &Engine{limits: DefaultLimits()}
	for _, body := range [][]byte{
		[]byte(`<!doctype html><html><body>Hi</body></html>`),
		[]byte(`<main>fragment</main>`),
	} {
		result, err := engine.TransformHTML(htmlTestBinding(), body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(result, []byte(`data-wispist-bootstrap`)) != 1 || !bytes.Contains(result, []byte(`<head>`)) {
			t.Fatalf("unexpected transformed HTML: %s", result)
		}
	}
}

func TestTransformHTMLOnlyKeepsCanonicalLeadingBootstrap(t *testing.T) {
	t.Parallel()
	engine := &Engine{limits: DefaultLimits()}
	canonical := []byte(`<html><head><script src="/_wispist/client/v1.js" data-wispist-bootstrap data-wispist-mode="live" data-wispist-read-only="false"></script><script src="app.js"></script></head></html>`)
	result, err := engine.TransformHTML(htmlTestBinding(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, canonical) {
		t.Fatalf("canonical bootstrap changed: %s", result)
	}

	lookalike := []byte(`<html><head><script src="app.js"></script><script src="/_wispist/client/v1.js" data-wispist-bootstrap data-wispist-mode="draft" data-wispist-read-only="false"></script></head></html>`)
	result, err = engine.TransformHTML(htmlTestBinding(), lookalike)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(result, []byte(`data-wispist-bootstrap`)) != 2 || !bytes.Contains(result, []byte(`<head><script src="/_wispist/client/v1.js"`)) {
		t.Fatalf("lookalike suppressed canonical bootstrap: %s", result)
	}
}
