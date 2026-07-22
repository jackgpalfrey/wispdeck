package wispist_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/wispdeck/wispdeck/wispist"
)

func TestEngineHostAdministrationLifecycle(t *testing.T) {
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	created := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/passport", `{"data":{"done":false}}`, map[string]string{
		"Content-Type": "application/json", "Origin": fixture.binding.Origin, "If-None-Match": "*",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create = (%d, %q)", created.Code, created.Body.String())
	}
	var document wireDocument
	if err := json.Unmarshal(created.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	ref := wispist.NamespaceRef{StoreKey: fixture.binding.StoreKey, Namespace: fixture.binding.Namespace}

	usage, err := fixture.engine.NamespaceUsage(context.Background(), ref)
	if err != nil || usage.Documents != 1 || len(usage.Collections) != 1 || usage.Collections[0].Name != "items" {
		t.Fatalf("usage = (%+v, %v)", usage, err)
	}
	page, err := fixture.engine.ListNamespaceDocuments(context.Background(), ref, "items", 50, "")
	if err != nil || len(page.Documents) != 1 || page.Documents[0].ID != "passport" {
		t.Fatalf("list = (%+v, %v)", page, err)
	}
	replaced, err := fixture.engine.ReplaceNamespaceDocument(
		context.Background(), ref, "items", "passport", document.Revision, []byte(`{"done":true}`),
	)
	if err != nil || string(replaced.Data) != `{"done":true}` || replaced.Revision == document.Revision {
		t.Fatalf("replace = (%+v, %v)", replaced, err)
	}
	if _, err := fixture.engine.ReplaceNamespaceDocument(
		context.Background(), ref, "items", "passport", replaced.Revision, []byte(`[]`),
	); !errors.Is(err, wispist.ErrInvalidDocumentData) {
		t.Fatalf("invalid replacement error = %v", err)
	}
	draftFixture := fixture
	draftFixture.binding.Namespace = "draft"
	draftCreated := draftFixture.request(
		http.MethodPut, "/_wispist/v1/collections/items/documents/hotel",
		`{"data":{"booked":true}}`, map[string]string{
			"Content-Type": "application/json", "Origin": fixture.binding.Origin, "If-None-Match": "*",
		},
	)
	if draftCreated.Code != http.StatusCreated {
		t.Fatalf("create draft = (%d, %q)", draftCreated.Code, draftCreated.Body.String())
	}
	snapshots, err := fixture.engine.NamespaceSnapshots(context.Background(), []wispist.NamespaceRef{
		ref,
		{StoreKey: fixture.binding.StoreKey, Namespace: "draft"},
	})
	if err != nil || len(snapshots["live"].Collections["items"]) != 1 ||
		string(snapshots["live"].Collections["items"][0].Data) != `{"done":true}` ||
		len(snapshots["draft"].Collections["items"]) != 1 {
		t.Fatalf("snapshots = (%+v, %v)", snapshots, err)
	}
	cleared, err := fixture.engine.ClearNamespaceCollection(context.Background(), ref, "items")
	if err != nil || cleared != 1 {
		t.Fatalf("clear = (%d, %v)", cleared, err)
	}
	if err := fixture.engine.PurgeNamespace(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	usage, err = fixture.engine.NamespaceUsage(context.Background(), ref)
	if err != nil || usage.Documents != 0 || usage.Bytes != 0 {
		t.Fatalf("purged usage = (%+v, %v)", usage, err)
	}
}
