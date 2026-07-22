package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/wispist"
)

func testMutationLimits() wispist.MutationLimits {
	return wispist.MutationLimits{
		MaxDocuments: 10, MaxDocumentBytes: 1024, MaxNamespaceBytes: 4096,
		MaxIdempotencyRecords: 100, ChangeRetentionEntries: 100,
		ChangeRetentionAge: 7 * 24 * time.Hour, IdempotencyRetention: 24 * time.Hour,
	}
}

func TestStoreDocumentLifecycleIdempotencyAndChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "wispist")
	factory, err := NewFactory(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = factory.Close() })
	if _, err := factory.Open(ctx, "site", false); !errors.Is(err, wispist.ErrStoreNotFound) {
		t.Fatalf("untouched store error = %v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created data directory: %v", err)
	}
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 13, 12, 0, 0, 123_000_000, time.UTC)
	fingerprint := sha256.Sum256([]byte("first request"))
	create := wispist.CreateRequest{
		Namespace: "live", Collection: "items", ID: "generated-one", Data: []byte(`{"done":false}`),
		IdempotencyKey: "1234567890abcdef", Fingerprint: fingerprint, Now: now, Limits: testMutationLimits(),
	}
	document, created, replay, err := store.Create(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	if replay || created.Sequence != 1 || created.Operation != wispist.ChangeCreate || document.ID != create.ID {
		t.Fatalf("unexpected create result: document=%+v change=%+v replay=%v", document, created, replay)
	}
	replayed, _, replay, err := store.Create(ctx, wispist.CreateRequest{
		Namespace: "live", Collection: "items", ID: "different-generated-id", Data: create.Data,
		IdempotencyKey: create.IdempotencyKey, Fingerprint: fingerprint, Now: now.Add(time.Minute), Limits: testMutationLimits(),
	})
	if err != nil || !replay || replayed.ID != document.ID || replayed.Revision != document.Revision {
		t.Fatalf("idempotent replay = %+v, replay %v, error %v", replayed, replay, err)
	}
	conflictingFingerprint := sha256.Sum256([]byte("different request"))
	create.Fingerprint = conflictingFingerprint
	if _, _, _, err := store.Create(ctx, create); !errors.Is(err, wispist.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error = %v", err)
	}

	selected, updated, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "passport", Data: []byte(`{"done":false}`),
		CreateOnly: true, Now: now.Add(2 * time.Minute), Limits: testMutationLimits(),
	})
	if err != nil || updated.Operation != wispist.ChangeCreate {
		t.Fatalf("selected create = %+v, %+v, %v", selected, updated, err)
	}
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: selected.ID, Data: []byte(`{"done":true}`),
		ExpectedRevision: "stale-revision-token", Now: now.Add(3 * time.Minute), Limits: testMutationLimits(),
	}); !errors.Is(err, wispist.ErrRevisionConflict) {
		t.Fatalf("stale replacement error = %v", err)
	}
	selected, updated, err = store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: selected.ID, Data: []byte(`{"done":true}`),
		ExpectedRevision: selected.Revision, Now: now.Add(3 * time.Minute), Limits: testMutationLimits(),
	})
	if err != nil || updated.Operation != wispist.ChangeUpdate {
		t.Fatalf("replacement = %+v, %+v, %v", selected, updated, err)
	}
	if _, err := store.Delete(ctx, wispist.DeleteRequest{
		Namespace: "live", Collection: "items", ID: selected.ID, ExpectedRevision: "stale-revision-token",
		Now: now.Add(4 * time.Minute), Limits: testMutationLimits(),
	}); !errors.Is(err, wispist.ErrRevisionConflict) {
		t.Fatalf("stale deletion error = %v", err)
	}
	deleted, err := store.Delete(ctx, wispist.DeleteRequest{
		Namespace: "live", Collection: "items", ID: selected.ID, ExpectedRevision: selected.Revision,
		Now: now.Add(4 * time.Minute), Limits: testMutationLimits(),
	})
	if err != nil || deleted.Operation != wispist.ChangeDelete {
		t.Fatalf("deletion = %+v, %v", deleted, err)
	}
	if _, err := store.Get(ctx, "live", "items", selected.ID); !errors.Is(err, wispist.ErrDocumentNotFound) {
		t.Fatalf("deleted read error = %v", err)
	}
	if _, err := store.Get(ctx, "draft", "items", document.ID); !errors.Is(err, wispist.ErrDocumentNotFound) {
		t.Fatalf("draft namespace leaked live data: %v", err)
	}

	changes, err := store.Changes(ctx, "live", []string{"items"}, wispist.EncodeChangeCursor("live", 0), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 4 || changes.Changes[0].Operation != wispist.ChangeCreate ||
		changes.Changes[3].Operation != wispist.ChangeDelete {
		t.Fatalf("changes = %+v", changes.Changes)
	}
}

func TestStoreAdministrativeUsageSnapshotClearAndPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	factory, err := NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = factory.Close() })
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	for index, value := range []struct {
		collection string
		id         string
		data       string
	}{
		{"items", "passport", `{"done":false}`},
		{"items", "tickets", `{"done":true}`},
		{"notes", "arrival", `{"text":"late"}`},
	} {
		if _, _, err := store.Put(ctx, wispist.PutRequest{
			Namespace: "live", Collection: value.collection, ID: value.id,
			Data: []byte(value.data), CreateOnly: true, Now: now.Add(time.Duration(index) * time.Second),
			Limits: testMutationLimits(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "draft", Collection: "items", ID: "hotel", Data: []byte(`{"booked":true}`),
		CreateOnly: true, Now: now.Add(10 * time.Second), Limits: testMutationLimits(),
	}); err != nil {
		t.Fatal(err)
	}
	usage, err := store.Usage(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	if usage.Documents != 3 || len(usage.Collections) != 2 || usage.Collections[0].Name != "items" ||
		usage.Collections[0].Documents != 2 || usage.Bytes != int64(len(`{"done":false}{"done":true}{"text":"late"}`)) {
		t.Fatalf("usage = %+v", usage)
	}
	snapshot, err := store.Snapshot(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Collections["items"]) != 2 || snapshot.Collections["items"][0].ID != "passport" ||
		len(snapshot.Collections["notes"]) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	snapshots, err := store.SnapshotNamespaces(ctx, []string{"live", "draft"})
	if err != nil || len(snapshots["live"].Collections["items"]) != 2 ||
		len(snapshots["draft"].Collections["items"]) != 1 ||
		snapshots["draft"].Collections["items"][0].ID != "hotel" {
		t.Fatalf("namespace snapshots = (%+v, %v)", snapshots, err)
	}
	changes, err := store.ClearCollection(ctx, wispist.ClearCollectionRequest{
		Namespace: "live", Collection: "items", Now: now.Add(time.Minute), Limits: testMutationLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].Operation != wispist.ChangeDelete || changes[1].Sequence <= changes[0].Sequence {
		t.Fatalf("clear changes = %+v", changes)
	}
	usage, err = store.Usage(ctx, "live")
	if err != nil || usage.Documents != 1 || len(usage.Collections) != 1 || usage.Collections[0].Name != "notes" {
		t.Fatalf("usage after clear = (%+v, %v)", usage, err)
	}
	if err := store.PurgeNamespace(ctx, "live"); err != nil {
		t.Fatal(err)
	}
	usage, err = store.Usage(ctx, "live")
	if err != nil || usage.Documents != 0 || len(usage.Collections) != 0 {
		t.Fatalf("usage after purge = (%+v, %v)", usage, err)
	}
	if cursor, err := store.HighWater(ctx, "live"); err != nil || cursor != wispist.EncodeChangeCursor("live", 0) {
		t.Fatalf("high water after purge = (%q, %v)", cursor, err)
	}
}

func TestStorePaginationUsesFirstPageWatermark(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	factory, err := NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	for index, id := range []string{"a", "b"} {
		if _, _, err := store.Put(ctx, wispist.PutRequest{
			Namespace: "live", Collection: "items", ID: id, Data: []byte(`{"value":true}`),
			CreateOnly: true, Now: now.Add(time.Duration(index) * time.Second), Limits: testMutationLimits(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.List(ctx, "live", "items", 1, "")
	if err != nil || len(first.Documents) != 1 || first.Documents[0].ID != "a" || first.After == "" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "c", Data: []byte(`{"value":true}`),
		CreateOnly: true, Now: now.Add(2 * time.Second), Limits: testMutationLimits(),
	}); err != nil {
		t.Fatal(err)
	}
	second, err := store.List(ctx, "live", "items", 1, first.After)
	if err != nil || len(second.Documents) != 1 || second.Documents[0].ID != "b" || second.After != "" || second.ChangeCursor != first.ChangeCursor {
		t.Fatalf("second page = %+v, %v", second, err)
	}
	forged := encodeCursor(paginationCursor{Namespace: "live", Collection: "items", Watermark: 99, Sequence: 1, ID: "a"})
	if _, err := store.List(ctx, "live", "items", 1, forged); !errors.Is(err, wispist.ErrInvalidCursor) {
		t.Fatalf("future pagination cursor error = %v", err)
	}
	if _, err := store.Changes(ctx, "live", []string{"items"}, wispist.EncodeChangeCursor("live", 99), 10); !errors.Is(err, wispist.ErrInvalidCursor) {
		t.Fatalf("future change cursor error = %v", err)
	}
}

func TestReplacementClampsTimestampAfterClockRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	factory, err := NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	createdAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	document, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "clock", Data: []byte(`{"value":1}`),
		CreateOnly: true, Now: createdAt, Limits: testMutationLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "clock", Data: []byte(`{"value":2}`),
		ExpectedRevision: document.Revision, Now: createdAt.Add(-time.Hour), Limits: testMutationLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.UpdatedAt.Equal(createdAt) || updated.UpdatedAt.Before(updated.CreatedAt) {
		t.Fatalf("timestamps after rollback = created %s, updated %s", updated.CreatedAt, updated.UpdatedAt)
	}
}

func TestStoreEnforcesQuotaAndChangeRetention(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	factory, err := NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	limits := testMutationLimits()
	limits.MaxDocuments = 1
	limits.ChangeRetentionEntries = 1
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "one", Data: []byte(`{"value":1}`),
		CreateOnly: true, Now: now, Limits: limits,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "two", Data: []byte(`{"value":2}`),
		CreateOnly: true, Now: now.Add(time.Second), Limits: limits,
	}); !errors.Is(err, wispist.ErrQuotaExceeded) {
		t.Fatalf("document quota error = %v", err)
	}
	if _, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "other", ID: "two", Data: []byte(`{"value":2}`),
		CreateOnly: true, Now: now.Add(2 * time.Second), Limits: limits,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Changes(ctx, "live", []string{"items", "other"}, wispist.EncodeChangeCursor("live", 0), 10); !errors.Is(err, wispist.ErrCursorExpired) {
		t.Fatalf("expired cursor error = %v", err)
	}
}

func TestConditionalReplacementHasSingleWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	factory, err := NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	store, err := factory.Open(ctx, "site", true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	document, _, err := store.Put(ctx, wispist.PutRequest{
		Namespace: "live", Collection: "items", ID: "shared", Data: []byte(`{"winner":0}`),
		CreateOnly: true, Now: now, Limits: testMutationLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, _, err := store.Put(ctx, wispist.PutRequest{
				Namespace: "live", Collection: "items", ID: "shared", Data: []byte(`{"winner":1}`),
				ExpectedRevision: document.Revision, Now: now.Add(time.Duration(index+1) * time.Second), Limits: testMutationLimits(),
			})
			results <- err
		}(index)
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, wispist.ErrRevisionConflict) {
			t.Fatalf("replacement error = %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful replacements = %d, want 1", winners)
	}
}

func TestFactoryCachesBoundsAndProtectsStores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "wispist")
	factory, err := NewFactory(directory)
	if err != nil {
		t.Fatal(err)
	}
	factory.maxOpen = 1
	first, err := factory.Open(ctx, "first", true)
	if err != nil {
		t.Fatal(err)
	}
	if mode := mustMode(t, directory).Perm(); mode != 0o700 {
		t.Fatalf("data directory mode = %o", mode)
	}
	if mode := mustMode(t, filepath.Join(directory, "first.db")).Perm(); mode != 0o600 {
		t.Fatalf("store mode = %o", mode)
	}
	if stats := factory.Stats(); stats.OpenStores != 1 || stats.InUse != 1 || stats.Evictions != 0 {
		t.Fatalf("active factory stats = %+v", stats)
	}
	if _, err := factory.Open(ctx, "second", true); !errors.Is(err, wispist.ErrStoreUnavailable) {
		t.Fatalf("active cache capacity error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := factory.Open(ctx, "second", true)
	if err != nil {
		t.Fatalf("LRU eviction open: %v", err)
	}
	if len(factory.entries) != 1 || factory.entries["second"] == nil {
		t.Fatalf("cache entries = %#v", factory.entries)
	}
	if stats := factory.Stats(); stats.OpenStores != 1 || stats.InUse != 1 || stats.Evictions != 1 {
		t.Fatalf("evicted factory stats = %+v", stats)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := factory.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Open(ctx, "third", true); err == nil {
		t.Fatal("closed factory accepted an open")
	}
}

func TestFactoryRejectsStoreSymlink(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "wispist")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do not open"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(directory, "site.db")); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFactory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer factory.Close()
	if _, err := factory.Open(context.Background(), "site", true); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink store error = %v", err)
	}
	contents, err := os.ReadFile(victim)
	if err != nil || string(contents) != "do not open" {
		t.Fatalf("victim changed to %q, %v", contents, err)
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
