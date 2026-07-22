package wispist

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// NamespaceRef identifies a host-owned Wispist namespace. MaxBytes may lower
// the engine-wide namespace limit for a host-specific mode such as a draft.
type NamespaceRef struct {
	StoreKey  string
	Namespace string
	MaxBytes  int64
}

var ErrInvalidNamespaceRef = errors.New("invalid Wispist namespace reference")

func (e *Engine) NamespaceUsage(ctx context.Context, ref NamespaceRef) (NamespaceUsage, error) {
	if err := e.validateNamespaceRef(ref); err != nil {
		return NamespaceUsage{}, err
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return NamespaceUsage{Namespace: ref.Namespace, Collections: []CollectionUsage{}}, nil
	}
	if err != nil {
		return NamespaceUsage{}, fmt.Errorf("open Wispist store for namespace usage: %w", err)
	}
	defer store.Close()
	return store.Usage(ctx, ref.Namespace)
}

func (e *Engine) NamespaceSnapshot(ctx context.Context, ref NamespaceRef) (NamespaceSnapshot, error) {
	snapshots, err := e.NamespaceSnapshots(ctx, []NamespaceRef{ref})
	if err != nil {
		return NamespaceSnapshot{}, err
	}
	return snapshots[ref.Namespace], nil
}

// NamespaceSnapshots exports several namespaces from the same store using one
// consistent read transaction. It is intended for host-level backup and data
// portability rather than the public site API.
func (e *Engine) NamespaceSnapshots(ctx context.Context, refs []NamespaceRef) (map[string]NamespaceSnapshot, error) {
	if len(refs) == 0 || len(refs) > 16 {
		return nil, ErrInvalidNamespaceRef
	}
	storeKey := refs[0].StoreKey
	namespaces := make([]string, 0, len(refs))
	empty := make(map[string]NamespaceSnapshot, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if err := e.validateNamespaceRef(ref); err != nil || ref.StoreKey != storeKey {
			return nil, ErrInvalidNamespaceRef
		}
		if _, exists := seen[ref.Namespace]; exists {
			return nil, ErrInvalidNamespaceRef
		}
		seen[ref.Namespace] = struct{}{}
		namespaces = append(namespaces, ref.Namespace)
		empty[ref.Namespace] = NamespaceSnapshot{
			Namespace: ref.Namespace, Collections: map[string][]Document{},
		}
	}
	store, err := e.stores.Open(ctx, storeKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return empty, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open Wispist store for namespace export: %w", err)
	}
	defer store.Close()
	return store.SnapshotNamespaces(ctx, namespaces)
}

func (e *Engine) ListNamespaceDocuments(
	ctx context.Context,
	ref NamespaceRef,
	collection string,
	limit int,
	after string,
) (ListPage, error) {
	if err := e.validateNamespaceRef(ref); err != nil {
		return ListPage{}, err
	}
	if !ValidCollectionName(collection) || limit < 1 || limit > e.limits.MaxListLimit {
		return ListPage{}, ErrInvalidNamespaceRef
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return ListPage{
			Documents: []Document{}, ChangeCursor: EncodeChangeCursor(ref.Namespace, 0),
		}, nil
	}
	if err != nil {
		return ListPage{}, fmt.Errorf("open Wispist store for document list: %w", err)
	}
	defer store.Close()
	return store.List(ctx, ref.Namespace, collection, limit, after)
}

func (e *Engine) ReplaceNamespaceDocument(
	ctx context.Context,
	ref NamespaceRef,
	collection, documentID, expectedRevision string,
	raw []byte,
) (Document, error) {
	if err := e.validateNamespaceRef(ref); err != nil {
		return Document{}, err
	}
	if !ValidCollectionName(collection) || !ValidDocumentID(documentID) || expectedRevision == "" {
		return Document{}, ErrInvalidNamespaceRef
	}
	data, err := normalizeJSONObject(raw, e.limits.MaxDocumentBytes, 32, 256)
	if err != nil {
		return Document{}, ErrInvalidDocumentData
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return Document{}, ErrDocumentNotFound
	}
	if err != nil {
		return Document{}, fmt.Errorf("open Wispist store for document replacement: %w", err)
	}
	defer store.Close()
	document, change, err := store.Put(ctx, PutRequest{
		Namespace: ref.Namespace, Collection: collection, ID: documentID,
		Data: data, ExpectedRevision: expectedRevision, Now: e.now().UTC(),
		Limits: e.namespaceMutationLimits(ref),
	})
	if err != nil {
		return Document{}, err
	}
	e.hub.publish(e.namespaceHubKey(ref), change)
	return document, nil
}

func (e *Engine) DeleteNamespaceDocument(
	ctx context.Context,
	ref NamespaceRef,
	collection, documentID, expectedRevision string,
) error {
	if err := e.validateNamespaceRef(ref); err != nil {
		return err
	}
	if !ValidCollectionName(collection) || !ValidDocumentID(documentID) || expectedRevision == "" {
		return ErrInvalidNamespaceRef
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return ErrDocumentNotFound
	}
	if err != nil {
		return fmt.Errorf("open Wispist store for document deletion: %w", err)
	}
	defer store.Close()
	change, err := store.Delete(ctx, DeleteRequest{
		Namespace: ref.Namespace, Collection: collection, ID: documentID,
		ExpectedRevision: expectedRevision, Now: e.now().UTC(),
		Limits: e.namespaceMutationLimits(ref),
	})
	if err != nil {
		return err
	}
	e.hub.publish(e.namespaceHubKey(ref), change)
	return nil
}

func (e *Engine) ClearNamespaceCollection(ctx context.Context, ref NamespaceRef, collection string) (int, error) {
	if err := e.validateNamespaceRef(ref); err != nil {
		return 0, err
	}
	if !ValidCollectionName(collection) {
		return 0, ErrInvalidNamespaceRef
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open Wispist store for collection clear: %w", err)
	}
	defer store.Close()
	changes, err := store.ClearCollection(ctx, ClearCollectionRequest{
		Namespace: ref.Namespace, Collection: collection, Now: e.now().UTC(),
		Limits: e.namespaceMutationLimits(ref),
	})
	if err != nil {
		return 0, err
	}
	for _, change := range changes {
		e.hub.publish(e.namespaceHubKey(ref), change)
	}
	return len(changes), nil
}

// PurgeNamespace permanently removes documents and retained mutation history.
// Active subscribers are reset so they cannot continue from a pre-purge cursor.
func (e *Engine) PurgeNamespace(ctx context.Context, ref NamespaceRef) error {
	if err := e.validateNamespaceRef(ref); err != nil {
		return err
	}
	store, err := e.stores.Open(ctx, ref.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open Wispist store for namespace purge: %w", err)
	}
	defer store.Close()
	if err := store.PurgeNamespace(ctx, ref.Namespace); err != nil {
		return err
	}
	e.hub.reset(e.namespaceHubKey(ref), "namespace_purged")
	return nil
}

func (e *Engine) validateNamespaceRef(ref NamespaceRef) error {
	if strings.TrimSpace(ref.StoreKey) == "" || len(ref.StoreKey) > 128 ||
		strings.TrimSpace(ref.Namespace) == "" || len(ref.Namespace) > 256 ||
		ref.MaxBytes < 0 || ref.MaxBytes > e.limits.MaxNamespaceBytes {
		return ErrInvalidNamespaceRef
	}
	return nil
}

func (e *Engine) namespaceMutationLimits(ref NamespaceRef) MutationLimits {
	maxBytes := e.limits.MaxNamespaceBytes
	if ref.MaxBytes > 0 {
		maxBytes = ref.MaxBytes
	}
	return MutationLimits{
		MaxDocuments: e.limits.MaxDocuments, MaxDocumentBytes: e.limits.MaxDocumentBytes,
		MaxNamespaceBytes: maxBytes, MaxIdempotencyRecords: e.limits.MaxIdempotencyRecords,
		ChangeRetentionEntries: e.limits.ChangeRetentionEntries,
		ChangeRetentionAge:     e.limits.ChangeRetentionAge,
		IdempotencyRetention:   e.limits.IdempotencyRetention,
	}
}

func (e *Engine) namespaceHubKey(ref NamespaceRef) string {
	return ref.StoreKey + "\x00" + ref.Namespace
}
