package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/wispdeck/wispdeck/wispist"
)

func (s *Store) Usage(ctx context.Context, namespace string) (wispist.NamespaceUsage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT collection, COUNT(*), COALESCE(SUM(length(data)), 0)
		FROM documents
		WHERE namespace = ?
		GROUP BY collection
		ORDER BY collection`, namespace)
	if err != nil {
		return wispist.NamespaceUsage{}, mapError("query namespace usage", err)
	}
	defer rows.Close()
	usage := wispist.NamespaceUsage{Namespace: namespace, Collections: []wispist.CollectionUsage{}}
	for rows.Next() {
		var collection wispist.CollectionUsage
		if err := rows.Scan(&collection.Name, &collection.Documents, &collection.Bytes); err != nil {
			return wispist.NamespaceUsage{}, mapError("scan namespace usage", err)
		}
		usage.Documents += collection.Documents
		usage.Bytes += collection.Bytes
		usage.Collections = append(usage.Collections, collection)
	}
	if err := rows.Err(); err != nil {
		return wispist.NamespaceUsage{}, mapError("iterate namespace usage", err)
	}
	return usage, nil
}

func (s *Store) Snapshot(ctx context.Context, namespace string) (wispist.NamespaceSnapshot, error) {
	snapshots, err := s.SnapshotNamespaces(ctx, []string{namespace})
	if err != nil {
		return wispist.NamespaceSnapshot{}, err
	}
	return snapshots[namespace], nil
}

func (s *Store) SnapshotNamespaces(ctx context.Context, namespaces []string) (map[string]wispist.NamespaceSnapshot, error) {
	if len(namespaces) == 0 {
		return map[string]wispist.NamespaceSnapshot{}, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, mapError("begin namespace snapshot", err)
	}
	defer func() { _ = tx.Rollback() }()
	snapshots := make(map[string]wispist.NamespaceSnapshot, len(namespaces))
	placeholders := make([]string, len(namespaces))
	arguments := make([]any, len(namespaces))
	for index, namespace := range namespaces {
		snapshots[namespace] = wispist.NamespaceSnapshot{
			Namespace: namespace, Collections: make(map[string][]wispist.Document),
		}
		placeholders[index] = "?"
		arguments[index] = namespace
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT namespace, collection, id, revision, data, created_at, updated_at
		FROM documents
		WHERE namespace IN (`+strings.Join(placeholders, ",")+`)
		ORDER BY namespace, collection, created_sequence, id`, arguments...)
	if err != nil {
		return nil, mapError("query namespace snapshot", err)
	}
	for rows.Next() {
		var namespace, collection string
		var document wispist.Document
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&namespace, &collection, &document.ID, &document.Revision, &document.Data, &createdAt, &updatedAt,
		); err != nil {
			_ = rows.Close()
			return nil, mapError("scan namespace snapshot", err)
		}
		document.CreatedAt = fromMillis(createdAt)
		document.UpdatedAt = fromMillis(updatedAt)
		snapshot := snapshots[namespace]
		snapshot.Collections[collection] = append(snapshot.Collections[collection], document)
		snapshots[namespace] = snapshot
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, mapError("iterate namespace snapshot", err)
	}
	if err := rows.Close(); err != nil {
		return nil, mapError("close namespace snapshot", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapError("commit namespace snapshot", err)
	}
	return snapshots, nil
}

func (s *Store) ClearCollection(ctx context.Context, request wispist.ClearCollectionRequest) ([]wispist.Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapError("begin collection clear", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT id, revision
		FROM documents
		WHERE namespace = ? AND collection = ?
		ORDER BY created_sequence, id`, request.Namespace, request.Collection)
	if err != nil {
		return nil, mapError("query documents for collection clear", err)
	}
	type selectedDocument struct {
		id       string
		revision string
	}
	selected := make([]selectedDocument, 0)
	for rows.Next() {
		var document selectedDocument
		if err := rows.Scan(&document.id, &document.revision); err != nil {
			_ = rows.Close()
			return nil, mapError("scan document for collection clear", err)
		}
		selected = append(selected, document)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, mapError("iterate documents for collection clear", err)
	}
	if err := rows.Close(); err != nil {
		return nil, mapError("close documents for collection clear", err)
	}

	changes := make([]wispist.Change, 0, len(selected))
	for _, document := range selected {
		sequence, err := nextSequence(ctx, tx, request.Namespace)
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, `
			DELETE FROM documents
			WHERE namespace = ? AND collection = ? AND id = ? AND revision = ?`,
			request.Namespace, request.Collection, document.id, document.revision,
		)
		if err != nil {
			return nil, mapError("delete document during collection clear", err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return nil, wispist.ErrRevisionConflict
		}
		change := wispist.Change{
			Sequence: sequence, Cursor: wispist.EncodeChangeCursor(request.Namespace, sequence),
			Collection: request.Collection, Operation: wispist.ChangeDelete,
			ID: document.id, Revision: document.revision,
		}
		if err := insertChange(ctx, tx, request.Namespace, change, request.Now); err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	if err := cleanupChanges(ctx, tx, request.Namespace, request.Now, request.Limits); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapError("commit collection clear", err)
	}
	return changes, nil
}

func (s *Store) PurgeNamespace(ctx context.Context, namespace string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapError("begin namespace purge", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range []string{
		`DELETE FROM idempotency_records WHERE namespace = ?`,
		`DELETE FROM changes WHERE namespace = ?`,
		`DELETE FROM documents WHERE namespace = ?`,
		`DELETE FROM namespace_state WHERE namespace = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, namespace); err != nil {
			return mapError("purge namespace", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit namespace purge: %w", err)
	}
	return nil
}
