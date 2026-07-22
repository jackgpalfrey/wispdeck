package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/wispist"
)

type Store struct {
	db *sql.DB
}

func (s *Store) Close() error { return s.db.Close() }

type paginationCursor struct {
	Namespace  string `json:"n"`
	Collection string `json:"c"`
	Watermark  uint64 `json:"w"`
	Sequence   uint64 `json:"s"`
	ID         string `json:"i"`
}

func (s *Store) List(ctx context.Context, namespace, collection string, limit int, after string) (wispist.ListPage, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return wispist.ListPage{}, mapError("begin document list", err)
	}
	defer func() { _ = tx.Rollback() }()

	var cursor paginationCursor
	if after == "" {
		cursor = paginationCursor{Namespace: namespace, Collection: collection}
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(last_sequence, 0) FROM namespace_state WHERE namespace = ?`, namespace,
		).Scan(&cursor.Watermark); errors.Is(err, sql.ErrNoRows) {
			cursor.Watermark = 0
		} else if err != nil {
			return wispist.ListPage{}, mapError("read list watermark", err)
		}
	} else if err := decodeCursor(after, &cursor); err != nil ||
		cursor.Namespace != namespace || cursor.Collection != collection {
		return wispist.ListPage{}, wispist.ErrInvalidCursor
	}
	if cursor.Sequence > cursor.Watermark {
		return wispist.ListPage{}, wispist.ErrInvalidCursor
	}
	var currentWatermark uint64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(last_sequence, 0) FROM namespace_state WHERE namespace = ?`, namespace,
	).Scan(&currentWatermark); errors.Is(err, sql.ErrNoRows) {
		currentWatermark = 0
	} else if err != nil {
		return wispist.ListPage{}, mapError("validate list watermark", err)
	}
	if cursor.Watermark > currentWatermark {
		return wispist.ListPage{}, wispist.ErrInvalidCursor
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, revision, data, created_at, updated_at, created_sequence
		FROM documents
		WHERE namespace = ? AND collection = ? AND created_sequence <= ?
		  AND (created_sequence > ? OR (created_sequence = ? AND id > ?))
		ORDER BY created_sequence, id
		LIMIT ?`,
		namespace, collection, cursor.Watermark,
		cursor.Sequence, cursor.Sequence, cursor.ID, limit+1,
	)
	if err != nil {
		return wispist.ListPage{}, mapError("query documents", err)
	}
	defer rows.Close()
	type listed struct {
		document wispist.Document
		sequence uint64
	}
	values := make([]listed, 0, limit+1)
	for rows.Next() {
		var value listed
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&value.document.ID, &value.document.Revision, &value.document.Data,
			&createdAt, &updatedAt, &value.sequence,
		); err != nil {
			return wispist.ListPage{}, mapError("scan document", err)
		}
		value.document.CreatedAt = fromMillis(createdAt)
		value.document.UpdatedAt = fromMillis(updatedAt)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return wispist.ListPage{}, mapError("iterate documents", err)
	}
	if err := rows.Close(); err != nil {
		return wispist.ListPage{}, mapError("close document list", err)
	}
	if err := tx.Commit(); err != nil {
		return wispist.ListPage{}, mapError("commit document list", err)
	}

	page := wispist.ListPage{ChangeCursor: wispist.EncodeChangeCursor(namespace, cursor.Watermark)}
	if len(values) > limit {
		last := values[limit-1]
		page.After = encodeCursor(paginationCursor{
			Namespace: cursor.Namespace, Collection: collection, Watermark: cursor.Watermark,
			Sequence: last.sequence, ID: last.document.ID,
		})
		values = values[:limit]
	}
	page.Documents = make([]wispist.Document, len(values))
	for index := range values {
		page.Documents[index] = values[index].document
	}
	return page, nil
}

func (s *Store) Get(ctx context.Context, namespace, collection, id string) (wispist.Document, error) {
	var document wispist.Document
	var createdAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, revision, data, created_at, updated_at
		FROM documents WHERE namespace = ? AND collection = ? AND id = ?`,
		namespace, collection, id,
	).Scan(&document.ID, &document.Revision, &document.Data, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return wispist.Document{}, wispist.ErrDocumentNotFound
	}
	if err != nil {
		return wispist.Document{}, mapError("query document", err)
	}
	document.CreatedAt = fromMillis(createdAt)
	document.UpdatedAt = fromMillis(updatedAt)
	return document, nil
}

func (s *Store) Create(ctx context.Context, request wispist.CreateRequest) (wispist.Document, wispist.Change, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("begin document creation", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := cleanupIdempotency(ctx, tx, request.Namespace, request.Now); err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	if document, fingerprint, found, err := idempotentDocument(ctx, tx, request.Namespace, request.IdempotencyKey, request.Now); err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	} else if found {
		if !bytes.Equal(fingerprint, request.Fingerprint[:]) {
			return wispist.Document{}, wispist.Change{}, false, wispist.ErrIdempotencyConflict
		}
		return document, wispist.Change{}, true, nil
	}
	var existing bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM documents WHERE namespace = ? AND collection = ? AND id = ?)`,
		request.Namespace, request.Collection, request.ID,
	).Scan(&existing); err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("check generated document ID", err)
	}
	if existing {
		return wispist.Document{}, wispist.Change{}, false, wispist.ErrRevisionConflict
	}
	if err := checkCreateCapacity(ctx, tx, request.Namespace, request.Collection, len(request.Data), request.Limits); err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	var idempotencyCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM idempotency_records WHERE namespace = ?`, request.Namespace,
	).Scan(&idempotencyCount); err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("count idempotency records", err)
	}
	if idempotencyCount >= request.Limits.MaxIdempotencyRecords {
		return wispist.Document{}, wispist.Change{}, false, wispist.ErrQuotaExceeded
	}
	sequence, err := nextSequence(ctx, tx, request.Namespace)
	if err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	revision, err := newRevision()
	if err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	document := wispist.Document{
		ID: request.ID, Revision: revision, Data: append([]byte(nil), request.Data...),
		CreatedAt: request.Now.UTC(), UpdatedAt: request.Now.UTC(),
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO documents (
			namespace, collection, id, revision, data, created_at, updated_at, created_sequence
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		request.Namespace, request.Collection, document.ID, document.Revision, document.Data,
		millis(document.CreatedAt), millis(document.UpdatedAt), sequence,
	); err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("insert document", err)
	}
	change := changeForDocument(request.Namespace, request.Collection, sequence, wispist.ChangeCreate, document)
	if err := insertChange(ctx, tx, request.Namespace, change, request.Now); err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (
			namespace, key, fingerprint, document_id, revision, data,
			document_created_at, document_updated_at, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		request.Namespace, request.IdempotencyKey, request.Fingerprint[:],
		document.ID, document.Revision, document.Data,
		millis(document.CreatedAt), millis(document.UpdatedAt), millis(request.Now),
		millis(request.Now.Add(request.Limits.IdempotencyRetention)),
	); err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("insert idempotency record", err)
	}
	if err := cleanupChanges(ctx, tx, request.Namespace, request.Now, request.Limits); err != nil {
		return wispist.Document{}, wispist.Change{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return wispist.Document{}, wispist.Change{}, false, mapError("commit document creation", err)
	}
	return document, change, false, nil
}

func (s *Store) Put(ctx context.Context, request wispist.PutRequest) (wispist.Document, wispist.Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wispist.Document{}, wispist.Change{}, mapError("begin document replacement", err)
	}
	defer func() { _ = tx.Rollback() }()
	var current wispist.Document
	var createdAt, updatedAt int64
	var createdSequence uint64
	err = tx.QueryRowContext(ctx, `
		SELECT id, revision, data, created_at, updated_at, created_sequence
		FROM documents WHERE namespace = ? AND collection = ? AND id = ?`,
		request.Namespace, request.Collection, request.ID,
	).Scan(&current.ID, &current.Revision, &current.Data, &createdAt, &updatedAt, &createdSequence)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return wispist.Document{}, wispist.Change{}, mapError("select document for replacement", err)
	}
	if request.CreateOnly && found {
		return wispist.Document{}, wispist.Change{}, wispist.ErrRevisionConflict
	}
	if !request.CreateOnly && !found {
		return wispist.Document{}, wispist.Change{}, wispist.ErrDocumentNotFound
	}
	if found && current.Revision != request.ExpectedRevision {
		return wispist.Document{}, wispist.Change{}, wispist.ErrRevisionConflict
	}
	if !found {
		if err := checkCreateCapacity(ctx, tx, request.Namespace, request.Collection, len(request.Data), request.Limits); err != nil {
			return wispist.Document{}, wispist.Change{}, err
		}
	} else if err := checkReplacementCapacity(ctx, tx, request.Namespace, len(current.Data), len(request.Data), request.Limits); err != nil {
		return wispist.Document{}, wispist.Change{}, err
	}
	sequence, err := nextSequence(ctx, tx, request.Namespace)
	if err != nil {
		return wispist.Document{}, wispist.Change{}, err
	}
	revision, err := newRevision()
	if err != nil {
		return wispist.Document{}, wispist.Change{}, err
	}
	operation := wispist.ChangeCreate
	document := wispist.Document{
		ID: request.ID, Revision: revision, Data: append([]byte(nil), request.Data...),
		CreatedAt: request.Now.UTC(), UpdatedAt: request.Now.UTC(),
	}
	if found {
		operation = wispist.ChangeUpdate
		document.CreatedAt = fromMillis(createdAt)
		if document.UpdatedAt.Before(document.CreatedAt) {
			document.UpdatedAt = document.CreatedAt
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE documents SET revision = ?, data = ?, updated_at = ?
			WHERE namespace = ? AND collection = ? AND id = ? AND revision = ?`,
			document.Revision, document.Data, millis(document.UpdatedAt),
			request.Namespace, request.Collection, request.ID, request.ExpectedRevision,
		)
		if err != nil {
			return wispist.Document{}, wispist.Change{}, mapError("replace document", err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return wispist.Document{}, wispist.Change{}, wispist.ErrRevisionConflict
		}
	} else {
		createdSequence = sequence
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO documents (
				namespace, collection, id, revision, data, created_at, updated_at, created_sequence
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			request.Namespace, request.Collection, request.ID, document.Revision, document.Data,
			millis(document.CreatedAt), millis(document.UpdatedAt), createdSequence,
		); err != nil {
			return wispist.Document{}, wispist.Change{}, mapError("insert selected-ID document", err)
		}
	}
	change := changeForDocument(request.Namespace, request.Collection, sequence, operation, document)
	if err := insertChange(ctx, tx, request.Namespace, change, request.Now); err != nil {
		return wispist.Document{}, wispist.Change{}, err
	}
	if err := cleanupChanges(ctx, tx, request.Namespace, request.Now, request.Limits); err != nil {
		return wispist.Document{}, wispist.Change{}, err
	}
	if err := tx.Commit(); err != nil {
		return wispist.Document{}, wispist.Change{}, mapError("commit document replacement", err)
	}
	return document, change, nil
}

func (s *Store) Delete(ctx context.Context, request wispist.DeleteRequest) (wispist.Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wispist.Change{}, mapError("begin document deletion", err)
	}
	defer func() { _ = tx.Rollback() }()
	var revision string
	err = tx.QueryRowContext(ctx, `
		SELECT revision FROM documents WHERE namespace = ? AND collection = ? AND id = ?`,
		request.Namespace, request.Collection, request.ID,
	).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return wispist.Change{}, wispist.ErrDocumentNotFound
	}
	if err != nil {
		return wispist.Change{}, mapError("select document for deletion", err)
	}
	if revision != request.ExpectedRevision {
		return wispist.Change{}, wispist.ErrRevisionConflict
	}
	sequence, err := nextSequence(ctx, tx, request.Namespace)
	if err != nil {
		return wispist.Change{}, err
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM documents
		WHERE namespace = ? AND collection = ? AND id = ? AND revision = ?`,
		request.Namespace, request.Collection, request.ID, request.ExpectedRevision,
	)
	if err != nil {
		return wispist.Change{}, mapError("delete document", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return wispist.Change{}, wispist.ErrRevisionConflict
	}
	change := wispist.Change{
		Sequence: sequence, Cursor: wispist.EncodeChangeCursor(request.Namespace, sequence),
		Collection: request.Collection, Operation: wispist.ChangeDelete,
		ID: request.ID, Revision: revision,
	}
	if err := insertChange(ctx, tx, request.Namespace, change, request.Now); err != nil {
		return wispist.Change{}, err
	}
	if err := cleanupChanges(ctx, tx, request.Namespace, request.Now, request.Limits); err != nil {
		return wispist.Change{}, err
	}
	if err := tx.Commit(); err != nil {
		return wispist.Change{}, mapError("commit document deletion", err)
	}
	return change, nil
}

func (s *Store) HighWater(ctx context.Context, namespace string) (string, error) {
	var sequence uint64
	err := s.db.QueryRowContext(ctx,
		`SELECT last_sequence FROM namespace_state WHERE namespace = ?`, namespace,
	).Scan(&sequence)
	if errors.Is(err, sql.ErrNoRows) {
		sequence = 0
	} else if err != nil {
		return "", mapError("read change high-water mark", err)
	}
	return wispist.EncodeChangeCursor(namespace, sequence), nil
}

func (s *Store) Changes(ctx context.Context, namespace string, collections []string, after string, limit int) (wispist.ChangesPage, error) {
	afterSequence, err := wispist.DecodeChangeCursor(namespace, after)
	if err != nil {
		return wispist.ChangesPage{}, wispist.ErrInvalidCursor
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return wispist.ChangesPage{}, mapError("begin change read", err)
	}
	defer func() { _ = tx.Rollback() }()
	var highWater uint64
	err = tx.QueryRowContext(ctx,
		`SELECT last_sequence FROM namespace_state WHERE namespace = ?`, namespace,
	).Scan(&highWater)
	if errors.Is(err, sql.ErrNoRows) {
		highWater = 0
	} else if err != nil {
		return wispist.ChangesPage{}, mapError("read change watermark", err)
	}
	if afterSequence > highWater {
		return wispist.ChangesPage{}, wispist.ErrInvalidCursor
	}
	var minimum sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(sequence) FROM changes WHERE namespace = ?`, namespace,
	).Scan(&minimum); err != nil {
		return wispist.ChangesPage{}, mapError("read retained change boundary", err)
	}
	if minimum.Valid {
		if afterSequence+1 < uint64(minimum.Int64) {
			return wispist.ChangesPage{}, wispist.ErrCursorExpired
		}
	} else if afterSequence < highWater {
		return wispist.ChangesPage{}, wispist.ErrCursorExpired
	}

	placeholders := make([]string, len(collections))
	arguments := make([]any, 0, len(collections)+4)
	arguments = append(arguments, namespace, afterSequence, highWater)
	for index, collection := range collections {
		placeholders[index] = "?"
		arguments = append(arguments, collection)
	}
	arguments = append(arguments, limit+1)
	query := `
		SELECT sequence, collection, operation, document_id, revision,
		       data, document_created_at, document_updated_at
		FROM changes
		WHERE namespace = ? AND sequence > ? AND sequence <= ?
		  AND collection IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY sequence
		LIMIT ?`
	rows, err := tx.QueryContext(ctx, query, arguments...)
	if err != nil {
		return wispist.ChangesPage{}, mapError("query changes", err)
	}
	defer rows.Close()
	changes := make([]wispist.Change, 0, limit+1)
	for rows.Next() {
		var change wispist.Change
		var operation string
		var data []byte
		var createdAt, updatedAt sql.NullInt64
		if err := rows.Scan(
			&change.Sequence, &change.Collection, &operation, &change.ID, &change.Revision,
			&data, &createdAt, &updatedAt,
		); err != nil {
			return wispist.ChangesPage{}, mapError("scan change", err)
		}
		change.Operation = wispist.ChangeOperation(operation)
		change.Cursor = wispist.EncodeChangeCursor(namespace, change.Sequence)
		if change.Operation != wispist.ChangeDelete {
			change.Document = &wispist.Document{
				ID: change.ID, Revision: change.Revision, Data: append([]byte(nil), data...),
				CreatedAt: fromMillis(createdAt.Int64), UpdatedAt: fromMillis(updatedAt.Int64),
			}
		}
		changes = append(changes, change)
	}
	if err := rows.Err(); err != nil {
		return wispist.ChangesPage{}, mapError("iterate changes", err)
	}
	if err := rows.Close(); err != nil {
		return wispist.ChangesPage{}, mapError("close change list", err)
	}
	if err := tx.Commit(); err != nil {
		return wispist.ChangesPage{}, mapError("commit change read", err)
	}
	page := wispist.ChangesPage{}
	if len(changes) > limit {
		page.More = true
		changes = changes[:limit]
	}
	page.Changes = changes
	if page.More && len(changes) > 0 {
		page.Cursor = changes[len(changes)-1].Cursor
	} else {
		page.Cursor = wispist.EncodeChangeCursor(namespace, highWater)
	}
	return page, nil
}

func idempotentDocument(ctx context.Context, tx *sql.Tx, namespace, key string, now time.Time) (wispist.Document, []byte, bool, error) {
	var document wispist.Document
	var fingerprint []byte
	var createdAt, updatedAt int64
	err := tx.QueryRowContext(ctx, `
		SELECT fingerprint, document_id, revision, data, document_created_at, document_updated_at
		FROM idempotency_records
		WHERE namespace = ? AND key = ? AND expires_at > ?`,
		namespace, key, millis(now),
	).Scan(&fingerprint, &document.ID, &document.Revision, &document.Data, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return wispist.Document{}, nil, false, nil
	}
	if err != nil {
		return wispist.Document{}, nil, false, mapError("query idempotency record", err)
	}
	document.CreatedAt = fromMillis(createdAt)
	document.UpdatedAt = fromMillis(updatedAt)
	return document, fingerprint, true, nil
}

func cleanupIdempotency(ctx context.Context, tx *sql.Tx, namespace string, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM idempotency_records WHERE namespace = ? AND expires_at <= ?`,
		namespace, millis(now),
	); err != nil {
		return mapError("expire idempotency records", err)
	}
	return nil
}

func checkCreateCapacity(ctx context.Context, tx *sql.Tx, namespace, collection string, dataBytes int, limits wispist.MutationLimits) error {
	if dataBytes > limits.MaxDocumentBytes {
		return wispist.ErrQuotaExceeded
	}
	var documents int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM documents WHERE namespace = ? AND collection = ?`,
		namespace, collection,
	).Scan(&documents); err != nil {
		return mapError("count collection documents", err)
	}
	if documents >= limits.MaxDocuments {
		return wispist.ErrQuotaExceeded
	}
	return checkReplacementCapacity(ctx, tx, namespace, 0, dataBytes, limits)
}

func checkReplacementCapacity(ctx context.Context, tx *sql.Tx, namespace string, oldBytes, newBytes int, limits wispist.MutationLimits) error {
	if newBytes > limits.MaxDocumentBytes {
		return wispist.ErrQuotaExceeded
	}
	var total int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(data)), 0) FROM documents WHERE namespace = ?`, namespace,
	).Scan(&total); err != nil {
		return mapError("measure namespace data", err)
	}
	if total-int64(oldBytes)+int64(newBytes) > limits.MaxNamespaceBytes {
		return wispist.ErrQuotaExceeded
	}
	return nil
}

func nextSequence(ctx context.Context, tx *sql.Tx, namespace string) (uint64, error) {
	var sequence uint64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO namespace_state (namespace, last_sequence) VALUES (?, 1)
		ON CONFLICT(namespace) DO UPDATE SET last_sequence = last_sequence + 1
		RETURNING last_sequence`, namespace,
	).Scan(&sequence)
	if err != nil {
		return 0, mapError("allocate change sequence", err)
	}
	return sequence, nil
}

func changeForDocument(namespace, collection string, sequence uint64, operation wispist.ChangeOperation, document wispist.Document) wispist.Change {
	copyDocument := document
	return wispist.Change{
		Sequence: sequence, Cursor: wispist.EncodeChangeCursor(namespace, sequence),
		Collection: collection, Operation: operation, Document: &copyDocument,
		ID: document.ID, Revision: document.Revision,
	}
}

func insertChange(ctx context.Context, tx *sql.Tx, namespace string, change wispist.Change, now time.Time) error {
	var data any
	var createdAt, updatedAt any
	if change.Document != nil {
		data = []byte(change.Document.Data)
		createdAt = millis(change.Document.CreatedAt)
		updatedAt = millis(change.Document.UpdatedAt)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO changes (
			namespace, sequence, collection, operation, document_id, revision,
			data, document_created_at, document_updated_at, occurred_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		namespace, change.Sequence, change.Collection, change.Operation,
		change.ID, change.Revision, data, createdAt, updatedAt, millis(now),
	); err != nil {
		return mapError("insert change", err)
	}
	return nil
}

func cleanupChanges(ctx context.Context, tx *sql.Tx, namespace string, now time.Time, limits wispist.MutationLimits) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM changes WHERE namespace = ? AND occurred_at < ?`,
		namespace, millis(now.Add(-limits.ChangeRetentionAge)),
	); err != nil {
		return mapError("expire old changes", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM changes
		WHERE namespace = ? AND sequence IN (
			SELECT sequence FROM changes WHERE namespace = ?
			ORDER BY sequence DESC LIMIT -1 OFFSET ?
		)`, namespace, namespace, limits.ChangeRetentionEntries,
	); err != nil {
		return mapError("bound retained changes", err)
	}
	return nil
}

func newRevision() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate document revision: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func encodeCursor(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeCursor(value string, destination any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > 512 {
		return wispist.ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return wispist.ErrInvalidCursor
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wispist.ErrInvalidCursor
	}
	return nil
}

func millis(value time.Time) int64 { return value.UTC().UnixMilli() }

func fromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func mapError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "database is locked") || strings.Contains(lower, "database is busy") ||
		strings.Contains(lower, "sqlite_busy") || strings.Contains(lower, "sqlite_locked") {
		return fmt.Errorf("%s: %w", operation, wispist.ErrStoreUnavailable)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
