package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

const SchemaVersion = 1

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin wispist migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		) STRICT`); err != nil {
		return fmt.Errorf("create wispist schema version: %w", err)
	}
	var version int
	err = tx.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read wispist schema version: %w", err)
	}
	if version > SchemaVersion {
		return fmt.Errorf("wispist schema version %d is newer than supported version %d", version, SchemaVersion)
	}
	if version < 1 {
		if err := migrationOne(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
			return fmt.Errorf("clear wispist schema version: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (1)`); err != nil {
			return fmt.Errorf("write wispist schema version: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit wispist migration: %w", err)
	}
	return nil
}

func migrationOne(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		CREATE TABLE namespace_state (
			namespace TEXT PRIMARY KEY CHECK(length(namespace) BETWEEN 1 AND 256),
			last_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_sequence >= 0)
		) STRICT;

		CREATE TABLE documents (
			namespace TEXT NOT NULL CHECK(length(namespace) BETWEEN 1 AND 256),
			collection TEXT NOT NULL CHECK(length(collection) BETWEEN 1 AND 48),
			id TEXT NOT NULL CHECK(length(id) BETWEEN 1 AND 64),
			revision TEXT NOT NULL CHECK(length(revision) BETWEEN 16 AND 128),
			data BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			created_sequence INTEGER NOT NULL CHECK(created_sequence > 0),
			PRIMARY KEY(namespace, collection, id),
			CHECK(created_at <= updated_at)
		) WITHOUT ROWID, STRICT;
		CREATE INDEX documents_collection_order
			ON documents(namespace, collection, created_sequence, id);

		CREATE TABLE changes (
			namespace TEXT NOT NULL CHECK(length(namespace) BETWEEN 1 AND 256),
			sequence INTEGER NOT NULL CHECK(sequence > 0),
			collection TEXT NOT NULL CHECK(length(collection) BETWEEN 1 AND 48),
			operation TEXT NOT NULL CHECK(operation IN ('create', 'update', 'delete')),
			document_id TEXT NOT NULL CHECK(length(document_id) BETWEEN 1 AND 64),
			revision TEXT NOT NULL CHECK(length(revision) BETWEEN 16 AND 128),
			data BLOB,
			document_created_at INTEGER,
			document_updated_at INTEGER,
			occurred_at INTEGER NOT NULL,
			PRIMARY KEY(namespace, sequence),
			CHECK((operation = 'delete') = (data IS NULL)),
			CHECK((data IS NULL) = (document_created_at IS NULL)),
			CHECK((data IS NULL) = (document_updated_at IS NULL))
		) WITHOUT ROWID, STRICT;
		CREATE INDEX changes_collection_sequence
			ON changes(namespace, collection, sequence);
		CREATE INDEX changes_retention
			ON changes(namespace, occurred_at, sequence);

		CREATE TABLE idempotency_records (
			namespace TEXT NOT NULL CHECK(length(namespace) BETWEEN 1 AND 256),
			key TEXT NOT NULL CHECK(length(key) BETWEEN 16 AND 128),
			fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
			document_id TEXT NOT NULL CHECK(length(document_id) BETWEEN 1 AND 64),
			revision TEXT NOT NULL CHECK(length(revision) BETWEEN 16 AND 128),
			data BLOB NOT NULL,
			document_created_at INTEGER NOT NULL,
			document_updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY(namespace, key),
			CHECK(created_at < expires_at)
		) WITHOUT ROWID, STRICT;
		CREATE INDEX idempotency_expiry
			ON idempotency_records(namespace, expires_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply wispist schema version 1: %w", err)
	}
	return nil
}
