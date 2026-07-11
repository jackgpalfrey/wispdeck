package store

import (
	"context"
	"database/sql"
	"fmt"
)

const schemaVersion = 1

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		) STRICT`); err != nil {
		return fmt.Errorf("create schema version table: %w", err)
	}
	var version int
	err = tx.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, schemaVersion)
	}
	if version == 0 {
		if err := migrationOne(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
			return fmt.Errorf("clear schema version: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, schemaVersion); err != nil {
			return fmt.Errorf("write schema version: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

func migrationOne(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL COLLATE NOCASE UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT;

		CREATE TABLE sessions (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			csrf_token TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			CHECK(created_at <= last_seen),
			CHECK(last_seen <= expires_at)
		) STRICT;
		CREATE INDEX sessions_user_id ON sessions(user_id);
		CREATE INDEX sessions_expires_at ON sessions(expires_at);

		CREATE TABLE auth_events (
			id INTEGER PRIMARY KEY,
			occurred_at INTEGER NOT NULL,
			kind TEXT NOT NULL CHECK(kind IN ('login_succeeded', 'login_failed', 'logout')),
			username TEXT,
			user_id TEXT,
			client_ip TEXT
		) STRICT;
		CREATE INDEX auth_events_occurred_at ON auth_events(occurred_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 1: %w", err)
	}
	return nil
}
