package store

import (
	"context"
	"database/sql"
	"fmt"
)

const schemaVersion = 7

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
	for version < schemaVersion {
		switch version + 1 {
		case 1:
			if err := migrationOne(ctx, tx); err != nil {
				return err
			}
		case 2:
			if err := migrationTwo(ctx, tx); err != nil {
				return err
			}
		case 3:
			if err := migrationThree(ctx, tx); err != nil {
				return err
			}
		case 4:
			if err := migrationFour(ctx, tx); err != nil {
				return err
			}
		case 5:
			if err := migrationFive(ctx, tx); err != nil {
				return err
			}
		case 6:
			if err := migrationSix(ctx, tx); err != nil {
				return err
			}
		case 7:
			if err := migrationSeven(ctx, tx); err != nil {
				return err
			}
		}
		version++
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
			return fmt.Errorf("clear schema version: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, version); err != nil {
			return fmt.Errorf("write schema version: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

func migrationSeven(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		DROP INDEX short_links_owner_created;
		ALTER TABLE short_links RENAME TO short_links_v6;

		CREATE TABLE short_links (
			id TEXT PRIMARY KEY CHECK(length(id) = 32),
			owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			slug TEXT NOT NULL COLLATE NOCASE UNIQUE
				CHECK(length(slug) BETWEEN 1 AND 48)
				CHECK(slug = lower(slug))
				CHECK(slug NOT GLOB '*[^a-z0-9-]*')
				CHECK(substr(slug, 1, 1) <> '-' AND substr(slug, -1, 1) <> '-'),
			title TEXT NOT NULL DEFAULT '' CHECK(length(title) <= 120),
			description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 1000),
			mode TEXT NOT NULL CHECK(mode IN ('redirect', 'index', 'open_all')),
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			expires_at INTEGER,
			deleted_at INTEGER,
			CHECK(created_at <= updated_at),
			CHECK(expires_at IS NULL OR created_at < expires_at),
			CHECK(deleted_at IS NULL OR (created_at <= deleted_at AND enabled = 0))
		) STRICT;
		INSERT INTO short_links (
			id, owner_user_id, slug, mode, enabled, created_at, updated_at,
			expires_at, deleted_at
		)
		SELECT id, owner_user_id, slug, 'redirect', enabled, created_at,
		       updated_at, NULL, deleted_at
		FROM short_links_v6;

		CREATE TABLE short_link_destinations (
			id TEXT PRIMARY KEY CHECK(length(id) = 32),
			link_id TEXT NOT NULL REFERENCES short_links(id) ON DELETE CASCADE,
			position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 24),
			label TEXT NOT NULL DEFAULT '' CHECK(length(label) <= 120),
			target_url TEXT NOT NULL CHECK(length(target_url) BETWEEN 1 AND 4096),
			UNIQUE(link_id, position)
		) STRICT;
		INSERT INTO short_link_destinations (id, link_id, position, target_url)
			SELECT id, id, 0, target_url FROM short_links_v6;

		CREATE TABLE short_link_daily_stats (
			link_id TEXT NOT NULL REFERENCES short_links(id) ON DELETE CASCADE,
			day INTEGER NOT NULL CHECK(day % 86400 = 0),
			visits INTEGER NOT NULL CHECK(visits > 0),
			last_visited_at INTEGER NOT NULL,
			PRIMARY KEY(link_id, day)
		) WITHOUT ROWID, STRICT;
		INSERT INTO short_link_daily_stats (link_id, day, visits, last_visited_at)
		SELECT id,
		       CAST(COALESCE(last_visited_at, created_at) / 86400 AS INTEGER) * 86400,
		       visit_count,
		       COALESCE(last_visited_at, created_at)
		FROM short_links_v6
		WHERE visit_count > 0;

		CREATE TABLE short_link_audit_events (
			id INTEGER PRIMARY KEY,
			occurred_at INTEGER NOT NULL,
			actor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			link_id TEXT NOT NULL REFERENCES short_links(id) ON DELETE RESTRICT,
			slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 48),
			kind TEXT NOT NULL CHECK(kind IN ('updated', 'enabled', 'disabled', 'retired'))
		) STRICT;
		CREATE INDEX short_link_audit_owner_time
			ON short_link_audit_events(owner_user_id, occurred_at DESC, id DESC);

		DROP TABLE short_links_v6;
		CREATE INDEX short_links_owner_created
			ON short_links(owner_user_id, created_at DESC, id)
			WHERE deleted_at IS NULL;
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 7: %w", err)
	}
	return nil
}

func migrationSix(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		CREATE TABLE short_links (
			id TEXT PRIMARY KEY CHECK(length(id) = 32),
			owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
			slug TEXT NOT NULL COLLATE NOCASE UNIQUE
				CHECK(length(slug) BETWEEN 1 AND 48)
				CHECK(slug = lower(slug))
				CHECK(slug NOT GLOB '*[^a-z0-9-]*')
				CHECK(substr(slug, 1, 1) <> '-' AND substr(slug, -1, 1) <> '-'),
			target_url TEXT NOT NULL CHECK(length(target_url) BETWEEN 1 AND 4096),
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
			visit_count INTEGER NOT NULL DEFAULT 0 CHECK(visit_count >= 0),
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_visited_at INTEGER,
			deleted_at INTEGER,
			CHECK(created_at <= updated_at),
			CHECK(last_visited_at IS NULL OR created_at <= last_visited_at),
			CHECK(deleted_at IS NULL OR (created_at <= deleted_at AND enabled = 0))
		) STRICT;
		CREATE INDEX short_links_owner_created
			ON short_links(owner_user_id, created_at DESC, id)
			WHERE deleted_at IS NULL;
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 6: %w", err)
	}
	return nil
}

func migrationFive(ctx context.Context, tx *sql.Tx) error {
	// Existing local users retain their previous full authority as superusers. Accounts
	// created through the web interface select their role explicitly.
	const schema = `
		ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'superuser'
			CHECK(role IN ('user', 'superuser'));
		ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
			CHECK(status IN ('pending', 'active', 'disabled'));

		CREATE TABLE user_setup_tokens (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
			created_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			CHECK(created_at < expires_at)
		) STRICT;
		CREATE INDEX user_setup_tokens_expires ON user_setup_tokens(expires_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 5: %w", err)
	}
	return nil
}

func migrationFour(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		ALTER TABLE users ADD COLUMN mfa_skipped INTEGER NOT NULL DEFAULT 0
			CHECK(mfa_skipped IN (0, 1));

		CREATE TABLE sessions_v4 (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			csrf_token TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			assurance TEXT NOT NULL CHECK(assurance IN ('bootstrap', 'password', 'mfa', 'recovery')),
			authenticated_at INTEGER NOT NULL,
			client_ip TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			CHECK(created_at <= last_seen),
			CHECK(last_seen <= expires_at)
		) STRICT;
		INSERT INTO sessions_v4 (
			token_hash, user_id, csrf_token, created_at, last_seen, expires_at,
			assurance, authenticated_at, client_ip, user_agent
		)
		SELECT token_hash, user_id, csrf_token, created_at, last_seen, expires_at,
			assurance, authenticated_at, client_ip, user_agent
		FROM sessions;
		DROP TABLE sessions;
		ALTER TABLE sessions_v4 RENAME TO sessions;
		CREATE INDEX sessions_user_id ON sessions(user_id);
		CREATE INDEX sessions_expires_at ON sessions(expires_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 4: %w", err)
	}
	return nil
}

func migrationThree(ctx context.Context, tx *sql.Tx) error {
	const schema = `
		CREATE TABLE totp_credentials (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			encrypted_secret BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			last_used_counter INTEGER CHECK(last_used_counter IS NULL OR last_used_counter >= 0)
		) STRICT;

		CREATE TABLE totp_enrollments (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			binding_hash BLOB NOT NULL CHECK(length(binding_hash) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			encrypted_secret BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			CHECK(created_at < expires_at)
		) STRICT;
		CREATE INDEX totp_enrollments_binding ON totp_enrollments(binding_hash);
		CREATE INDEX totp_enrollments_expires ON totp_enrollments(expires_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 3: %w", err)
	}
	return nil
}

func migrationTwo(ctx context.Context, tx *sql.Tx) error {
	// Password-only sessions from schema v1 must not survive the transition to
	// explicit authentication assurance levels.
	const schema = `
		DELETE FROM sessions;
		ALTER TABLE sessions ADD COLUMN assurance TEXT NOT NULL DEFAULT 'mfa'
			CHECK(assurance IN ('bootstrap', 'mfa', 'recovery'));
		ALTER TABLE sessions ADD COLUMN authenticated_at INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT '';
		ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';

		DROP INDEX auth_events_occurred_at;
		ALTER TABLE auth_events RENAME TO auth_events_v1;
		CREATE TABLE auth_events (
			id INTEGER PRIMARY KEY,
			occurred_at INTEGER NOT NULL,
			kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
			username TEXT,
			user_id TEXT,
			client_ip TEXT,
			details TEXT NOT NULL DEFAULT ''
		) STRICT;
		INSERT INTO auth_events (id, occurred_at, kind, username, user_id, client_ip)
			SELECT id, occurred_at, kind, username, user_id, client_ip FROM auth_events_v1;
		DROP TABLE auth_events_v1;
		CREATE INDEX auth_events_occurred_at ON auth_events(occurred_at);
		CREATE INDEX auth_events_user_id ON auth_events(user_id, occurred_at);

		CREATE TABLE webauthn_credentials (
			credential_id BLOB NOT NULL,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			rp_id TEXT NOT NULL,
			name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
			encrypted_record BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			last_used_at INTEGER,
			PRIMARY KEY (rp_id, credential_id),
			UNIQUE (user_id, rp_id, name)
		) STRICT;
		CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id, rp_id);

		CREATE TABLE login_transactions (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			client_ip TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			CHECK(created_at < expires_at)
		) STRICT;
		CREATE INDEX login_transactions_expires ON login_transactions(expires_at);

		CREATE TABLE auth_ceremonies (
			token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
			binding_hash BLOB NOT NULL CHECK(length(binding_hash) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK(kind IN ('passkey_login', 'passkey_register')),
			encrypted_data BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			CHECK(created_at < expires_at)
		) STRICT;
		CREATE INDEX auth_ceremonies_binding ON auth_ceremonies(binding_hash, kind);
		CREATE INDEX auth_ceremonies_expires ON auth_ceremonies(expires_at);

		CREATE TABLE recovery_codes (
			code_digest BLOB PRIMARY KEY CHECK(length(code_digest) = 32),
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			batch_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			used_at INTEGER
		) STRICT;
		CREATE INDEX recovery_codes_user ON recovery_codes(user_id, used_at);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema version 2: %w", err)
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
