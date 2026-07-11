// Package store owns Wispdeck's durable control-plane state.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	_ "modernc.org/sqlite"
)

var ErrUserExists = errors.New("user already exists")

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	cleanup := func(err error) (*SQLite, error) {
		_ = db.Close()
		return nil, err
	}
	for _, statement := range []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return cleanup(fmt.Errorf("configure database: %w", err))
		}
	}
	if err := migrate(ctx, db); err != nil {
		return cleanup(err)
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			return cleanup(fmt.Errorf("restrict database permissions: %w", err))
		}
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) CreateUser(ctx context.Context, username, passwordHash string, now time.Time) (auth.User, error) {
	id, err := randomID()
	if err != nil {
		return auth.User{}, err
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(username) DO NOTHING`, id, username, passwordHash, unix(now), unix(now))
	if err != nil {
		return auth.User{}, fmt.Errorf("insert user: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return auth.User{}, fmt.Errorf("inspect user insert: %w", err)
	}
	if rows != 1 {
		return auth.User{}, ErrUserExists
	}
	return auth.User{ID: id, Username: username, PasswordHash: passwordHash}, nil
}

func (s *SQLite) UserByUsername(ctx context.Context, username string) (auth.User, error) {
	var user auth.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash FROM users WHERE username = ?`, username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("query user: %w", err)
	}
	return user, nil
}

func (s *SQLite) UserByID(ctx context.Context, userID string) (auth.User, error) {
	var user auth.User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash FROM users WHERE id = ?`, userID,
	).Scan(&user.ID, &user.Username, &user.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("query user by ID: %w", err)
	}
	return user, nil
}

func (s *SQLite) UpdatePasswordHash(ctx context.Context, userID, passwordHash string, now time.Time) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, passwordHash, unix(now), userID,
	)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	return requireOneRow(result, "user")
}

func (s *SQLite) ChangePasswordAndRevoke(ctx context.Context, userID, passwordHash string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, passwordHash, unix(now), userID,
	)
	if err != nil {
		return fmt.Errorf("update changed password: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("password-change user not found")
	}
	for _, statement := range []string{
		`DELETE FROM auth_ceremonies WHERE user_id = ?`,
		`DELETE FROM login_transactions WHERE user_id = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
			return fmt.Errorf("revoke authentication state after password change: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}
	return nil
}

func (s *SQLite) CreateSession(ctx context.Context, session auth.SessionRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (
			token_hash, user_id, csrf_token, created_at, last_seen, expires_at,
			assurance, authenticated_at, client_ip, user_agent
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.TokenHash[:], session.UserID, session.CSRFToken,
		unix(session.CreatedAt), unix(session.LastSeen), unix(session.ExpiresAt),
		session.Assurance, unix(session.AuthenticatedAt), session.ClientIP, session.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (s *SQLite) SessionByTokenHash(ctx context.Context, digest [32]byte) (auth.Session, error) {
	var session auth.Session
	var tokenHash []byte
	var createdAt, authenticatedAt, lastSeen, expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT s.token_hash, s.csrf_token, s.assurance, s.created_at, s.authenticated_at,
		       s.last_seen, s.expires_at, s.client_ip, s.user_agent,
		       u.id, u.username
		FROM sessions AS s
		JOIN users AS u ON u.id = s.user_id
		WHERE s.token_hash = ?`, digest[:],
	).Scan(
		&tokenHash, &session.CSRFToken, &session.Assurance, &createdAt, &authenticatedAt,
		&lastSeen, &expiresAt, &session.ClientIP, &session.UserAgent,
		&session.User.ID, &session.User.Username,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Session{}, auth.ErrInvalidSession
	}
	if err != nil {
		return auth.Session{}, fmt.Errorf("query session: %w", err)
	}
	if len(tokenHash) != len(session.TokenHash) {
		return auth.Session{}, errors.New("stored session digest has invalid length")
	}
	copy(session.TokenHash[:], tokenHash)
	session.CreatedAt = time.Unix(createdAt, 0).UTC()
	session.AuthenticatedAt = time.Unix(authenticatedAt, 0).UTC()
	session.LastSeen = time.Unix(lastSeen, 0).UTC()
	session.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return session, nil
}

func (s *SQLite) TouchSession(ctx context.Context, digest [32]byte, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, unix(now), digest[:])
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return requireOneRow(result, "session")
}

func (s *SQLite) DeleteSession(ctx context.Context, digest [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, digest[:])
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *SQLite) RecordAuthEvent(ctx context.Context, event auth.AuthEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_events (occurred_at, kind, username, user_id, client_ip, details)
		VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?)`,
		unix(event.OccurredAt), event.Kind, event.Username, event.UserID, event.ClientIP, event.Details,
	)
	if err != nil {
		return fmt.Errorf("insert auth event: %w", err)
	}
	return nil
}

func (s *SQLite) AuthEventsByUser(ctx context.Context, userID string, limit int) ([]auth.AuthEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT occurred_at, kind, COALESCE(username, ''), COALESCE(user_id, ''),
		       COALESCE(client_ip, ''), details
		FROM auth_events WHERE user_id = ?
		ORDER BY occurred_at DESC, id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("query authentication events: %w", err)
	}
	defer rows.Close()
	var events []auth.AuthEvent
	for rows.Next() {
		var event auth.AuthEvent
		var occurredAt int64
		if err := rows.Scan(&occurredAt, &event.Kind, &event.Username, &event.UserID, &event.ClientIP, &event.Details); err != nil {
			return nil, fmt.Errorf("scan authentication event: %w", err)
		}
		event.OccurredAt = time.Unix(occurredAt, 0).UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate authentication events: %w", err)
	}
	return events, nil
}

func requireOneRow(result sql.Result, kind string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect %s update: %w", kind, err)
	}
	if rows != 1 {
		return fmt.Errorf("%s not found", kind)
	}
	return nil
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func unix(t time.Time) int64 { return t.UTC().Unix() }
