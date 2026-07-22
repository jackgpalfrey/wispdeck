package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/updatepolicy"
)

func (s *SQLite) UpdateSettings(ctx context.Context) (updatepolicy.Settings, error) {
	var settings updatepolicy.Settings
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT mode, skipped_version, updated_at
		FROM update_settings WHERE singleton = 1
	`).Scan(&settings.Mode, &settings.SkippedVersion, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return updatepolicy.Settings{}, errors.New("update settings are missing")
	}
	if err != nil {
		return updatepolicy.Settings{}, fmt.Errorf("query update settings: %w", err)
	}
	if updatedAt > 0 {
		settings.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	}
	return settings, nil
}

func (s *SQLite) SaveUpdateSettings(
	ctx context.Context,
	settings updatepolicy.Settings,
	event updatepolicy.Event,
) error {
	if !updatepolicy.ValidMode(settings.Mode) || len(settings.SkippedVersion) > 64 {
		return errors.New("invalid update settings")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin update settings change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE update_settings
		SET mode = ?, skipped_version = ?, updated_at = ?, updated_by_user_id = NULLIF(?, '')
		WHERE singleton = 1
	`, settings.Mode, settings.SkippedVersion, unix(settings.UpdatedAt), event.Actor.UserID)
	if err != nil {
		return fmt.Errorf("save update settings: %w", err)
	}
	if err := requireOneRow(result, "update settings"); err != nil {
		return err
	}
	if err := insertUpdateEvent(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit update settings change: %w", err)
	}
	return nil
}

func (s *SQLite) RecordUpdateEvent(ctx context.Context, event updatepolicy.Event) error {
	return insertUpdateEvent(ctx, s.db, event)
}

type updateEventExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertUpdateEvent(ctx context.Context, executor updateEventExecutor, event updatepolicy.Event) error {
	if event.OccurredAt.IsZero() || len(event.Actor.Username) > 64 || len(event.Actor.ClientIP) > 128 ||
		len(event.Version) > 64 || len(event.Details) > 500 {
		return errors.New("invalid update event")
	}
	_, err := executor.ExecContext(ctx, `
		INSERT INTO update_events (
			occurred_at, actor_user_id, actor_username, client_ip, kind, version, details
		) VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?)
	`, unix(event.OccurredAt), event.Actor.UserID, event.Actor.Username,
		event.Actor.ClientIP, event.Kind, event.Version, event.Details)
	if err != nil {
		return fmt.Errorf("record update event: %w", err)
	}
	return nil
}
