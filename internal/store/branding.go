package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/branding"
)

const maxBrandingEvents = 1_000

func (s *SQLite) BrandingSettings(ctx context.Context) (branding.Settings, error) {
	var settings branding.Settings
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT instance_name, tagline, accent, landing_page_enabled, updated_at
		FROM branding_settings WHERE singleton = 1
	`).Scan(
		&settings.Name, &settings.Tagline, &settings.Accent,
		&settings.LandingPageEnabled, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return branding.Settings{}, errors.New("branding settings are missing")
	}
	if err != nil {
		return branding.Settings{}, fmt.Errorf("query branding settings: %w", err)
	}
	if updatedAt > 0 {
		settings.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	}
	return settings, nil
}

func (s *SQLite) SaveBrandingSettings(
	ctx context.Context,
	settings branding.Settings,
	actor branding.Actor,
) error {
	normalized, err := branding.Normalize(settings)
	if err != nil || settings.UpdatedAt.IsZero() || actor.UserID == "" || actor.Username == "" ||
		len(actor.UserID) > 64 || len(actor.Username) > 64 || len(actor.ClientIP) > 128 {
		return errors.New("invalid branding change")
	}
	normalized.UpdatedAt = settings.UpdatedAt.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin branding change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE branding_settings
		SET instance_name = ?, tagline = ?, accent = ?, landing_page_enabled = ?, updated_at = ?,
			updated_by_user_id = ?
		WHERE singleton = 1
	`, normalized.Name, normalized.Tagline, normalized.Accent, normalized.LandingPageEnabled,
		unix(normalized.UpdatedAt), actor.UserID)
	if err != nil {
		return fmt.Errorf("save branding settings: %w", err)
	}
	if err := requireOneRow(result, "branding settings"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO branding_events (
			occurred_at, actor_user_id, actor_username, client_ip,
			instance_name, tagline, accent, landing_page_enabled
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, unix(normalized.UpdatedAt), actor.UserID, actor.Username, actor.ClientIP,
		normalized.Name, normalized.Tagline, normalized.Accent,
		normalized.LandingPageEnabled); err != nil {
		return fmt.Errorf("record branding change: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM branding_events WHERE id IN (
			SELECT id FROM branding_events
			ORDER BY occurred_at DESC, id DESC LIMIT -1 OFFSET ?
		)
	`, maxBrandingEvents); err != nil {
		return fmt.Errorf("bound branding history: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit branding change: %w", err)
	}
	return nil
}
