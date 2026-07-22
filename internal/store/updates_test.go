package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/updatepolicy"
)

func TestUpdateSettingsAndAuditAreAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 22, 18, 0, 0, 0, time.UTC)
	user, err := database.CreateUser(ctx, "alice", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := database.UpdateSettings(ctx)
	if err != nil || settings.Mode != updatepolicy.ModeNotify || settings.SkippedVersion != "" {
		t.Fatalf("default settings = (%+v, %v)", settings, err)
	}
	settings.Mode = updatepolicy.ModeAutomatic
	settings.SkippedVersion = "v1.2.3"
	settings.UpdatedAt = now
	event := updatepolicy.Event{
		OccurredAt: now,
		Actor:      updatepolicy.Actor{UserID: user.ID, Username: user.Username, ClientIP: "192.0.2.1"},
		Kind:       "settings_changed", Details: "mode=automatic",
	}
	if err := database.SaveUpdateSettings(ctx, settings, event); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.UpdateSettings(ctx)
	if err != nil || loaded != settings {
		t.Fatalf("loaded settings = (%+v, %v), want %+v", loaded, err, settings)
	}
	var count int
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM update_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("update event count = %d", count)
	}

	invalid := settings
	invalid.Mode = "invalid"
	if err := database.SaveUpdateSettings(ctx, invalid, event); err == nil {
		t.Fatal("stored an invalid update mode")
	}
	loaded, err = database.UpdateSettings(ctx)
	if err != nil || loaded != settings {
		t.Fatalf("invalid change altered settings: (%+v, %v)", loaded, err)
	}
}
