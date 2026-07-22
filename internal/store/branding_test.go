package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/branding"
)

func TestBrandingSettingsAndAuditAreAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	user, err := database.CreateUser(ctx, "alice", "hash", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := database.BrandingSettings(ctx)
	if err != nil || defaults.Name != "" || defaults.Tagline != "" ||
		defaults.Accent != branding.DefaultAccent || !defaults.LandingPageEnabled {
		t.Fatalf("default branding = (%+v, %v)", defaults, err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	want := branding.Settings{
		Name: "Jack’s Deck", Tagline: "Everything useful, close at hand.", Accent: "ocean",
		LandingPageEnabled: false, UpdatedAt: now,
	}
	actor := branding.Actor{UserID: user.ID, Username: user.Username, ClientIP: "192.0.2.1"}
	if err := database.SaveBrandingSettings(ctx, want, actor); err != nil {
		t.Fatal(err)
	}
	got, err := database.BrandingSettings(ctx)
	if err != nil || got != want {
		t.Fatalf("stored branding = (%+v, %v), want %+v", got, err, want)
	}
	var count int
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM branding_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("branding event count = %d", count)
	}

	invalid := want
	invalid.Accent = "javascript"
	if err := database.SaveBrandingSettings(ctx, invalid, actor); err == nil {
		t.Fatal("SaveBrandingSettings() accepted an invalid accent")
	}
	got, err = database.BrandingSettings(ctx)
	if err != nil || got != want {
		t.Fatalf("invalid change altered settings: (%+v, %v)", got, err)
	}
}
