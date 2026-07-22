package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
)

func TestSQLiteShortLinkLifecycleAuthorizationStatsAndAudit(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	alice, err := database.CreateManagedUser(ctx, "alice", "hash", auth.RoleUser, auth.UserActive, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := database.CreateManagedUser(ctx, "bob", "hash", auth.RoleSuperuser, auth.UserActive, now)
	if err != nil {
		t.Fatal(err)
	}

	link, err := database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "release-notes", Title: "Private title", Description: "Private notes",
		Mode: shortlink.ModeRedirect, ExpiresAt: now.Add(24 * time.Hour),
		Destinations: []shortlink.Destination{{Label: "Release", URL: "https://example.com/v1"}},
	}, shortlink.DefaultLimits(), now)
	if err != nil {
		t.Fatal(err)
	}
	if link.OwnerUserID != alice.ID || !link.Enabled || len(link.Destinations) != 1 || link.Destinations[0].ID == "" {
		t.Fatalf("created link = %#v", link)
	}
	if _, err := database.CreateShortLink(ctx, bob.ID, shortlink.Link{
		Slug: "release-notes", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.net"}},
	}, shortlink.DefaultLimits(), now); !errors.Is(err, shortlink.ErrSlugUnavailable) {
		t.Fatalf("duplicate slug error = %v", err)
	}

	aliceLinks, err := database.ShortLinks(ctx, alice.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceLinks) != 1 || aliceLinks[0].OwnerUsername != "alice" || aliceLinks[0].Title != "Private title" || len(aliceLinks[0].Destinations) != 1 {
		t.Fatalf("Alice links = %#v", aliceLinks)
	}
	if links, err := database.ShortLinks(ctx, bob.ID, false); err != nil || len(links) != 0 {
		t.Fatalf("Bob links = (%#v, %v)", links, err)
	}
	if links, err := database.ShortLinks(ctx, bob.ID, true); err != nil || len(links) != 1 {
		t.Fatalf("all links = (%#v, %v)", links, err)
	}

	update := shortlink.Input{
		Title: "Changed privately", Description: "Changed notes", Mode: shortlink.ModeIndex,
		ExpiresAt: now.Add(48 * time.Hour),
		Destinations: []shortlink.Destination{
			{Label: "Docs", URL: "https://example.com/docs"},
			{Label: "Source", URL: "https://example.com/source"},
		},
	}
	if err := database.UpdateShortLink(ctx, link.ID, bob.ID, false, update, now.Add(time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("cross-owner update error = %v", err)
	}
	if err := database.UpdateShortLink(ctx, link.ID, bob.ID, true, update, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	resolved, err := database.ResolveShortLink(ctx, "RELEASE-NOTES", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Mode != shortlink.ModeIndex || resolved.Title != "" || resolved.Description != "" || len(resolved.Destinations) != 2 || resolved.Destinations[1].URL != "https://example.com/source" {
		t.Fatalf("resolved link = %#v", resolved)
	}
	if _, err := database.ResolveShortLink(ctx, "release-notes", now.Add(49*time.Hour)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("expired resolution error = %v", err)
	}

	day := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	if err := database.AddShortLinkVisits(ctx, []shortlink.VisitBucket{{
		LinkID: link.ID, Day: day, Visits: 2, LastVisitedAt: now.Add(3 * time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := database.AddShortLinkVisits(ctx, []shortlink.VisitBucket{{
		LinkID: link.ID, Day: day, Visits: 3, LastVisitedAt: now.Add(4 * time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	aliceLinks, err = database.ShortLinks(ctx, alice.ID, false)
	if err != nil || len(aliceLinks) != 1 || aliceLinks[0].VisitCount != 5 || !aliceLinks[0].LastVisitedAt.Equal(now.Add(4*time.Minute)) {
		t.Fatalf("links after stats = (%#v, %v)", aliceLinks, err)
	}
	stats, err := database.ShortLinkDailyStats(ctx, alice.ID, false, day)
	if err != nil || len(stats) != 1 || stats[0].Visits != 5 {
		t.Fatalf("daily stats = (%#v, %v)", stats, err)
	}

	if err := database.SetShortLinkEnabled(ctx, link.ID, bob.ID, true, false, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ResolveShortLink(ctx, "release-notes", now.Add(6*time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("disabled resolution error = %v", err)
	}
	if err := database.RetireShortLink(ctx, link.ID, bob.ID, false, now.Add(7*time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("cross-owner retirement error = %v", err)
	}
	if err := database.RetireShortLink(ctx, link.ID, bob.ID, true, now.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if links, err := database.ShortLinks(ctx, alice.ID, false); err != nil || len(links) != 0 {
		t.Fatalf("retired link remained visible = (%#v, %v)", links, err)
	}
	if _, err := database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "release-notes", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://replacement.example"}},
	}, shortlink.DefaultLimits(), now.Add(8*time.Minute)); !errors.Is(err, shortlink.ErrSlugUnavailable) {
		t.Fatalf("retired slug reuse error = %v", err)
	}

	events, err := database.ShortLinkAuditEvents(ctx, alice.ID, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Kind != shortlink.AuditRetired || events[1].Kind != shortlink.AuditDisabled || events[2].Kind != shortlink.AuditUpdated {
		t.Fatalf("owner audit events = %#v", events)
	}
	for _, event := range events {
		if event.ActorUsername != "bob" || event.OwnerUsername != "alice" || event.Slug != "release-notes" {
			t.Fatalf("audit event = %#v", event)
		}
	}
}

func TestSQLiteShortLinkRequiresActiveOwner(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	user, err := database.CreateManagedUser(ctx, "disabled", "hash", auth.RoleUser, auth.UserDisabled, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShortLink(ctx, user.ID, shortlink.Link{
		Slug: "blocked", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, shortlink.DefaultLimits(), now); !errors.Is(err, shortlink.ErrForbidden) {
		t.Fatalf("disabled-owner creation error = %v", err)
	}
}

func TestShortLinkQuotaIncludesPermanentlyReservedRetiredLinks(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	user, err := database.CreateUser(ctx, "owner", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	limits := shortlink.Limits{MaxLinksPerUser: 1}
	first, err := database.CreateShortLink(ctx, user.ID, shortlink.Link{
		Slug: "first", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, limits, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShortLink(ctx, user.ID, shortlink.Link{
		Slug: "second", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, limits, now); !errors.Is(err, shortlink.ErrLinkLimit) {
		t.Fatalf("link quota error = %v", err)
	}
	if err := database.RetireShortLink(ctx, first.ID, user.ID, false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShortLink(ctx, user.ID, shortlink.Link{
		Slug: "second", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, limits, now.Add(2*time.Minute)); !errors.Is(err, shortlink.ErrLinkLimit) {
		t.Fatalf("retired permanent name did not consume quota: %v", err)
	}
}

func TestMigrationSevenPreservesExistingShortLinks(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wispdeck.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range []func(context.Context, *sql.Tx) error{
		migrationOne, migrationTwo, migrationThree, migrationFour, migrationFive, migrationSix,
	} {
		if err := migration(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (6)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`
		INSERT INTO users (
			id, username, password_hash, created_at, updated_at,
			mfa_skipped, role, status
		) VALUES ('user-1', 'alice', 'hash', 100, 100, 0, 'user', 'active')`); err != nil {
		t.Fatal(err)
	}
	linkID := "0123456789abcdef0123456789abcdef"
	if _, err := tx.Exec(`
		INSERT INTO short_links (
			id, owner_user_id, slug, target_url, enabled, visit_count,
			created_at, updated_at, last_visited_at
		) VALUES (?, 'user-1', 'legacy', 'https://legacy.example', 1, 7, 100, 100, 200)`, linkID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	links, err := database.ShortLinks(ctx, "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Mode != shortlink.ModeRedirect || links[0].VisitCount != 7 || len(links[0].Destinations) != 1 || links[0].Destinations[0].URL != "https://legacy.example" {
		t.Fatalf("migrated short link = %#v", links)
	}
	var kind, resourceID string
	if err := database.db.QueryRow(`SELECT kind, resource_id FROM public_names WHERE name = 'legacy'`).Scan(&kind, &resourceID); err != nil {
		t.Fatal(err)
	}
	if kind != "link" || resourceID != linkID {
		t.Fatalf("migrated public name = (%q, %q)", kind, resourceID)
	}
}
