package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
)

func TestSQLiteShortLinkLifecycleAndAuthorization(t *testing.T) {
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
	bob, err := database.CreateManagedUser(ctx, "bob", "hash", auth.RoleUser, auth.UserActive, now)
	if err != nil {
		t.Fatal(err)
	}

	link, err := database.CreateShortLink(ctx, alice.ID, "release-notes", "https://example.com/v1", now)
	if err != nil {
		t.Fatal(err)
	}
	if link.OwnerUserID != alice.ID || !link.Enabled || link.VisitCount != 0 {
		t.Fatalf("created link = %#v", link)
	}
	if _, err := database.CreateShortLink(ctx, bob.ID, "release-notes", "https://example.net", now); !errors.Is(err, shortlink.ErrSlugUnavailable) {
		t.Fatalf("duplicate slug error = %v", err)
	}

	aliceLinks, err := database.ShortLinks(ctx, alice.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceLinks) != 1 || aliceLinks[0].OwnerUsername != "alice" {
		t.Fatalf("Alice links = %#v", aliceLinks)
	}
	if links, err := database.ShortLinks(ctx, bob.ID, false); err != nil || len(links) != 0 {
		t.Fatalf("Bob links = (%#v, %v)", links, err)
	}
	if links, err := database.ShortLinks(ctx, bob.ID, true); err != nil || len(links) != 1 {
		t.Fatalf("all links = (%#v, %v)", links, err)
	}

	if err := database.UpdateShortLinkTarget(ctx, link.ID, bob.ID, false, "https://attacker.example", now.Add(time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("cross-owner update error = %v", err)
	}
	if err := database.UpdateShortLinkTarget(ctx, link.ID, bob.ID, true, "https://example.com/v2", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	resolved, err := database.ResolveShortLink(ctx, "RELEASE-NOTES", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.TargetURL != "https://example.com/v2" || resolved.VisitCount != 1 || !resolved.LastVisitedAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("resolved link = %#v", resolved)
	}
	resolved, err = database.ResolveShortLink(ctx, "release-notes", now.Add(3*time.Minute))
	if err != nil || resolved.VisitCount != 2 {
		t.Fatalf("second resolution = (%#v, %v)", resolved, err)
	}

	if err := database.SetShortLinkEnabled(ctx, link.ID, alice.ID, false, false, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ResolveShortLink(ctx, "release-notes", now.Add(5*time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("disabled resolution error = %v", err)
	}
	if err := database.RetireShortLink(ctx, link.ID, bob.ID, false, now.Add(6*time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("cross-owner delete error = %v", err)
	}
	if err := database.RetireShortLink(ctx, link.ID, alice.ID, false, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if links, err := database.ShortLinks(ctx, alice.ID, false); err != nil || len(links) != 0 {
		t.Fatalf("retired link remained visible = (%#v, %v)", links, err)
	}
	if _, err := database.CreateShortLink(ctx, alice.ID, "release-notes", "https://replacement.example", now.Add(7*time.Minute)); !errors.Is(err, shortlink.ErrSlugUnavailable) {
		t.Fatalf("retired slug reuse error = %v", err)
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
	if _, err := database.CreateShortLink(ctx, user.ID, "blocked", "https://example.com", now); !errors.Is(err, shortlink.ErrForbidden) {
		t.Fatalf("disabled-owner creation error = %v", err)
	}
}
