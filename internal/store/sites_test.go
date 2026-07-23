package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	"github.com/wispdeck/wispdeck/internal/site"
)

func TestSiteReleasePublicationPreviewAndGlobalNames(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	alice, err := database.CreateUser(ctx, "alice", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := database.CreateManagedUser(ctx, "bob", "hash", auth.RoleUser, auth.UserActive, now)
	if err != nil {
		t.Fatal(err)
	}

	limits := site.DefaultLimits()
	created, err := database.CreateSite(ctx, alice.ID, "notes", "Private notes site", false, limits, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "notes", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, false, shortlink.DefaultLimits(), now); !errors.Is(err, shortlink.ErrSlugUnavailable) {
		t.Fatalf("link using site name error = %v", err)
	}
	if _, err := database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "other", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, false, shortlink.DefaultLimits(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateSite(ctx, alice.ID, "other", "", false, limits, now); !errors.Is(err, site.ErrNameUnavailable) {
		t.Fatalf("site using link name error = %v", err)
	}

	bundleOne := testBundle(map[string]string{
		"index.html": "<h1>one</h1>", "app.js": "one()",
	})
	if _, err := database.CreateSiteRelease(ctx, bob.ID, false, created.ID, bundleOne, limits, now.Add(time.Minute)); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("cross-owner upload error = %v", err)
	}
	releaseOne, err := database.CreateSiteRelease(ctx, alice.ID, false, created.ID, bundleOne, limits, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := database.SiteByName(ctx, "notes")
	if err != nil || loaded.DraftReleaseID != releaseOne.ID || loaded.PublishedReleaseID != "" {
		t.Fatalf("draft site = (%#v, %v)", loaded, err)
	}

	grant, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateSitePreviewGrant(
		ctx, alice.ID, false, "notes", "p0123456789abcdef0123456789abcdef",
		auth.TokenDigest(grant), now.Add(3*time.Minute), now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	previewToken, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExchangeSitePreviewGrant(
		ctx, "pffffffffffffffffffffffffffffffff", auth.TokenDigest(grant),
		auth.TokenDigest(previewToken), now.Add(time.Hour), now.Add(2*time.Minute),
	); !errors.Is(err, site.ErrInvalidPreview) {
		t.Fatalf("wrong-origin preview exchange error = %v", err)
	}
	preview, err := database.ExchangeSitePreviewGrant(
		ctx, "p0123456789abcdef0123456789abcdef", auth.TokenDigest(grant),
		auth.TokenDigest(previewToken), now.Add(time.Hour), now.Add(2*time.Minute),
	)
	if err != nil || preview.DraftReleaseID != releaseOne.ID {
		t.Fatalf("preview exchange = (%#v, %v)", preview, err)
	}
	if _, err := database.ExchangeSitePreviewGrant(
		ctx, "p0123456789abcdef0123456789abcdef", auth.TokenDigest(grant),
		auth.TokenDigest(previewToken), now.Add(time.Hour), now.Add(2*time.Minute),
	); !errors.Is(err, site.ErrInvalidPreview) {
		t.Fatalf("reused preview grant error = %v", err)
	}
	if _, err := database.SitePreviewSession(
		ctx, "p0123456789abcdef0123456789abcdef", auth.TokenDigest(previewToken), now.Add(30*time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	if err := database.PublishSiteRelease(ctx, alice.ID, false, created.ID, releaseOne.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = database.SiteByName(ctx, "notes")
	if err != nil || loaded.PublishedReleaseID != releaseOne.ID || loaded.DraftReleaseID != "" {
		t.Fatalf("published site = (%#v, %v)", loaded, err)
	}
	file, err := database.SiteFile(ctx, releaseOne.ID, "index.html")
	if err != nil || string(file.Body) != "<h1>one</h1>" {
		t.Fatalf("published file = (%#v, %v)", file, err)
	}

	bundleTwo := testBundle(map[string]string{"index.html": "<h1>two</h1>"})
	releaseTwo, err := database.CreateSiteRelease(ctx, alice.ID, false, created.ID, bundleTwo, limits, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ = database.SiteByName(ctx, "notes")
	if loaded.PublishedReleaseID != releaseOne.ID || loaded.DraftReleaseID != releaseTwo.ID {
		t.Fatalf("site pointers after second upload = %#v", loaded)
	}
	if err := database.PublishSiteRelease(ctx, alice.ID, false, created.ID, releaseTwo.ID, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.PublishSiteRelease(ctx, alice.ID, false, created.ID, releaseOne.ID, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, _ = database.SiteByName(ctx, "notes")
	if loaded.PublishedReleaseID != releaseOne.ID {
		t.Fatalf("rollback publication = %#v", loaded)
	}
	if err := database.SetSiteEnabled(ctx, bob.ID, false, created.ID, false, now); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("cross-owner disable error = %v", err)
	}
	if err := database.SetSiteEnabled(ctx, alice.ID, false, created.ID, false, now); err != nil {
		t.Fatal(err)
	}

	sites, err := database.Sites(ctx, alice.ID, false)
	if err != nil || len(sites) != 1 || len(sites[0].Releases) != 2 || sites[0].Releases[0].Version != 2 {
		t.Fatalf("managed sites = (%#v, %v)", sites, err)
	}
	usage, err := database.SiteUsage(ctx, alice.ID, false, created.ID)
	if err != nil || usage.SiteReleases != 2 || usage.OwnerSites != 1 || usage.SiteBytes != bundleOne.TotalBytes+bundleTwo.TotalBytes {
		t.Fatalf("site usage = (%+v, %v)", usage, err)
	}
	if err := database.DeleteSiteRelease(ctx, alice.ID, false, created.ID, releaseOne.ID, now.Add(7*time.Minute)); !errors.Is(err, site.ErrSelectedRelease) {
		t.Fatalf("selected release deletion error = %v", err)
	}
	if err := database.DeleteSiteRelease(ctx, alice.ID, false, created.ID, releaseTwo.ID, now.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.PurgeSiteContent(ctx, alice.ID, false, created.ID, now.Add(8*time.Minute)); err != nil {
		t.Fatal(err)
	}
	sites, err = database.Sites(ctx, alice.ID, false)
	if err != nil || len(sites) != 1 || sites[0].Enabled || len(sites[0].Releases) != 0 ||
		sites[0].DraftReleaseID != "" || sites[0].PublishedReleaseID != "" {
		t.Fatalf("purged site = (%#v, %v)", sites, err)
	}
	if _, err := database.CreateSite(ctx, alice.ID, "notes", "replacement", false, limits, now.Add(9*time.Minute)); !errors.Is(err, site.ErrNameUnavailable) {
		t.Fatalf("purged name was released: %v", err)
	}
	republished, err := database.CreateSiteRelease(ctx, alice.ID, false, created.ID, bundleTwo, limits, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.PublishSiteRelease(ctx, alice.ID, false, created.ID, republished.ID, now.Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSiteEnabled(ctx, alice.ID, false, created.ID, true, now.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = database.SiteByName(ctx, "notes")
	if err != nil || !loaded.Enabled || loaded.PublishedReleaseID != republished.ID {
		t.Fatalf("republished purged site = (%+v, %v)", loaded, err)
	}
}

func TestRetiredLinkNameCanBecomeFreshSiteOnlyForOwner(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	alice, err := database.CreateUser(ctx, "alice", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := database.CreateUser(ctx, "bob", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "itinerary", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://old.example"}},
	}, false, shortlink.DefaultLimits(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RetireShortLink(ctx, retired.ID, alice.ID, false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	limits := site.DefaultLimits()
	if _, err := database.CreateSite(
		ctx, alice.ID, "itinerary", "Holiday", false, limits, now.Add(2*time.Minute),
	); !errors.Is(err, site.ErrReclaimConfirmation) {
		t.Fatalf("unconfirmed site reclamation error = %v", err)
	}
	if _, err := database.CreateSite(
		ctx, bob.ID, "itinerary", "Takeover", true, limits, now.Add(2*time.Minute),
	); !errors.Is(err, site.ErrNameUnavailable) {
		t.Fatalf("cross-owner site reclamation error = %v", err)
	}
	created, err := database.CreateSite(
		ctx, alice.ID, "itinerary", "Holiday", true, limits, now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == retired.ID {
		t.Fatal("site reused the retired link identity")
	}
	loaded, err := database.SiteByName(ctx, "itinerary")
	if err != nil || loaded.ID != created.ID || loaded.Title != "Holiday" {
		t.Fatalf("reclaimed site = (%+v, %v)", loaded, err)
	}
	if _, err := database.ResolveShortLink(ctx, "itinerary", now.Add(3*time.Minute)); !errors.Is(err, shortlink.ErrNotFound) {
		t.Fatalf("retired link still resolved after conversion: %v", err)
	}
}

func TestSiteQuotasAreEnforcedAtomically(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	owner, err := database.CreateUser(ctx, "owner", "hash", now)
	if err != nil {
		t.Fatal(err)
	}
	limits := site.Limits{MaxSitesPerUser: 1, MaxReleasesPerSite: 2, MaxStorageBytesPerUser: 1 << 20}
	created, err := database.CreateSite(ctx, owner.ID, "one", "", false, limits, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateSite(ctx, owner.ID, "two", "", false, limits, now); !errors.Is(err, site.ErrSiteLimit) {
		t.Fatalf("site quota error = %v", err)
	}
	bundle := testBundle(map[string]string{"index.html": "one"})
	for range 2 {
		if _, err := database.CreateSiteRelease(ctx, owner.ID, false, created.ID, bundle, limits, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.CreateSiteRelease(ctx, owner.ID, false, created.ID, bundle, limits, now); !errors.Is(err, site.ErrReleaseLimit) {
		t.Fatalf("release quota error = %v", err)
	}
	storageLimits := limits
	storageLimits.MaxReleasesPerSite = 3
	storageLimits.MaxStorageBytesPerUser = bundle.TotalBytes * 2
	if _, err := database.CreateSiteRelease(ctx, owner.ID, false, created.ID, bundle, storageLimits, now); !errors.Is(err, site.ErrStorageLimit) {
		t.Fatalf("storage quota error = %v", err)
	}
}

func testBundle(files map[string]string) site.Bundle {
	paths := make([]site.File, 0, len(files))
	var total int64
	hasher := sha256.New()
	for name, contents := range files {
		body := []byte(contents)
		digest := sha256.Sum256(body)
		paths = append(paths, site.File{
			Path: name, ContentType: "text/html; charset=utf-8", Body: body, Digest: digest,
		})
		total += int64(len(body))
		_, _ = hasher.Write(digest[:])
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return site.Bundle{Files: paths, TotalBytes: total, Digest: digest}
}
