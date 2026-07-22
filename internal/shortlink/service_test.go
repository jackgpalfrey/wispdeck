package shortlink

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRepository struct {
	created  Link
	resolved Link
	links    []Link
	stats    []DailyStat
	visits   []VisitBucket
	flushErr error
}

func (f *fakeRepository) CreateShortLink(_ context.Context, owner string, link Link, _ Limits, now time.Time) (Link, error) {
	link.ID = "0123456789abcdef0123456789abcdef"
	link.OwnerUserID = owner
	link.Enabled = true
	link.CreatedAt = now
	link.UpdatedAt = now
	f.created = link
	return link, nil
}

func (f *fakeRepository) ShortLinks(context.Context, string, bool) ([]Link, error) {
	return append([]Link(nil), f.links...), nil
}

func (f *fakeRepository) UpdateShortLink(context.Context, string, string, bool, Input, time.Time) error {
	return nil
}

func (f *fakeRepository) SetShortLinkEnabled(context.Context, string, string, bool, bool, time.Time) error {
	return nil
}

func (f *fakeRepository) RetireShortLink(context.Context, string, string, bool, time.Time) error {
	return nil
}

func (f *fakeRepository) ResolveShortLink(context.Context, string, time.Time) (Link, error) {
	return f.resolved, nil
}

func (f *fakeRepository) AddShortLinkVisits(_ context.Context, visits []VisitBucket) error {
	if f.flushErr != nil {
		return f.flushErr
	}
	f.visits = append(f.visits, visits...)
	return nil
}

func (f *fakeRepository) ShortLinkDailyStats(context.Context, string, bool, time.Time) ([]DailyStat, error) {
	return append([]DailyStat(nil), f.stats...), nil
}

func (f *fakeRepository) ShortLinkAuditEvents(context.Context, string, bool, int) ([]AuditEvent, error) {
	return nil, nil
}

func TestNormalizeSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   error
	}{
		{input: " Launch-Notes ", want: "launch-notes"},
		{input: "x", want: "x"},
		{input: "", err: ErrInvalidSlug},
		{input: "-leading", err: ErrInvalidSlug},
		{input: "trailing-", err: ErrInvalidSlug},
		{input: "not_ok", err: ErrInvalidSlug},
		{input: "login", err: ErrReservedSlug},
		{input: "healthz", err: ErrReservedSlug},
		{input: "SECURITY", err: ErrReservedSlug},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeSlug(test.input)
			if !errors.Is(err, test.err) {
				t.Fatalf("NormalizeSlug(%q) error = %v, want %v", test.input, err, test.err)
			}
			if got != test.want {
				t.Fatalf("NormalizeSlug(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"https://example.com",
		"http://127.0.0.1:8080/path?query=value#fragment",
		"https://[::1]/private",
		"https://example.com/%0d%0aencoded-is-data",
	}
	for _, value := range valid {
		if got, err := ValidateTarget(value); err != nil || got != value {
			t.Errorf("ValidateTarget(%q) = (%q, %v)", value, got, err)
		}
	}

	invalid := []string{
		"",
		"/relative",
		"javascript:alert(1)",
		"ftp://example.com/file",
		"https://user:password@example.com",
		"https://",
		"https://example.com/path with spaces",
		"https://example.com\r\nX-Test: injected",
	}
	for _, value := range invalid {
		if _, err := ValidateTarget(value); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ValidateTarget(%q) error = %v", value, err)
		}
	}

	if _, err := ValidateTarget("https://example.com/" + strings.Repeat("a", MaxTargetLength)); !errors.Is(err, ErrTargetTooLong) {
		t.Fatalf("oversized target error = %v", err)
	}
}

func TestRandomSlugUsesValidAlphabet(t *testing.T) {
	for range 100 {
		slug, err := randomSlug()
		if err != nil {
			t.Fatal(err)
		}
		if len(slug) != automaticLength {
			t.Fatalf("random slug length = %d", len(slug))
		}
		if normalized, err := NormalizeSlug(slug); err != nil || normalized != slug {
			t.Fatalf("random slug = %q, normalize error = %v", slug, err)
		}
	}
}

func TestServiceValidatesAndNormalizesRichLinkInput(t *testing.T) {
	repository := &fakeRepository{}
	service, err := NewService(repository, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	actor := Actor{UserID: "user-1"}
	link, err := service.Create(context.Background(), actor, Input{
		Slug: " Reading ", Title: " Private title ", Description: "notes\r\nline two",
		Mode: ModeIndex, ExpiresAt: now.Add(time.Hour),
		Destinations: []Destination{
			{Label: " Docs ", URL: " https://docs.example "},
			{Label: "Source", URL: "https://source.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if link.Slug != "reading" || link.Title != "Private title" || link.Description != "notes\nline two" ||
		len(link.Destinations) != 2 || link.Destinations[0].Label != "Docs" || link.Destinations[0].Position != 0 {
		t.Fatalf("normalized link = %#v", link)
	}

	tests := []struct {
		name  string
		input Input
		err   error
	}{
		{
			name: "redirect with many destinations",
			input: Input{Mode: ModeRedirect, Destinations: []Destination{
				{URL: "https://one.example"}, {URL: "https://two.example"},
			}},
			err: ErrInvalidDestinations,
		},
		{
			name: "duplicate destinations",
			input: Input{Mode: ModeIndex, Destinations: []Destination{
				{URL: "https://same.example"}, {URL: "https://same.example"},
			}},
			err: ErrDuplicateTarget,
		},
		{
			name: "expired",
			input: Input{Mode: ModeRedirect, ExpiresAt: now.Add(-time.Minute), Destinations: []Destination{
				{URL: "https://example.com"},
			}},
			err: ErrInvalidExpiry,
		},
		{
			name: "title control character",
			input: Input{Title: "bad\ntitle", Mode: ModeRedirect, Destinations: []Destination{
				{URL: "https://example.com"},
			}},
			err: ErrInvalidTitle,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Create(context.Background(), actor, test.input)
			if !errors.Is(err, test.err) {
				t.Fatalf("Create error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestServiceBuffersVisitsOverlaysStatsAndRestoresFailedFlush(t *testing.T) {
	linkID := "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	repository := &fakeRepository{
		resolved: Link{
			ID: linkID, Slug: "go", Mode: ModeRedirect, Enabled: true,
			Destinations: []Destination{{Label: " Example ", URL: " https://example.com "}},
		},
		links: []Link{{ID: linkID, Slug: "go", VisitCount: 5}},
		stats: []DailyStat{{
			LinkID: linkID, Day: utcDay(now), Visits: 3, LastVisitedAt: now.Add(-time.Minute),
		}},
	}
	service, err := NewService(repository, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	resolved, err := service.Resolve(context.Background(), "go", false)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Destinations[0].Label != "Example" || resolved.Destinations[0].URL != "https://example.com" {
		t.Fatalf("normalized resolved destinations = %#v", resolved.Destinations)
	}
	if len(service.counter.snapshot()) != 0 {
		t.Fatal("non-counted resolution changed the counter")
	}
	for range 2 {
		if _, err := service.Resolve(context.Background(), "go", true); err != nil {
			t.Fatal(err)
		}
	}
	links, err := service.List(context.Background(), Actor{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].VisitCount != 7 || len(links[0].DailyStats) != 1 || links[0].DailyStats[0].Visits != 5 {
		t.Fatalf("links with pending stats = %#v", links)
	}

	repository.flushErr = errors.New("database unavailable")
	if err := service.FlushVisits(context.Background()); err == nil {
		t.Fatal("failed flush returned nil")
	}
	if buckets := service.counter.snapshot(); len(buckets) != 1 || buckets[0].Visits != 2 {
		t.Fatalf("restored buckets = %#v", buckets)
	}
	repository.flushErr = nil
	if err := service.FlushVisits(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repository.visits) != 1 || repository.visits[0].Visits != 2 || len(service.counter.snapshot()) != 0 {
		t.Fatalf("flushed visits = %#v, pending = %#v", repository.visits, service.counter.snapshot())
	}
}

func TestVisitCounterBoundsUniqueBuckets(t *testing.T) {
	counter := newVisitCounter(1)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	counter.record("link-1", now)
	counter.record("link-1", now)
	counter.record("link-2", now)
	buckets := counter.snapshot()
	if len(buckets) != 1 || buckets[0].LinkID != "link-1" || buckets[0].Visits != 2 {
		t.Fatalf("bounded buckets = %#v", buckets)
	}
}

func TestVisitCounterHandlesConcurrentTraffic(t *testing.T) {
	counter := newVisitCounter(10)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	const workers = 32
	const visitsPerWorker = 250
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range visitsPerWorker {
				counter.record("link-1", now)
			}
		}()
	}
	wait.Wait()
	buckets := counter.snapshot()
	if len(buckets) != 1 || buckets[0].Visits != workers*visitsPerWorker {
		t.Fatalf("concurrent bucket = %#v", buckets)
	}
}
