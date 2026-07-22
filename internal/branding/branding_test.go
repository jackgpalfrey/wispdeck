package branding

import (
	"context"
	"errors"
	"math"
	"strconv"
	"sync"
	"testing"
	"time"
)

type memoryRepository struct {
	mu       sync.Mutex
	settings Settings
	actor    Actor
	err      error
}

func (r *memoryRepository) BrandingSettings(context.Context) (Settings, error) {
	return r.settings, r.err
}

func (r *memoryRepository) SaveBrandingSettings(_ context.Context, settings Settings, actor Actor) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.settings = settings
	r.actor = actor
	return nil
}

func TestServiceAppliesDefaultsAndCachesValidatedUpdate(t *testing.T) {
	t.Parallel()
	repository := &memoryRepository{settings: Settings{LandingPageEnabled: true}}
	service, err := NewService(context.Background(), repository, "sites.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if current := service.Current(); current.Name != "sites.example.test" ||
		current.Tagline != DefaultTagline || current.Accent != DefaultAccent {
		t.Fatalf("default branding = %+v", current)
	}
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	updated, err := service.Update(context.Background(), Settings{
		Name: "  Jack’s Links  ", Tagline: "  Useful things, in one place.  ", Accent: "OCEAN",
		LandingPageEnabled: false,
	}, Actor{UserID: "user-id", Username: "jack", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Jack’s Links" || updated.Tagline != "Useful things, in one place." ||
		updated.Accent != "ocean" || updated.LandingPageEnabled || !updated.UpdatedAt.Equal(now) {
		t.Fatalf("updated branding = %+v", updated)
	}
	if service.Current() != updated || repository.settings != updated || repository.actor.Username != "jack" {
		t.Fatal("validated update was not stored and cached")
	}
}

func TestServiceRejectsUnsafeOrInvalidSettings(t *testing.T) {
	t.Parallel()
	service, err := NewService(context.Background(), &memoryRepository{
		settings: Settings{LandingPageEnabled: true},
	}, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: "id", Username: "jack"}
	for _, settings := range []Settings{
		{Name: "", Tagline: "tagline", Accent: "forest"},
		{Name: "name\nheader", Tagline: "tagline", Accent: "forest"},
		{Name: "name", Tagline: "", Accent: "forest"},
		{Name: "name", Tagline: "tagline", Accent: "url(javascript:bad)"},
	} {
		if _, err := service.Update(context.Background(), settings, actor); !errors.Is(err, ErrInvalidSettings) {
			t.Fatalf("Update(%+v) error = %v", settings, err)
		}
	}
	if service.Current().Name != "example.test" {
		t.Fatal("invalid update changed cached branding")
	}
}

func TestServiceDoesNotCacheFailedWrite(t *testing.T) {
	t.Parallel()
	repository := &memoryRepository{settings: Settings{LandingPageEnabled: true}}
	service, err := NewService(context.Background(), repository, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	repository.err = errors.New("write failed")
	if _, err := service.Update(context.Background(), Settings{
		Name: "Changed", Tagline: "Still safe", Accent: "teal",
	}, Actor{UserID: "id", Username: "jack"}); err == nil {
		t.Fatal("Update() succeeded despite repository failure")
	}
	if service.Current().Name != "example.test" {
		t.Fatal("failed write changed cached branding")
	}
}

func TestAccentPaletteHasAccessibleButtonContrast(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{})
	for _, accent := range Accents() {
		if accent.ID == "" || accent.Label == "" {
			t.Fatalf("incomplete accent: %+v", accent)
		}
		if _, duplicate := seen[accent.ID]; duplicate {
			t.Fatalf("duplicate accent ID %q", accent.ID)
		}
		seen[accent.ID] = struct{}{}
		if contrast := whiteContrast(t, accent.Hex); contrast < 4.5 {
			t.Errorf("accent %q contrast against white = %.2f, want at least 4.5", accent.ID, contrast)
		}
	}
}

func whiteContrast(t *testing.T, hex string) float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("invalid accent hex %q", hex)
	}
	channels := make([]float64, 3)
	for index := range channels {
		value, err := strconv.ParseUint(hex[1+index*2:3+index*2], 16, 8)
		if err != nil {
			t.Fatalf("invalid accent hex %q: %v", hex, err)
		}
		channel := float64(value) / 255
		if channel <= 0.04045 {
			channels[index] = channel / 12.92
		} else {
			channels[index] = math.Pow((channel+0.055)/1.055, 2.4)
		}
	}
	luminance := 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2]
	return 1.05 / (luminance + 0.05)
}
