// Package branding owns the small, browser-visible identity configured for a
// Wispdeck installation. It deliberately exposes curated colours rather than
// accepting arbitrary CSS or remotely hosted assets.
package branding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	DefaultTagline  = "Short links, your server, your rules."
	DefaultAccent   = "forest"
	MaxNameRunes    = 48
	MaxTaglineRunes = 160
)

var ErrInvalidSettings = errors.New("branding settings are invalid")

type Accent struct {
	ID    string
	Label string
	Hex   string
}

var accentPalette = []Accent{
	{ID: "forest", Label: "Forest", Hex: "#3f6b4f"},
	{ID: "ocean", Label: "Ocean", Hex: "#315f8c"},
	{ID: "teal", Label: "Teal", Hex: "#27736b"},
	{ID: "violet", Label: "Violet", Hex: "#684f8c"},
	{ID: "rose", Label: "Rose", Hex: "#8c455c"},
	{ID: "ember", Label: "Ember", Hex: "#94532f"},
	{ID: "slate", Label: "Slate", Hex: "#485363"},
}

type Settings struct {
	Name               string
	Tagline            string
	Accent             string
	LandingPageEnabled bool
	UpdatedAt          time.Time
}

type Actor struct {
	UserID   string
	Username string
	ClientIP string
}

type Repository interface {
	BrandingSettings(context.Context) (Settings, error)
	SaveBrandingSettings(context.Context, Settings, Actor) error
}

type Service struct {
	repository Repository
	now        func() time.Time
	current    atomic.Pointer[Settings]
	updateMu   sync.Mutex
}

func NewService(ctx context.Context, repository Repository, fallbackName string) (*Service, error) {
	if repository == nil {
		return nil, errors.New("branding repository is required")
	}
	fallbackName = normalizeText(fallbackName)
	if err := validateText(fallbackName, 1, MaxNameRunes); err != nil {
		return nil, errors.New("valid branding fallback name is required")
	}
	settings, err := repository.BrandingSettings(ctx)
	if err != nil {
		return nil, err
	}
	settings = withDefaults(settings, fallbackName)
	settings, err = Normalize(settings)
	if err != nil {
		return nil, errors.New("stored branding settings are invalid")
	}
	service := &Service{repository: repository, now: time.Now}
	service.current.Store(&settings)
	return service, nil
}

func (s *Service) Current() Settings {
	return *s.current.Load()
}

func (s *Service) Update(ctx context.Context, settings Settings, actor Actor) (Settings, error) {
	normalized, err := Normalize(settings)
	if err != nil {
		return Settings{}, err
	}
	if actor.UserID == "" || actor.Username == "" || len(actor.UserID) > 64 ||
		len(actor.Username) > 64 || len(actor.ClientIP) > 128 {
		return Settings{}, errors.New("branding actor is invalid")
	}
	normalized.UpdatedAt = s.now().UTC()

	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if err := s.repository.SaveBrandingSettings(ctx, normalized, actor); err != nil {
		return Settings{}, err
	}
	s.current.Store(&normalized)
	return normalized, nil
}

func Normalize(settings Settings) (Settings, error) {
	settings.Name = normalizeText(settings.Name)
	settings.Tagline = normalizeText(settings.Tagline)
	settings.Accent = strings.ToLower(strings.TrimSpace(settings.Accent))
	if err := validateText(settings.Name, 1, MaxNameRunes); err != nil {
		return Settings{}, ErrInvalidSettings
	}
	if err := validateText(settings.Tagline, 1, MaxTaglineRunes); err != nil {
		return Settings{}, ErrInvalidSettings
	}
	if _, ok := AccentByID(settings.Accent); !ok {
		return Settings{}, ErrInvalidSettings
	}
	return settings, nil
}

func Accents() []Accent {
	return append([]Accent(nil), accentPalette...)
}

func AccentByID(id string) (Accent, bool) {
	for _, accent := range accentPalette {
		if accent.ID == id {
			return accent, true
		}
	}
	return Accent{}, false
}

func withDefaults(settings Settings, fallbackName string) Settings {
	if strings.TrimSpace(settings.Name) == "" {
		settings.Name = fallbackName
	}
	if strings.TrimSpace(settings.Tagline) == "" {
		settings.Tagline = DefaultTagline
	}
	if strings.TrimSpace(settings.Accent) == "" {
		settings.Accent = DefaultAccent
	}
	return settings
}

func normalizeText(value string) string {
	return norm.NFC.String(strings.TrimSpace(value))
}

func validateText(value string, minimum, maximum int) error {
	if !utf8.ValidString(value) {
		return ErrInvalidSettings
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return ErrInvalidSettings
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.In(char, unicode.Zl, unicode.Zp) {
			return ErrInvalidSettings
		}
	}
	return nil
}
