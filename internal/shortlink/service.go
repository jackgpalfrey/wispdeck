// Package shortlink implements Wispdeck's short-link policy and authorization.
package shortlink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MinSlugLength   = 1
	MaxSlugLength   = 48
	MaxTargetLength = 4096
	automaticLength = 10
)

var (
	ErrForbidden       = errors.New("short-link operation is forbidden")
	ErrNotFound        = errors.New("short link not found")
	ErrSlugUnavailable = errors.New("that short name is already in use")
	ErrInvalidSlug     = fmt.Errorf("short name must be %d to %d characters using lowercase letters, numbers, or hyphens", MinSlugLength, MaxSlugLength)
	ErrReservedSlug    = errors.New("that short name is reserved by Wispdeck")
	ErrInvalidTarget   = errors.New("destination must be an absolute HTTP or HTTPS URL without embedded credentials")
	ErrTargetTooLong   = fmt.Errorf("destination must not exceed %d bytes", MaxTargetLength)
)

var reservedSlugs = map[string]struct{}{
	"account":  {},
	"admin":    {},
	"api":      {},
	"assets":   {},
	"data":     {},
	"links":    {},
	"login":    {},
	"logout":   {},
	"security": {},
	"settings": {},
	"setup":    {},
	"sites":    {},
}

// Actor is the authenticated authority used for management operations.
type Actor struct {
	UserID    string
	Superuser bool
}

// Link is a managed redirect. Slugs are globally unique within a deployment.
type Link struct {
	ID            string
	OwnerUserID   string
	OwnerUsername string
	Slug          string
	TargetURL     string
	Enabled       bool
	VisitCount    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastVisitedAt time.Time
}

// Repository owns durable short-link state. Owner-aware mutations must apply
// their authorization predicate in the same SQL statement as the mutation.
type Repository interface {
	CreateShortLink(context.Context, string, string, string, time.Time) (Link, error)
	ShortLinks(context.Context, string, bool) ([]Link, error)
	UpdateShortLinkTarget(context.Context, string, string, bool, string, time.Time) error
	SetShortLinkEnabled(context.Context, string, string, bool, bool, time.Time) error
	RetireShortLink(context.Context, string, string, bool, time.Time) error
	ResolveShortLink(context.Context, string, time.Time) (Link, error)
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("short-link repository is required")
	}
	return &Service{repository: repository, now: time.Now}, nil
}

// Create creates a link for the authenticated actor. An empty slug requests a
// cryptographically random one; explicit slugs are never silently replaced.
func (s *Service) Create(ctx context.Context, actor Actor, slug, target string) (Link, error) {
	if actor.UserID == "" {
		return Link{}, ErrForbidden
	}
	target, err := ValidateTarget(target)
	if err != nil {
		return Link{}, err
	}
	slug = strings.TrimSpace(slug)
	if slug != "" {
		slug, err = NormalizeSlug(slug)
		if err != nil {
			return Link{}, err
		}
		return s.repository.CreateShortLink(ctx, actor.UserID, slug, target, s.now().UTC())
	}

	for range 8 {
		slug, err = randomSlug()
		if err != nil {
			return Link{}, err
		}
		link, createErr := s.repository.CreateShortLink(ctx, actor.UserID, slug, target, s.now().UTC())
		if createErr == nil {
			return link, nil
		}
		if !errors.Is(createErr, ErrSlugUnavailable) {
			return Link{}, createErr
		}
	}
	return Link{}, errors.New("could not allocate a unique short name")
}

func (s *Service) List(ctx context.Context, actor Actor) ([]Link, error) {
	if actor.UserID == "" {
		return nil, ErrForbidden
	}
	return s.repository.ShortLinks(ctx, actor.UserID, actor.Superuser)
}

func (s *Service) UpdateTarget(ctx context.Context, actor Actor, id, target string) error {
	if actor.UserID == "" || !validID(id) {
		return ErrNotFound
	}
	target, err := ValidateTarget(target)
	if err != nil {
		return err
	}
	return s.repository.UpdateShortLinkTarget(ctx, id, actor.UserID, actor.Superuser, target, s.now().UTC())
}

func (s *Service) SetEnabled(ctx context.Context, actor Actor, id string, enabled bool) error {
	if actor.UserID == "" || !validID(id) {
		return ErrNotFound
	}
	return s.repository.SetShortLinkEnabled(ctx, id, actor.UserID, actor.Superuser, enabled, s.now().UTC())
}

func (s *Service) Retire(ctx context.Context, actor Actor, id string) error {
	if actor.UserID == "" || !validID(id) {
		return ErrNotFound
	}
	return s.repository.RetireShortLink(ctx, id, actor.UserID, actor.Superuser, s.now().UTC())
}

func (s *Service) Resolve(ctx context.Context, slug string) (Link, error) {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return Link{}, ErrNotFound
	}
	link, err := s.repository.ResolveShortLink(ctx, slug, s.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return Link{}, ErrNotFound
	}
	if err != nil {
		return Link{}, err
	}
	target, err := ValidateTarget(link.TargetURL)
	if err != nil {
		return Link{}, fmt.Errorf("stored short-link destination is invalid: %w", err)
	}
	link.TargetURL = target
	return link, nil
}

// NormalizeSlug returns the deployment-wide canonical slug.
func NormalizeSlug(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < MinSlugLength || len(value) > MaxSlugLength {
		return "", ErrInvalidSlug
	}
	for i, char := range []byte(value) {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return "", ErrInvalidSlug
		}
		if (i == 0 || i == len(value)-1) && char == '-' {
			return "", ErrInvalidSlug
		}
	}
	if _, reserved := reservedSlugs[value]; reserved {
		return "", ErrReservedSlug
	}
	return value, nil
}

// ValidateTarget accepts only navigation URLs and returns their trimmed form.
// Wispdeck never fetches the URL, so private and loopback destinations remain
// useful for deliberately private deployments without creating an SSRF path.
func ValidateTarget(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return "", ErrInvalidTarget
	}
	if len(value) > MaxTargetLength {
		return "", ErrTargetTooLong
	}
	for _, char := range value {
		if char <= 0x20 || char == 0x7f {
			return "", ErrInvalidTarget
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return "", ErrInvalidTarget
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", ErrInvalidTarget
	}
	return value, nil
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range []byte(value) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func randomSlug() (string, error) {
	const alphabet = "abcdefghjklmnpqrstuvwxyz23456789"
	random := make([]byte, automaticLength)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate short name: %w", err)
	}
	result := make([]byte, automaticLength)
	for i, value := range random {
		// The alphabet has 32 characters, so masking is unbiased.
		result[i] = alphabet[int(value)&31]
	}
	return string(result), nil
}
