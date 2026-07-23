// Package site implements Wispdeck's immutable hosted-site policy and authorization.
package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
)

const (
	MaxTitleLength                = 120
	MaxUploadBytes                = 20 << 20
	MaxBundleBytes                = 50 << 20
	MaxFileBytes                  = 10 << 20
	MaxFiles                      = 500
	PreviewGrantLifetime          = 2 * time.Minute
	PreviewLifetime               = 8 * time.Hour
	DefaultMaxSitesPerUser        = 100
	DefaultMaxReleasesPerSite     = 25
	DefaultMaxStorageBytesPerUser = 1 << 30
)

var (
	ErrForbidden           = errors.New("site operation is forbidden")
	ErrNotFound            = errors.New("site not found")
	ErrNameUnavailable     = errors.New("that public name is already in use")
	ErrReclaimConfirmation = errors.New("confirm that you want to reuse this retired short name")
	ErrInvalidName         = errors.New("site name must use lowercase letters, numbers, or hyphens")
	ErrInvalidTitle        = fmt.Errorf("private title must not exceed %d characters or contain control characters", MaxTitleLength)
	ErrInvalidBundle       = errors.New("bundle must be a ZIP archive containing a root index.html")
	ErrBundleTooLarge      = fmt.Errorf("expanded bundle must not exceed %d MiB", MaxBundleBytes>>20)
	ErrTooManyFiles        = fmt.Errorf("bundle must not contain more than %d files", MaxFiles)
	ErrInvalidFile         = errors.New("bundle contains an invalid file")
	ErrNoDraft             = errors.New("site has no draft release")
	ErrInvalidPreview      = errors.New("preview access is invalid or expired")
	ErrSiteLimit           = errors.New("site limit reached")
	ErrReleaseLimit        = errors.New("release limit reached for this site")
	ErrStorageLimit        = errors.New("hosted-site storage limit reached")
	ErrSelectedRelease     = errors.New("the current draft or published release cannot be deleted")
)

type Limits struct {
	MaxSitesPerUser        int
	MaxReleasesPerSite     int
	MaxStorageBytesPerUser int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxSitesPerUser:        DefaultMaxSitesPerUser,
		MaxReleasesPerSite:     DefaultMaxReleasesPerSite,
		MaxStorageBytesPerUser: DefaultMaxStorageBytesPerUser,
	}
}

type Actor struct {
	UserID    string
	Superuser bool
}

type File struct {
	Path        string
	ContentType string
	Body        []byte
	Digest      [32]byte
}

type Bundle struct {
	Files      []File
	TotalBytes int64
	Digest     [32]byte
}

type Release struct {
	ID          string
	SiteID      string
	Version     int
	FileCount   int
	TotalBytes  int64
	Digest      [32]byte
	CreatedAt   time.Time
	PublishedAt time.Time
}

type Site struct {
	ID                 string
	OwnerUserID        string
	OwnerUsername      string
	Name               string
	Title              string
	Enabled            bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DraftReleaseID     string
	PublishedReleaseID string
	Releases           []Release
}

type CreateInput struct {
	Name             string
	Title            string
	ConfirmedReclaim string
}

type Usage struct {
	SiteReleases int
	SiteBytes    int64
	OwnerSites   int
	OwnerBytes   int64
	Limits       Limits
}

type Preview struct {
	Site               Site
	DraftReleaseID     string
	PublishedReleaseID string
	ExpiresAt          time.Time
}

type PreviewGrant struct {
	Code        string
	OriginLabel string
}

type Repository interface {
	CreateSite(context.Context, string, string, string, bool, Limits, time.Time) (Site, error)
	Sites(context.Context, string, bool) ([]Site, error)
	CreateSiteRelease(context.Context, string, bool, string, Bundle, Limits, time.Time) (Release, error)
	PublishSiteRelease(context.Context, string, bool, string, string, time.Time) error
	SetSiteEnabled(context.Context, string, bool, string, bool, time.Time) error
	SiteUsage(context.Context, string, bool, string) (Usage, error)
	DeleteSiteRelease(context.Context, string, bool, string, string, time.Time) error
	PurgeSiteContent(context.Context, string, bool, string, time.Time) error
	SiteByName(context.Context, string) (Site, error)
	SiteFile(context.Context, string, string) (File, error)
	CreateSitePreviewGrant(context.Context, string, bool, string, string, [32]byte, time.Time, time.Time) error
	ExchangeSitePreviewGrant(context.Context, string, [32]byte, [32]byte, time.Time, time.Time) (Preview, error)
	SitePreviewSession(context.Context, string, [32]byte, time.Time) (Preview, error)
}

type Service struct {
	repository Repository
	limits     Limits
	now        func() time.Time
}

func NewService(repository Repository, limits Limits) (*Service, error) {
	if repository == nil {
		return nil, errors.New("site repository is required")
	}
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if limits.MaxSitesPerUser < 1 || limits.MaxReleasesPerSite < 2 ||
		limits.MaxStorageBytesPerUser < MaxBundleBytes {
		return nil, errors.New("site limits are invalid")
	}
	return &Service{repository: repository, limits: limits, now: time.Now}, nil
}

func (s *Service) Limits() Limits { return s.limits }

func (s *Service) Create(ctx context.Context, actor Actor, name, title string) (Site, error) {
	return s.CreateWithInput(ctx, actor, CreateInput{Name: name, Title: title})
}

func (s *Service) CreateWithInput(ctx context.Context, actor Actor, input CreateInput) (Site, error) {
	if actor.UserID == "" {
		return Site{}, ErrForbidden
	}
	name, err := NormalizeName(input.Name)
	if err != nil {
		return Site{}, err
	}
	title, err := normalizeTitle(input.Title)
	if err != nil {
		return Site{}, err
	}
	confirmed, confirmedErr := NormalizeName(input.ConfirmedReclaim)
	allowReclaim := confirmedErr == nil && confirmed == name
	return s.repository.CreateSite(
		ctx, actor.UserID, name, title, allowReclaim, s.limits, s.now().UTC(),
	)
}

func (s *Service) List(ctx context.Context, actor Actor) ([]Site, error) {
	if actor.UserID == "" {
		return nil, ErrForbidden
	}
	return s.repository.Sites(ctx, actor.UserID, actor.Superuser)
}

func (s *Service) Upload(ctx context.Context, actor Actor, siteID string, bundle Bundle) (Release, error) {
	if actor.UserID == "" || !validID(siteID) {
		return Release{}, ErrNotFound
	}
	if err := ValidateBundle(bundle); err != nil {
		return Release{}, err
	}
	return s.repository.CreateSiteRelease(ctx, actor.UserID, actor.Superuser, siteID, bundle, s.limits, s.now().UTC())
}

func (s *Service) Publish(ctx context.Context, actor Actor, siteID, releaseID string) error {
	if actor.UserID == "" || !validID(siteID) || !validID(releaseID) {
		return ErrNotFound
	}
	return s.repository.PublishSiteRelease(ctx, actor.UserID, actor.Superuser, siteID, releaseID, s.now().UTC())
}

func (s *Service) SetEnabled(ctx context.Context, actor Actor, siteID string, enabled bool) error {
	if actor.UserID == "" || !validID(siteID) {
		return ErrNotFound
	}
	return s.repository.SetSiteEnabled(ctx, actor.UserID, actor.Superuser, siteID, enabled, s.now().UTC())
}

func (s *Service) Usage(ctx context.Context, actor Actor, siteID string) (Usage, error) {
	if actor.UserID == "" || !validID(siteID) {
		return Usage{}, ErrNotFound
	}
	usage, err := s.repository.SiteUsage(ctx, actor.UserID, actor.Superuser, siteID)
	if err != nil {
		return Usage{}, err
	}
	usage.Limits = s.limits
	return usage, nil
}

func (s *Service) DeleteRelease(ctx context.Context, actor Actor, siteID, releaseID string) error {
	if actor.UserID == "" || !validID(siteID) || !validID(releaseID) {
		return ErrNotFound
	}
	return s.repository.DeleteSiteRelease(
		ctx, actor.UserID, actor.Superuser, siteID, releaseID, s.now().UTC(),
	)
}

// PurgeContent removes every release while retaining the site and its public
// name for the original owner. An embedding host should take the site offline
// with this operation before separately purging associated data stores.
func (s *Service) PurgeContent(ctx context.Context, actor Actor, siteID string) error {
	if actor.UserID == "" || !validID(siteID) {
		return ErrNotFound
	}
	return s.repository.PurgeSiteContent(ctx, actor.UserID, actor.Superuser, siteID, s.now().UTC())
}

func (s *Service) SiteByName(ctx context.Context, name string) (Site, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Site{}, ErrNotFound
	}
	return s.repository.SiteByName(ctx, name)
}

func (s *Service) File(ctx context.Context, releaseID, filePath string) (File, error) {
	if !validID(releaseID) {
		return File{}, ErrNotFound
	}
	return s.repository.SiteFile(ctx, releaseID, filePath)
}

func (s *Service) GrantPreview(ctx context.Context, actor Actor, name string) (PreviewGrant, error) {
	if actor.UserID == "" {
		return PreviewGrant{}, ErrForbidden
	}
	name, err := NormalizeName(name)
	if err != nil {
		return PreviewGrant{}, ErrNotFound
	}
	token, err := auth.NewToken()
	if err != nil {
		return PreviewGrant{}, fmt.Errorf("generate site preview grant: %w", err)
	}
	originRandom, err := auth.NewToken()
	if err != nil {
		return PreviewGrant{}, fmt.Errorf("generate site preview origin: %w", err)
	}
	originDigest := auth.TokenDigest(originRandom)
	originLabel := "p" + hex.EncodeToString(originDigest[:16])
	now := s.now().UTC()
	err = s.repository.CreateSitePreviewGrant(
		ctx, actor.UserID, actor.Superuser, name, originLabel,
		auth.TokenDigest(token), now.Add(PreviewGrantLifetime), now,
	)
	if err != nil {
		return PreviewGrant{}, err
	}
	return PreviewGrant{Code: token, OriginLabel: originLabel}, nil
}

func (s *Service) ExchangePreview(ctx context.Context, originLabel, grant string) (string, Preview, error) {
	if !validPreviewOriginLabel(originLabel) || !auth.ValidToken(grant) {
		return "", Preview{}, ErrInvalidPreview
	}
	token, err := auth.NewToken()
	if err != nil {
		return "", Preview{}, fmt.Errorf("generate site preview session: %w", err)
	}
	now := s.now().UTC()
	preview, err := s.repository.ExchangeSitePreviewGrant(
		ctx, originLabel, auth.TokenDigest(grant), auth.TokenDigest(token), now.Add(PreviewLifetime), now,
	)
	if err != nil {
		return "", Preview{}, err
	}
	return token, preview, nil
}

func (s *Service) Preview(ctx context.Context, originLabel, token string) (Preview, error) {
	if !validPreviewOriginLabel(originLabel) || !auth.ValidToken(token) {
		return Preview{}, ErrInvalidPreview
	}
	return s.repository.SitePreviewSession(ctx, originLabel, auth.TokenDigest(token), s.now().UTC())
}

func validPreviewOriginLabel(value string) bool {
	if len(value) != 33 || value[0] != 'p' {
		return false
	}
	for _, char := range []byte(value[1:]) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func NormalizeName(value string) (string, error) {
	name, err := shortlink.NormalizeSlug(value)
	if errors.Is(err, shortlink.ErrReservedSlug) {
		return "", shortlink.ErrReservedSlug
	}
	if err != nil {
		return "", ErrInvalidName
	}
	return name, nil
}

func ValidateBundle(bundle Bundle) error {
	if len(bundle.Files) < 1 || len(bundle.Files) > MaxFiles {
		return ErrInvalidBundle
	}
	if bundle.TotalBytes < 1 || bundle.TotalBytes > MaxBundleBytes {
		return ErrBundleTooLarge
	}
	index := false
	seen := make(map[string]struct{}, len(bundle.Files))
	var total int64
	for _, file := range bundle.Files {
		clean, err := normalizeFilePath(file.Path)
		if err != nil || clean != file.Path {
			return ErrInvalidFile
		}
		key := strings.ToLower(clean)
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalidFile
		}
		seen[key] = struct{}{}
		if file.Path == "index.html" {
			index = true
		}
		if len(file.Body) > MaxFileBytes || file.ContentType == "" || len(file.ContentType) > 255 ||
			strings.ContainsAny(file.ContentType, "\r\n\x00") || sha256.Sum256(file.Body) != file.Digest {
			return ErrInvalidFile
		}
		total += int64(len(file.Body))
		if total > MaxBundleBytes {
			return ErrBundleTooLarge
		}
	}
	if !index || total != bundle.TotalBytes || calculateBundleDigest(bundle.Files) != bundle.Digest {
		return ErrInvalidBundle
	}
	return nil
}

func normalizeTitle(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxTitleLength {
		return "", ErrInvalidTitle
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return "", ErrInvalidTitle
		}
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
