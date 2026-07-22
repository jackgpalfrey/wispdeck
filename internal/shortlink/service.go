// Package shortlink implements Wispdeck's short-link policy and authorization.
package shortlink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	MinSlugLength          = 1
	MaxSlugLength          = 48
	MaxTargetLength        = 4096
	MaxTitleLength         = 120
	MaxDescriptionLength   = 1000
	MaxLabelLength         = 120
	MaxDestinations        = 25
	StatsWindowDays        = 30
	DefaultMaxLinksPerUser = 1_000
	automaticLength        = 10
	maxPendingBuckets      = 10_000
)

var (
	ErrForbidden           = errors.New("short-link operation is forbidden")
	ErrNotFound            = errors.New("short link not found")
	ErrSlugUnavailable     = errors.New("that short name is already in use")
	ErrInvalidSlug         = fmt.Errorf("short name must be %d to %d characters using lowercase letters, numbers, or hyphens", MinSlugLength, MaxSlugLength)
	ErrReservedSlug        = errors.New("that short name is reserved by Wispdeck")
	ErrInvalidTarget       = errors.New("destination must be an absolute HTTP or HTTPS URL without embedded credentials")
	ErrTargetTooLong       = fmt.Errorf("destination must not exceed %d bytes", MaxTargetLength)
	ErrInvalidMode         = errors.New("invalid short-link mode")
	ErrInvalidDestinations = fmt.Errorf("links must contain between 1 and %d destinations", MaxDestinations)
	ErrDuplicateTarget     = errors.New("the same destination cannot be included more than once")
	ErrInvalidTitle        = fmt.Errorf("private title must not exceed %d characters or contain control characters", MaxTitleLength)
	ErrInvalidDescription  = fmt.Errorf("private notes must not exceed %d characters or contain control characters", MaxDescriptionLength)
	ErrInvalidLabel        = fmt.Errorf("destination labels must not exceed %d characters or contain control characters", MaxLabelLength)
	ErrInvalidExpiry       = errors.New("expiry must be a future UTC date and time")
	ErrLinkLimit           = errors.New("short-link limit reached")
)

type Limits struct {
	MaxLinksPerUser int
}

func DefaultLimits() Limits { return Limits{MaxLinksPerUser: DefaultMaxLinksPerUser} }

var reservedSlugs = map[string]struct{}{
	"account":  {},
	"admin":    {},
	"api":      {},
	"assets":   {},
	"data":     {},
	"healthz":  {},
	"links":    {},
	"login":    {},
	"logout":   {},
	"security": {},
	"settings": {},
	"setup":    {},
	"sites":    {},
}

type Mode string

const (
	ModeRedirect Mode = "redirect"
	ModeIndex    Mode = "index"
	ModeOpenAll  Mode = "open_all"
)

func ValidMode(mode Mode) bool {
	return mode == ModeRedirect || mode == ModeIndex || mode == ModeOpenAll
}

// Actor is the authenticated authority used for management operations.
type Actor struct {
	UserID    string
	Superuser bool
}

type Destination struct {
	ID       string
	Label    string
	URL      string
	Position int
}

// Link is a managed redirect or public multi-destination page. Title and
// Description are private control-plane metadata and must never be rendered by
// a public link handler.
type Link struct {
	ID            string
	OwnerUserID   string
	OwnerUsername string
	Slug          string
	Title         string
	Description   string
	Mode          Mode
	Destinations  []Destination
	Enabled       bool
	VisitCount    int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     time.Time
	LastVisitedAt time.Time
	DailyStats    []DailyStat
}

type Input struct {
	Slug         string
	Title        string
	Description  string
	Mode         Mode
	Destinations []Destination
	ExpiresAt    time.Time
}

type DailyStat struct {
	LinkID        string
	Day           time.Time
	Visits        int64
	LastVisitedAt time.Time
}

type VisitBucket struct {
	LinkID        string
	Day           time.Time
	Visits        int64
	LastVisitedAt time.Time
}

type AuditKind string

const (
	AuditUpdated  AuditKind = "updated"
	AuditEnabled  AuditKind = "enabled"
	AuditDisabled AuditKind = "disabled"
	AuditRetired  AuditKind = "retired"
)

type AuditEvent struct {
	OccurredAt    time.Time
	ActorUsername string
	OwnerUsername string
	Slug          string
	Kind          AuditKind
}

// Repository owns durable short-link state. Owner-aware mutations must apply
// their authorization predicate in the same SQL statement as the mutation.
type Repository interface {
	CreateShortLink(context.Context, string, Link, Limits, time.Time) (Link, error)
	ShortLinks(context.Context, string, bool) ([]Link, error)
	UpdateShortLink(context.Context, string, string, bool, Input, time.Time) error
	SetShortLinkEnabled(context.Context, string, string, bool, bool, time.Time) error
	RetireShortLink(context.Context, string, string, bool, time.Time) error
	ResolveShortLink(context.Context, string, time.Time) (Link, error)
	AddShortLinkVisits(context.Context, []VisitBucket) error
	ShortLinkDailyStats(context.Context, string, bool, time.Time) ([]DailyStat, error)
	ShortLinkAuditEvents(context.Context, string, bool, int) ([]AuditEvent, error)
}

type Service struct {
	repository Repository
	limits     Limits
	now        func() time.Time
	counter    *visitCounter
	flushMu    sync.Mutex
}

func NewService(repository Repository, limits Limits) (*Service, error) {
	if repository == nil {
		return nil, errors.New("short-link repository is required")
	}
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if limits.MaxLinksPerUser < 1 {
		return nil, errors.New("short-link limits are invalid")
	}
	return &Service{
		repository: repository,
		limits:     limits,
		now:        time.Now,
		counter:    newVisitCounter(maxPendingBuckets),
	}, nil
}

func (s *Service) Limits() Limits { return s.limits }

// Create creates a link for the authenticated actor. An empty slug requests a
// cryptographically random one; explicit slugs are never silently replaced.
func (s *Service) Create(ctx context.Context, actor Actor, input Input) (Link, error) {
	if actor.UserID == "" {
		return Link{}, ErrForbidden
	}
	now := s.now().UTC()
	validated, err := s.validateInput(input, true, now)
	if err != nil {
		return Link{}, err
	}
	validated.Slug = strings.TrimSpace(validated.Slug)
	if validated.Slug != "" {
		validated.Slug, err = NormalizeSlug(validated.Slug)
		if err != nil {
			return Link{}, err
		}
		return s.repository.CreateShortLink(ctx, actor.UserID, linkFromInput(validated), s.limits, now)
	}

	for range 8 {
		validated.Slug, err = randomSlug()
		if err != nil {
			return Link{}, err
		}
		link, createErr := s.repository.CreateShortLink(ctx, actor.UserID, linkFromInput(validated), s.limits, now)
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
	links, err := s.repository.ShortLinks(ctx, actor.UserID, actor.Superuser)
	if err != nil {
		return nil, err
	}
	since := utcDay(s.now().UTC()).AddDate(0, 0, -(StatsWindowDays - 1))
	stats, err := s.repository.ShortLinkDailyStats(ctx, actor.UserID, actor.Superuser, since)
	if err != nil {
		return nil, err
	}
	pending := s.counter.snapshot()
	applyPendingTotals(links, pending)
	stats = append(stats, pending...)
	applyStats(links, stats)
	return links, nil
}

func (s *Service) AuditEvents(ctx context.Context, actor Actor, limit int) ([]AuditEvent, error) {
	if actor.UserID == "" {
		return nil, ErrForbidden
	}
	if limit < 1 || limit > 100 {
		limit = 25
	}
	return s.repository.ShortLinkAuditEvents(ctx, actor.UserID, actor.Superuser, limit)
}

func (s *Service) Update(ctx context.Context, actor Actor, id string, input Input) error {
	if actor.UserID == "" || !validID(id) {
		return ErrNotFound
	}
	now := s.now().UTC()
	validated, err := s.validateInput(input, false, now)
	if err != nil {
		return err
	}
	return s.repository.UpdateShortLink(ctx, id, actor.UserID, actor.Superuser, validated, now)
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

// Resolve loads a public link without writing to storage. A counted GET is
// recorded in a bounded in-memory buffer and later flushed in batches.
func (s *Service) Resolve(ctx context.Context, slug string, countVisit bool) (Link, error) {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return Link{}, ErrNotFound
	}
	now := s.now().UTC()
	link, err := s.repository.ResolveShortLink(ctx, slug, now)
	if errors.Is(err, ErrNotFound) {
		return Link{}, ErrNotFound
	}
	if err != nil {
		return Link{}, err
	}
	if err := validateStoredLink(&link); err != nil {
		return Link{}, fmt.Errorf("stored short link is invalid: %w", err)
	}
	if countVisit {
		s.counter.record(link.ID, now)
	}
	return link, nil
}

// FlushVisits persists pending aggregate counts. On failure, the drained
// buckets are merged back into the bounded buffer for a later retry.
func (s *Service) FlushVisits(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	buckets := s.counter.drain()
	if len(buckets) == 0 {
		return nil
	}
	if err := s.repository.AddShortLinkVisits(ctx, buckets); err != nil {
		s.counter.restore(buckets)
		return fmt.Errorf("flush short-link visits: %w", err)
	}
	return nil
}

func (s *Service) validateInput(input Input, creating bool, now time.Time) (Input, error) {
	if !ValidMode(input.Mode) {
		return Input{}, ErrInvalidMode
	}
	title, err := normalizeSingleLine(input.Title, MaxTitleLength, ErrInvalidTitle)
	if err != nil {
		return Input{}, err
	}
	description, err := normalizeDescription(input.Description)
	if err != nil {
		return Input{}, err
	}
	destinations, err := validateDestinations(input.Mode, input.Destinations)
	if err != nil {
		return Input{}, err
	}
	expiresAt := input.ExpiresAt
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
		if !expiresAt.After(now) {
			return Input{}, ErrInvalidExpiry
		}
	}
	slug := ""
	if creating {
		slug = input.Slug
	}
	return Input{
		Slug: slug, Title: title, Description: description, Mode: input.Mode,
		Destinations: destinations, ExpiresAt: expiresAt,
	}, nil
}

func linkFromInput(input Input) Link {
	return Link{
		Slug: input.Slug, Title: input.Title, Description: input.Description,
		Mode: input.Mode, Destinations: input.Destinations, ExpiresAt: input.ExpiresAt,
	}
}

func validateDestinations(mode Mode, values []Destination) ([]Destination, error) {
	if len(values) < 1 || len(values) > MaxDestinations || (mode == ModeRedirect && len(values) != 1) {
		return nil, ErrInvalidDestinations
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]Destination, 0, len(values))
	for i, destination := range values {
		target, err := ValidateTarget(destination.URL)
		if err != nil {
			return nil, fmt.Errorf("destination %d: %w", i+1, err)
		}
		if _, exists := seen[target]; exists {
			return nil, ErrDuplicateTarget
		}
		seen[target] = struct{}{}
		label, err := normalizeSingleLine(destination.Label, MaxLabelLength, ErrInvalidLabel)
		if err != nil {
			return nil, fmt.Errorf("destination %d: %w", i+1, err)
		}
		result = append(result, Destination{Label: label, URL: target, Position: i})
	}
	return result, nil
}

func validateStoredLink(link *Link) error {
	if !ValidMode(link.Mode) {
		return ErrInvalidMode
	}
	destinations, err := validateDestinations(link.Mode, link.Destinations)
	if err != nil {
		return err
	}
	link.Destinations = destinations
	return nil
}

func normalizeSingleLine(value string, max int, invalid error) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > max {
		return "", invalid
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return "", invalid
		}
	}
	return value, nil
}

func normalizeDescription(value string) (string, error) {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxDescriptionLength {
		return "", ErrInvalidDescription
	}
	for _, char := range value {
		if (char < 0x20 && char != '\n' && char != '\t') || char == 0x7f {
			return "", ErrInvalidDescription
		}
	}
	return value, nil
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

func applyStats(links []Link, stats []DailyStat) {
	byID := make(map[string]*Link, len(links))
	dayMaps := make(map[string]map[int64]*DailyStat, len(links))
	for i := range links {
		byID[links[i].ID] = &links[i]
		dayMaps[links[i].ID] = make(map[int64]*DailyStat)
	}
	for _, stat := range stats {
		link := byID[stat.LinkID]
		if link == nil || stat.Visits <= 0 {
			continue
		}
		day := utcDay(stat.Day)
		key := day.Unix()
		existing := dayMaps[stat.LinkID][key]
		if existing == nil {
			copy := DailyStat{LinkID: stat.LinkID, Day: day}
			existing = &copy
			dayMaps[stat.LinkID][key] = existing
		}
		existing.Visits += stat.Visits
		if stat.LastVisitedAt.After(existing.LastVisitedAt) {
			existing.LastVisitedAt = stat.LastVisitedAt
		}
	}
	for i := range links {
		for _, stat := range dayMaps[links[i].ID] {
			links[i].DailyStats = append(links[i].DailyStats, *stat)
		}
		sort.Slice(links[i].DailyStats, func(a, b int) bool {
			return links[i].DailyStats[a].Day.After(links[i].DailyStats[b].Day)
		})
	}
}

func applyPendingTotals(links []Link, stats []DailyStat) {
	byID := make(map[string]*Link, len(links))
	for i := range links {
		byID[links[i].ID] = &links[i]
	}
	for _, stat := range stats {
		link := byID[stat.LinkID]
		if link == nil || stat.Visits <= 0 {
			continue
		}
		if math.MaxInt64-link.VisitCount < stat.Visits {
			link.VisitCount = math.MaxInt64
		} else {
			link.VisitCount += stat.Visits
		}
		if stat.LastVisitedAt.After(link.LastVisitedAt) {
			link.LastVisitedAt = stat.LastVisitedAt
		}
	}
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

func utcDay(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

type visitKey struct {
	linkID string
	day    int64
}

type visitCounter struct {
	mu         sync.Mutex
	buckets    map[visitKey]VisitBucket
	maxBuckets int
}

func newVisitCounter(maxBuckets int) *visitCounter {
	return &visitCounter{buckets: make(map[visitKey]VisitBucket), maxBuckets: maxBuckets}
}

func (c *visitCounter) record(linkID string, now time.Time) {
	day := utcDay(now)
	key := visitKey{linkID: linkID, day: day.Unix()}
	c.mu.Lock()
	defer c.mu.Unlock()
	bucket, exists := c.buckets[key]
	if !exists && len(c.buckets) >= c.maxBuckets {
		return
	}
	if bucket.Visits < math.MaxInt64 {
		bucket.Visits++
	}
	bucket.LinkID = linkID
	bucket.Day = day
	if now.After(bucket.LastVisitedAt) {
		bucket.LastVisitedAt = now.UTC()
	}
	c.buckets[key] = bucket
}

func (c *visitCounter) snapshot() []DailyStat {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]DailyStat, 0, len(c.buckets))
	for _, bucket := range c.buckets {
		result = append(result, DailyStat(bucket))
	}
	return result
}

func (c *visitCounter) drain() []VisitBucket {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]VisitBucket, 0, len(c.buckets))
	for _, bucket := range c.buckets {
		result = append(result, bucket)
	}
	c.buckets = make(map[visitKey]VisitBucket)
	return result
}

func (c *visitCounter) restore(values []VisitBucket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, value := range values {
		key := visitKey{linkID: value.LinkID, day: utcDay(value.Day).Unix()}
		bucket, exists := c.buckets[key]
		if !exists && len(c.buckets) >= c.maxBuckets {
			continue
		}
		if math.MaxInt64-bucket.Visits < value.Visits {
			bucket.Visits = math.MaxInt64
		} else {
			bucket.Visits += value.Visits
		}
		bucket.LinkID = value.LinkID
		bucket.Day = utcDay(value.Day)
		if value.LastVisitedAt.After(bucket.LastVisitedAt) {
			bucket.LastVisitedAt = value.LastVisitedAt.UTC()
		}
		c.buckets[key] = bucket
	}
}
