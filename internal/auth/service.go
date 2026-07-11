package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidSession     = errors.New("invalid session")
	ErrUserNotFound       = errors.New("user not found")
)

const dummyPassword = "wispdeck-dummy-password-verification-only"

type User struct {
	ID           string
	Username     string
	PasswordHash string
}

type Principal struct {
	ID       string
	Username string
}

type Session struct {
	TokenHash [32]byte
	User      Principal
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

type SessionRecord struct {
	TokenHash [32]byte
	UserID    string
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

type Repository interface {
	UserByUsername(context.Context, string) (User, error)
	UpdatePasswordHash(context.Context, string, string, time.Time) error
	CreateSession(context.Context, SessionRecord) error
	SessionByTokenHash(context.Context, [32]byte) (Session, error)
	TouchSession(context.Context, [32]byte, time.Time) error
	DeleteSession(context.Context, [32]byte) error
	RecordAuthEvent(context.Context, AuthEvent) error
}

type AuthEvent struct {
	OccurredAt time.Time
	Kind       string
	Username   string
	UserID     string
	ClientIP   string
}

type Service struct {
	repository       Repository
	now              func() time.Time
	dummyHash        string
	idleTimeout      time.Duration
	absoluteLifetime time.Duration
	logger           *slog.Logger
}

func NewService(repository Repository) (*Service, error) {
	dummyHash, err := HashPassword(dummyPassword)
	if err != nil {
		return nil, fmt.Errorf("create dummy password hash: %w", err)
	}
	return &Service{
		repository:       repository,
		now:              time.Now,
		dummyHash:        dummyHash,
		idleTimeout:      30 * time.Minute,
		absoluteLifetime: 12 * time.Hour,
		logger:           slog.Default(),
	}, nil
}

// Login verifies credentials and creates a new server-side session. clientIP
// is used only for the security audit event and must already be derived from a
// trusted transport boundary.
func (s *Service) Login(ctx context.Context, username, password, clientIP string) (string, Session, error) {
	normalized := NormalizeUsername(username)
	user, err := s.repository.UserByUsername(ctx, normalized)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return "", Session{}, fmt.Errorf("load user: %w", err)
	}

	storedHash := s.dummyHash
	if err == nil {
		storedHash = user.PasswordHash
	}
	matched, verifyErr := VerifyPassword(password, storedHash)
	if verifyErr != nil {
		return "", Session{}, fmt.Errorf("verify stored password hash: %w", verifyErr)
	}
	if err != nil || !matched {
		auditUsername := normalized
		if ValidateUsername(auditUsername) != nil {
			auditUsername = ""
		}
		s.recordEvent(ctx, AuthEvent{
			OccurredAt: s.now().UTC(), Kind: "login_failed", Username: auditUsername, ClientIP: clientIP,
		})
		return "", Session{}, ErrInvalidCredentials
	}

	now := s.now().UTC()
	if PasswordHashNeedsUpgrade(user.PasswordHash) {
		upgraded, hashErr := HashPassword(password)
		if hashErr != nil {
			return "", Session{}, fmt.Errorf("upgrade password hash: %w", hashErr)
		}
		if updateErr := s.repository.UpdatePasswordHash(ctx, user.ID, upgraded, now); updateErr != nil {
			return "", Session{}, fmt.Errorf("store upgraded password hash: %w", updateErr)
		}
		user.PasswordHash = upgraded
	}

	token, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	csrfToken, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	record := SessionRecord{
		TokenHash: TokenDigest(token),
		UserID:    user.ID,
		CSRFToken: csrfToken,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(s.absoluteLifetime),
	}
	if err := s.repository.CreateSession(ctx, record); err != nil {
		return "", Session{}, fmt.Errorf("create session: %w", err)
	}
	session := Session{
		TokenHash: record.TokenHash,
		User:      Principal{ID: user.ID, Username: user.Username},
		CSRFToken: record.CSRFToken,
		CreatedAt: record.CreatedAt,
		LastSeen:  record.LastSeen,
		ExpiresAt: record.ExpiresAt,
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "login_succeeded", Username: user.Username, UserID: user.ID, ClientIP: clientIP,
	})
	return token, session, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (Session, error) {
	if !ValidToken(token) {
		return Session{}, ErrInvalidSession
	}
	digest := TokenDigest(token)
	session, err := s.repository.SessionByTokenHash(ctx, digest)
	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			return Session{}, ErrInvalidSession
		}
		return Session{}, fmt.Errorf("load session: %w", err)
	}
	now := s.now().UTC()
	if !now.Before(session.ExpiresAt) || now.Sub(session.LastSeen) >= s.idleTimeout {
		_ = s.repository.DeleteSession(ctx, digest)
		return Session{}, ErrInvalidSession
	}
	if now.Sub(session.LastSeen) >= time.Minute {
		if err := s.repository.TouchSession(ctx, digest, now); err != nil {
			return Session{}, fmt.Errorf("touch session: %w", err)
		}
		session.LastSeen = now
	}
	return session, nil
}

func (s *Service) Logout(ctx context.Context, session Session, clientIP string) error {
	if err := s.repository.DeleteSession(ctx, session.TokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "logout", Username: session.User.Username, UserID: session.User.ID, ClientIP: clientIP,
	})
	return nil
}

func (s *Service) recordEvent(ctx context.Context, event AuthEvent) {
	// Authentication must not fail merely because its audit trail cannot be
	// written. Log a failed best-effort write without changing the credential
	// path or exposing the failure to a remote caller.
	if err := s.repository.RecordAuthEvent(ctx, event); err != nil {
		s.logger.ErrorContext(ctx, "record authentication event", "kind", event.Kind, "error", err)
	}
}

// setClock is intentionally available only to this package's tests. Production
// always uses time.Now.
func (s *Service) setClock(now func() time.Time) {
	s.now = now
}
