package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidSession     = errors.New("invalid session")
	ErrUserNotFound       = errors.New("user not found")
	ErrPasswordMismatch   = errors.New("current password is incorrect")
	ErrForbidden          = errors.New("forbidden")
	ErrLastSuperuser      = errors.New("cannot remove the final active superuser")
	ErrInvalidSetupToken  = errors.New("invalid or expired setup token")
	ErrInvalidUserState   = errors.New("invalid user state transition")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidRole        = errors.New("invalid role")
)

// #nosec G101 -- this fixed, non-secret input equalizes verification timing for unknown accounts.
const dummyPassword = "wispdeck-dummy-password-verification-only"

type User struct {
	ID           string
	Username     string
	PasswordHash string
	MFASkipped   bool
	Role         Role
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Principal struct {
	ID       string
	Username string
	Role     Role
}

type Role string

const (
	RoleUser      Role = "user"
	RoleSuperuser Role = "superuser"
)

func ValidRole(role Role) bool {
	return role == RoleUser || role == RoleSuperuser
}

type UserStatus string

const (
	UserPending  UserStatus = "pending"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

func ValidUserStatus(status UserStatus) bool {
	return status == UserPending || status == UserActive || status == UserDisabled
}

type Assurance string

const (
	AssuranceBootstrap Assurance = "bootstrap"
	AssurancePassword  Assurance = "password"
	AssuranceMFA       Assurance = "mfa"
	AssuranceRecovery  Assurance = "recovery"
)

type Session struct {
	TokenHash       [32]byte
	User            Principal
	CSRFToken       string
	Assurance       Assurance
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeen        time.Time
	ExpiresAt       time.Time
	ClientIP        string
	UserAgent       string
}

type SessionRecord struct {
	TokenHash       [32]byte
	UserID          string
	CSRFToken       string
	Assurance       Assurance
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeen        time.Time
	ExpiresAt       time.Time
	ClientIP        string
	UserAgent       string
}

type Repository interface {
	UserByUsername(context.Context, string) (User, error)
	UserByID(context.Context, string) (User, error)
	UpdatePasswordHash(context.Context, string, string, time.Time) error
	ChangePasswordAndRevoke(context.Context, string, string, time.Time) error
	CreateSession(context.Context, SessionRecord) error
	SessionByTokenHash(context.Context, [32]byte) (Session, error)
	TouchSession(context.Context, [32]byte, time.Time) error
	DeleteSession(context.Context, [32]byte) error
	SessionsByUser(context.Context, string) ([]SessionSummary, error)
	DeleteOtherSessions(context.Context, string, [32]byte) error
	AuthEventsByUser(context.Context, string, int) ([]AuthEvent, error)
	RecordAuthEvent(context.Context, AuthEvent) error
	Users(context.Context) ([]UserSummary, error)
	CreateManagedUser(context.Context, string, string, Role, UserStatus, time.Time) (User, error)
	CreatePendingUser(context.Context, string, string, Role, SetupTokenRecord) (User, error)
	SetupByTokenHash(context.Context, [32]byte, time.Time) (UserSetup, error)
	CompleteUserSetup(context.Context, [32]byte, string, time.Time) (User, error)
	ReplaceUserSetupToken(context.Context, string, SetupTokenRecord) error
	UpdateUserRole(context.Context, string, Role, time.Time) (User, error)
	UpdateUserStatus(context.Context, string, UserStatus, time.Time) (User, error)
	DeleteUserSession(context.Context, string, [32]byte) error
}

type AuthEvent struct {
	OccurredAt time.Time
	Kind       string
	Username   string
	UserID     string
	ClientIP   string
	Details    string
}

type Service struct {
	repository       Repository
	now              func() time.Time
	dummyHash        string
	idleTimeout      time.Duration
	absoluteLifetime time.Duration
	logger           *slog.Logger
	passwords        *PasswordManager
}

func NewService(repository Repository, passwords *PasswordManager) (*Service, error) {
	if passwords == nil {
		return nil, errors.New("password manager is required")
	}
	dummyHash, err := passwords.Hash(dummyPassword)
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
		passwords:        passwords,
	}, nil
}

func (s *Service) VerifyCredentials(ctx context.Context, username, password, clientIP string) (User, error) {
	normalized := NormalizeUsername(username)
	user, err := s.repository.UserByUsername(ctx, normalized)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return User{}, fmt.Errorf("load user: %w", err)
	}

	storedHash := s.dummyHash
	if err == nil {
		storedHash = user.PasswordHash
	}
	matched, verifyErr := s.passwords.Verify(password, storedHash)
	if verifyErr != nil {
		return User{}, fmt.Errorf("verify stored password hash: %w", verifyErr)
	}
	if err != nil || !matched || user.Status != UserActive {
		auditUsername := normalized
		auditUserID := ""
		if ValidateUsername(auditUsername) != nil {
			auditUsername = ""
		}
		if err == nil {
			auditUserID = user.ID
		}
		s.recordEvent(ctx, AuthEvent{
			OccurredAt: s.now().UTC(), Kind: "login_failed", Username: auditUsername,
			UserID: auditUserID, ClientIP: clientIP,
		})
		return User{}, ErrInvalidCredentials
	}

	now := s.now().UTC()
	if s.passwords.NeedsUpgrade(user.PasswordHash) {
		upgraded, hashErr := s.passwords.Hash(password)
		if hashErr != nil {
			return User{}, fmt.Errorf("upgrade password hash: %w", hashErr)
		}
		if updateErr := s.repository.UpdatePasswordHash(ctx, user.ID, upgraded, now); updateErr != nil {
			return User{}, fmt.Errorf("store upgraded password hash: %w", updateErr)
		}
		user.PasswordHash = upgraded
	}

	return user, nil
}

func (s *Service) NewSession(ctx context.Context, user User, assurance Assurance, clientIP, userAgent string) (string, Session, error) {
	if assurance != AssuranceBootstrap && assurance != AssurancePassword && assurance != AssuranceMFA && assurance != AssuranceRecovery {
		return "", Session{}, errors.New("invalid session assurance")
	}
	now := s.now().UTC()
	userAgent = boundedUserAgent(userAgent)
	token, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	csrfToken, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	record := SessionRecord{
		TokenHash:       TokenDigest(token),
		UserID:          user.ID,
		CSRFToken:       csrfToken,
		Assurance:       assurance,
		CreatedAt:       now,
		AuthenticatedAt: now,
		LastSeen:        now,
		ExpiresAt:       now.Add(s.absoluteLifetime),
		ClientIP:        clientIP,
		UserAgent:       userAgent,
	}
	if err := s.repository.CreateSession(ctx, record); err != nil {
		return "", Session{}, fmt.Errorf("create session: %w", err)
	}
	session := Session{
		TokenHash:       record.TokenHash,
		User:            Principal{ID: user.ID, Username: user.Username, Role: user.Role},
		CSRFToken:       record.CSRFToken,
		Assurance:       record.Assurance,
		CreatedAt:       record.CreatedAt,
		AuthenticatedAt: record.AuthenticatedAt,
		LastSeen:        record.LastSeen,
		ExpiresAt:       record.ExpiresAt,
		ClientIP:        record.ClientIP,
		UserAgent:       record.UserAgent,
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "login_succeeded", Username: user.Username, UserID: user.ID, ClientIP: clientIP,
	})
	return token, session, nil
}

func boundedUserAgent(value string) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= 512 {
		return value
	}
	value = value[:512]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
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

func (s *Service) ChangePassword(
	ctx context.Context,
	session Session,
	currentPassword, newPassword string,
	checker PasswordChecker,
	passwordContext PasswordContext,
) error {
	if session.Assurance == AssuranceRecovery {
		return ErrForbidden
	}
	user, err := s.repository.UserByID(ctx, session.User.ID)
	if err != nil {
		return fmt.Errorf("load user for password change: %w", err)
	}
	matched, err := s.passwords.Verify(currentPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify current password: %w", err)
	}
	if !matched {
		return ErrPasswordMismatch
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if checker != nil {
		if err := checker.Check(ctx, newPassword, passwordContext); err != nil {
			return err
		}
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if err := s.repository.ChangePasswordAndRevoke(ctx, user.ID, hash, now); err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "password_changed", Username: user.Username,
		UserID: user.ID, ClientIP: session.ClientIP,
	})
	return nil
}

func (s *Service) Sessions(ctx context.Context, session Session) ([]SessionSummary, error) {
	return s.repository.SessionsByUser(ctx, session.User.ID)
}

func (s *Service) RevokeOtherSessions(ctx context.Context, session Session) error {
	if err := s.repository.DeleteOtherSessions(ctx, session.User.ID, session.TokenHash); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "sessions_revoked", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP,
	})
	return nil
}

func (s *Service) RevokeSession(ctx context.Context, session Session, digest [32]byte) error {
	if err := s.repository.DeleteUserSession(ctx, session.User.ID, digest); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "session_revoked", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP, Details: fmt.Sprintf("session=%x", digest[:8]),
	})
	return nil
}

func (s *Service) Events(ctx context.Context, session Session, limit int) ([]AuthEvent, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("audit event limit must be between 1 and 100")
	}
	return s.repository.AuthEventsByUser(ctx, session.User.ID, limit)
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
