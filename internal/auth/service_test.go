package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type memoryRepository struct {
	user     User
	sessions map[[32]byte]Session
	events   []AuthEvent
}

func (r *memoryRepository) UserByUsername(_ context.Context, username string) (User, error) {
	if username != r.user.Username {
		return User{}, ErrUserNotFound
	}
	return r.user, nil
}

func (r *memoryRepository) UserByID(_ context.Context, userID string) (User, error) {
	if userID != r.user.ID {
		return User{}, ErrUserNotFound
	}
	return r.user, nil
}

func (r *memoryRepository) UpdatePasswordHash(_ context.Context, userID, hash string, _ time.Time) error {
	if userID != r.user.ID {
		return ErrUserNotFound
	}
	r.user.PasswordHash = hash
	return nil
}

func (r *memoryRepository) ChangePasswordAndRevoke(_ context.Context, userID, hash string, _ time.Time) error {
	if userID != r.user.ID {
		return ErrUserNotFound
	}
	r.user.PasswordHash = hash
	clear(r.sessions)
	return nil
}

func (r *memoryRepository) CreateSession(_ context.Context, record SessionRecord) error {
	r.sessions[record.TokenHash] = Session{
		TokenHash: record.TokenHash,
		User: Principal{
			ID:       r.user.ID,
			Username: r.user.Username,
		},
		CSRFToken:       record.CSRFToken,
		Assurance:       record.Assurance,
		CreatedAt:       record.CreatedAt,
		AuthenticatedAt: record.AuthenticatedAt,
		LastSeen:        record.LastSeen,
		ExpiresAt:       record.ExpiresAt,
		ClientIP:        record.ClientIP,
		UserAgent:       record.UserAgent,
	}
	return nil
}

func (r *memoryRepository) SessionByTokenHash(_ context.Context, digest [32]byte) (Session, error) {
	session, ok := r.sessions[digest]
	if !ok {
		return Session{}, ErrInvalidSession
	}
	return session, nil
}

func (r *memoryRepository) TouchSession(_ context.Context, digest [32]byte, now time.Time) error {
	session, ok := r.sessions[digest]
	if !ok {
		return ErrInvalidSession
	}
	session.LastSeen = now
	r.sessions[digest] = session
	return nil
}

func (r *memoryRepository) DeleteSession(_ context.Context, digest [32]byte) error {
	delete(r.sessions, digest)
	return nil
}

func (r *memoryRepository) SessionsByUser(_ context.Context, userID string) ([]SessionSummary, error) {
	var summaries []SessionSummary
	for _, session := range r.sessions {
		if session.User.ID == userID {
			summaries = append(summaries, SessionSummary{
				TokenHash: session.TokenHash, Assurance: session.Assurance,
				CreatedAt: session.CreatedAt, AuthenticatedAt: session.AuthenticatedAt,
				LastSeen: session.LastSeen, ExpiresAt: session.ExpiresAt,
				ClientIP: session.ClientIP, UserAgent: session.UserAgent,
			})
		}
	}
	return summaries, nil
}

func (r *memoryRepository) DeleteOtherSessions(_ context.Context, userID string, keep [32]byte) error {
	for digest, session := range r.sessions {
		if session.User.ID == userID && digest != keep {
			delete(r.sessions, digest)
		}
	}
	return nil
}

func (r *memoryRepository) AuthEventsByUser(_ context.Context, userID string, limit int) ([]AuthEvent, error) {
	var events []AuthEvent
	for i := len(r.events) - 1; i >= 0 && len(events) < limit; i-- {
		if r.events[i].UserID == userID {
			events = append(events, r.events[i])
		}
	}
	return events, nil
}

func (r *memoryRepository) RecordAuthEvent(_ context.Context, event AuthEvent) error {
	r.events = append(r.events, event)
	return nil
}

func newServiceTest(t *testing.T) (*Service, *memoryRepository, *time.Time) {
	t.Helper()
	useFastPasswordParams(t)
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRepository{
		user:     User{ID: "user-1", Username: "alice", PasswordHash: hash},
		sessions: make(map[[32]byte]Session),
	}
	keys, err := NewKeyMaterial(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := NewPasswordManager(keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, passwords)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	service.setClock(func() time.Time { return now })
	return service, repository, &now
}

func TestServiceSessionIdleTimeout(t *testing.T) {
	service, repository, now := newServiceTest(t)
	token, _, err := service.Login(context.Background(), "Alice", "correct horse battery staple", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(29 * time.Minute)
	if _, err := service.Authenticate(context.Background(), token); err != nil {
		t.Fatalf("active session rejected: %v", err)
	}
	*now = now.Add(31 * time.Minute)
	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("idle session error = %v", err)
	}
	if len(repository.sessions) != 0 {
		t.Fatal("expired session was not deleted")
	}
}

func TestServiceSessionAbsoluteLifetime(t *testing.T) {
	service, _, now := newServiceTest(t)
	token, _, err := service.Login(context.Background(), "alice", "correct horse battery staple", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for range 24 {
		*now = now.Add(29 * time.Minute)
		if _, err := service.Authenticate(context.Background(), token); err != nil {
			t.Fatalf("session rejected before absolute expiry: %v", err)
		}
	}
	*now = now.Add(24 * time.Minute)
	if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("absolute-expiry error = %v", err)
	}
}

func TestServiceUsesGenericCredentialFailure(t *testing.T) {
	service, repository, _ := newServiceTest(t)
	for _, username := range []string{"alice", "unknown", string(make([]byte, 128))} {
		if _, _, err := service.Login(context.Background(), username, "incorrect password phrase", "192.0.2.1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login(%q) error = %v", username, err)
		}
	}
	if got := repository.events[len(repository.events)-1].Username; got != "" {
		t.Fatalf("invalid username persisted in audit event: %q", got)
	}
}

type allowPasswordChecker struct{}

func (allowPasswordChecker) Check(context.Context, string, PasswordContext) error { return nil }

func TestChangePasswordRequiresRecentMFAAndRevokesSessions(t *testing.T) {
	service, repository, _ := newServiceTest(t)
	user := repository.user
	_, session, err := service.NewSession(context.Background(), user, AssuranceMFA, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(
		context.Background(), session,
		"correct horse battery staple", "saffron-planetary-cello-woodland",
		allowPasswordChecker{}, PasswordContext{Username: "alice", Service: "wispdeck"},
	); err != nil {
		t.Fatal(err)
	}
	if len(repository.sessions) != 0 {
		t.Fatal("password change did not revoke sessions")
	}
	matched, err := service.passwords.Verify("saffron-planetary-cello-woodland", repository.user.PasswordHash)
	if err != nil || !matched {
		t.Fatalf("new password verification = (%v, %v)", matched, err)
	}
}

func TestChangePasswordRejectsBootstrapSession(t *testing.T) {
	service, repository, _ := newServiceTest(t)
	_, session, err := service.NewSession(context.Background(), repository.user, AssuranceBootstrap, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	err = service.ChangePassword(
		context.Background(), session,
		"correct horse battery staple", "saffron-planetary-cello-woodland",
		allowPasswordChecker{}, PasswordContext{},
	)
	if !errors.Is(err, ErrRecentMFARequired) {
		t.Fatalf("ChangePassword error = %v", err)
	}
}
