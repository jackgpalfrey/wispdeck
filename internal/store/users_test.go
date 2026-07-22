package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func TestInitialUserCreationIsSingleUseAndAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	initialized, err := database.InstallationInitialized(ctx)
	if err != nil || initialized {
		t.Fatalf("fresh initialization state = (%v, %v)", initialized, err)
	}
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	created, err := database.CreateInitialUser(ctx, "owner", "password-hash", "192.0.2.8", now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Username != "owner" || created.Role != auth.RoleSuperuser || created.Status != auth.UserActive {
		t.Fatalf("initial user = %+v", created)
	}
	initialized, err = database.InstallationInitialized(ctx)
	if err != nil || !initialized {
		t.Fatalf("initialized state = (%v, %v)", initialized, err)
	}
	if _, err := database.CreateInitialUser(
		ctx, "attacker", "other-hash", "198.51.100.4", now,
	); !errors.Is(err, auth.ErrAlreadyInitialized) {
		t.Fatalf("second initial user error = %v", err)
	}
	events, err := database.AuthEventsByUser(ctx, created.ID, 10)
	if err != nil || len(events) != 1 || events[0].Kind != "initial_superuser_created" ||
		events[0].ClientIP != "192.0.2.8" {
		t.Fatalf("initial user events = (%+v, %v)", events, err)
	}
}

func TestConcurrentInitialUserCreationHasOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, username := range []string{"alice", "mallory"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := database.CreateInitialUser(ctx, username, "password-hash", "192.0.2.1", time.Now())
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var succeeded, alreadyInitialized int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, auth.ErrAlreadyInitialized):
			alreadyInitialized++
		default:
			t.Fatalf("unexpected concurrent creation error: %v", err)
		}
	}
	if succeeded != 1 || alreadyInitialized != 1 {
		t.Fatalf("concurrent results: succeeded=%d already_initialized=%d", succeeded, alreadyInitialized)
	}
}

func TestManagedUserLifecycleAndLastSuperuserInvariant(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	alice, err := database.CreateUser(ctx, "alice", "alice-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	if alice.Role != auth.RoleSuperuser || alice.Status != auth.UserActive {
		t.Fatalf("initial local user = %#v", alice)
	}
	if _, err := database.UpdateUserRole(ctx, alice.ID, auth.RoleUser, now); !errors.Is(err, auth.ErrLastSuperuser) {
		t.Fatalf("final-superuser demotion error = %v", err)
	}
	if _, err := database.UpdateUserStatus(ctx, alice.ID, auth.UserDisabled, now); !errors.Is(err, auth.ErrLastSuperuser) {
		t.Fatalf("final-superuser disable error = %v", err)
	}

	bob, err := database.CreateManagedUser(ctx, "bob", "bob-hash", auth.RoleSuperuser, auth.UserActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpdateUserRole(ctx, alice.ID, auth.RoleUser, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	aliceToken, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	aliceDigest := auth.TokenDigest(aliceToken)
	if err := database.CreateSession(ctx, auth.SessionRecord{
		TokenHash: aliceDigest, UserID: alice.ID, CSRFToken: aliceToken,
		Assurance: auth.AssuranceMFA, CreatedAt: now, AuthenticatedAt: now,
		LastSeen: now, ExpiresAt: now.Add(time.Hour), ClientIP: "192.0.2.1", UserAgent: "browser",
	}); err != nil {
		t.Fatal(err)
	}
	aliceSession, err := database.SessionByTokenHash(ctx, aliceDigest)
	if err != nil || aliceSession.User.Role != auth.RoleUser {
		t.Fatalf("role-aware session = (%#v, %v)", aliceSession, err)
	}
	if _, err := database.UpdateUserRole(ctx, alice.ID, auth.RoleSuperuser, now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}

	token, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	digest := auth.TokenDigest(token)
	if err := database.CreateSession(ctx, auth.SessionRecord{
		TokenHash: digest, UserID: bob.ID, CSRFToken: token,
		Assurance: auth.AssuranceMFA, CreatedAt: now, AuthenticatedAt: now,
		LastSeen: now, ExpiresAt: now.Add(time.Hour), ClientIP: "192.0.2.1", UserAgent: "browser",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpdateUserStatus(ctx, bob.ID, auth.UserDisabled, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SessionByTokenHash(ctx, digest); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("disabled-user session error = %v", err)
	}
	lateToken, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateSession(ctx, auth.SessionRecord{
		TokenHash: auth.TokenDigest(lateToken), UserID: bob.ID, CSRFToken: lateToken,
		Assurance: auth.AssuranceMFA, CreatedAt: now, AuthenticatedAt: now,
		LastSeen: now, ExpiresAt: now.Add(time.Hour), ClientIP: "192.0.2.1", UserAgent: "browser",
	}); err == nil {
		t.Fatal("created a session for a disabled user")
	}
	if _, err := database.UserByUsername(ctx, "bob"); err != nil {
		t.Fatalf("disabled user lookup failed: %v", err)
	}
}

func TestPendingUserSetupIsSingleUse(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	creator, err := database.CreateUser(ctx, "alice", "alice-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	record := auth.SetupTokenRecord{
		TokenHash: auth.TokenDigest(token), CreatedByUserID: creator.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	pending, err := database.CreatePendingUser(ctx, "bob", "placeholder-hash", auth.RoleUser, record)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != auth.UserPending {
		t.Fatalf("pending user = %#v", pending)
	}
	setup, err := database.SetupByTokenHash(ctx, record.TokenHash, now)
	if err != nil || setup.UserID != pending.ID {
		t.Fatalf("setup lookup = (%#v, %v)", setup, err)
	}
	active, err := database.CompleteUserSetup(ctx, record.TokenHash, "permanent-hash", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != auth.UserActive || active.PasswordHash != "permanent-hash" {
		t.Fatalf("completed user = %#v", active)
	}
	if _, err := database.CompleteUserSetup(ctx, record.TokenHash, "other-hash", now.Add(2*time.Minute)); !errors.Is(err, auth.ErrInvalidSetupToken) {
		t.Fatalf("reused setup token error = %v", err)
	}
}
