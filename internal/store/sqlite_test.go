package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func TestSQLiteUserAndSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control", "wispdeck.db")
	database, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	user, err := database.CreateUser(ctx, "alice", "encoded-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser(ctx, "ALICE", "other-hash", now); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate user error = %v", err)
	}
	loaded, err := database.UserByUsername(ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != user.ID || loaded.Username != "alice" {
		t.Fatalf("loaded user = %#v", loaded)
	}
	if err := database.UpdatePasswordHash(ctx, user.ID, "upgraded-hash", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = database.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PasswordHash != "upgraded-hash" {
		t.Fatalf("password hash = %q", loaded.PasswordHash)
	}

	token, err := auth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	digest := auth.TokenDigest(token)
	record := auth.SessionRecord{
		TokenHash: digest,
		UserID:    user.ID,
		CSRFToken: "csrf-token",
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := database.CreateSession(ctx, record); err != nil {
		t.Fatal(err)
	}
	session, err := database.SessionByTokenHash(ctx, digest)
	if err != nil {
		t.Fatal(err)
	}
	if session.User.ID != user.ID || session.CSRFToken != record.CSRFToken {
		t.Fatalf("loaded session = %#v", session)
	}
	if err := database.TouchSession(ctx, digest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteSession(ctx, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SessionByTokenHash(ctx, digest); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("deleted session error = %v", err)
	}
	if err := database.RecordAuthEvent(ctx, auth.AuthEvent{
		OccurredAt: now, Kind: "login_succeeded", Username: "alice", UserID: user.ID, ClientIP: "192.0.2.1",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteRejectsNewerSchema(t *testing.T) {
	// The migration's newer-version guard is exercised indirectly by opening a
	// database, changing its version, closing it, and attempting to reopen it.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wispdeck.db")
	database, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE schema_version SET version = 999`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(ctx, path); err == nil {
		t.Fatal("opened a database with a newer schema")
	}
}
