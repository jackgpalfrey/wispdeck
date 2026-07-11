package store

import (
	"context"
	"database/sql"
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
		TokenHash:       digest,
		UserID:          user.ID,
		CSRFToken:       "csrf-token",
		Assurance:       auth.AssuranceMFA,
		CreatedAt:       now,
		AuthenticatedAt: now,
		LastSeen:        now,
		ExpiresAt:       now.Add(time.Hour),
		ClientIP:        "192.0.2.1",
		UserAgent:       "test agent",
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

func TestMigrationTwoInvalidatesPasswordOnlySessions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wispdeck.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	if err := migrationOne(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO users VALUES ('user-1', 'alice', 'hash', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	legacyDigest := make([]byte, 32)
	if _, err := tx.Exec(`INSERT INTO sessions VALUES (?, 'user-1', 'csrf', 1, 1, 100)`, legacyDigest); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	var count int
	if err := database.db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy session count = %d", count)
	}
	if err := database.db.QueryRow(`SELECT count(*) FROM webauthn_credentials`).Scan(&count); err != nil {
		t.Fatalf("schema v2 table missing: %v", err)
	}
}

func TestSQLiteMFAStateLifecycle(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	user, err := database.CreateUser(ctx, "alice", "encoded-hash", now)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"laptop", "security key"} {
		if err := database.CreatePasskey(ctx, auth.PasskeyRecord{
			CredentialID: []byte(name), UserID: user.ID, RPID: "admin.example.test",
			Name: name, EncryptedRecord: []byte("encrypted-" + name), CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.DeletePasskeyKeepingOne(ctx, user.ID, "admin.example.test", "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := database.DeletePasskeyKeepingOne(ctx, user.ID, "admin.example.test", "security key"); !errors.Is(err, ErrLastPasskey) {
		t.Fatalf("last-passkey error = %v", err)
	}

	loginToken, _ := auth.NewToken()
	loginDigest := auth.TokenDigest(loginToken)
	transaction := auth.LoginTransaction{
		TokenHash: loginDigest, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		ClientIP: "192.0.2.1", UserAgent: "test",
	}
	if err := database.CreateLoginTransaction(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if _, err := database.LoginTransactionByHash(ctx, loginDigest, now); err != nil {
		t.Fatal(err)
	}

	ceremonyToken, _ := auth.NewToken()
	ceremonyDigest := auth.TokenDigest(ceremonyToken)
	if err := database.CreateCeremony(ctx, auth.Ceremony{
		TokenHash: ceremonyDigest, BindingHash: loginDigest, UserID: user.ID,
		Kind: auth.CeremonyPasskeyLogin, EncryptedData: []byte("encrypted-session"),
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeCeremony(ctx, ceremonyDigest, loginDigest, auth.CeremonyPasskeyLogin, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeCeremony(ctx, ceremonyDigest, loginDigest, auth.CeremonyPasskeyLogin, now); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("replayed ceremony error = %v", err)
	}

	codeDigest := auth.TokenDigest("recovery-code")
	if err := database.ReplaceRecoveryCodes(ctx, user.ID, "batch", []auth.RecoveryCodeRecord{{
		Digest: codeDigest, UserID: user.ID, BatchID: "batch", CreatedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeRecoveryLogin(ctx, loginDigest, codeDigest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ConsumeRecoveryLogin(ctx, loginDigest, codeDigest, now); !errors.Is(err, ErrLoginTransactionNotFound) {
		t.Fatalf("replayed recovery error = %v", err)
	}
}
