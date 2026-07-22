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

func TestMigrationsInvalidatePasswordOnlySessionsAndReachCurrentSchema(t *testing.T) {
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
	if err := database.db.QueryRow(`SELECT count(*) FROM totp_credentials`).Scan(&count); err != nil {
		t.Fatalf("schema v3 table missing: %v", err)
	}
	if err := database.db.QueryRow(`SELECT count(*) FROM short_links`).Scan(&count); err != nil {
		t.Fatalf("schema v6 table missing: %v", err)
	}
	for _, table := range []string{
		"short_link_destinations", "short_link_daily_stats", "short_link_audit_events",
		"public_names", "sites", "site_releases", "site_files",
		"site_preview_grants", "site_preview_sessions", "site_audit_events",
		"update_settings", "update_events", "branding_settings", "branding_events",
	} {
		if err := database.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatalf("schema v7 table %s missing: %v", table, err)
		}
	}
	if err := database.db.QueryRow(`SELECT version FROM schema_version`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", count, SchemaVersion)
	}
}

func TestMigrationTenPreservesAuditAndContinuesReleaseVersions(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range []func(context.Context, *sql.Tx) error{
		migrationOne, migrationTwo, migrationThree, migrationFour, migrationFive,
		migrationSix, migrationSeven, migrationEight, migrationNine,
	} {
		if err := migration(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	userID := "11111111111111111111111111111111"
	siteID := "22222222222222222222222222222222"
	releaseID := "33333333333333333333333333333333"
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (
			id, username, password_hash, created_at, updated_at, mfa_skipped, role, status
		) VALUES (?, 'alice', 'hash', 100, 100, 0, 'superuser', 'active')`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sites (id, owner_user_id, name, title, enabled, created_at, updated_at)
		VALUES (?, ?, 'notes', '', 1, 100, 100)`, siteID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_releases (
			id, site_id, version, created_by_user_id, file_count, total_bytes,
			bundle_digest, created_at
		) VALUES (?, ?, 7, ?, 1, 10, ?, 100)`, releaseID, siteID, userID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_audit_events (
			occurred_at, actor_user_id, owner_user_id, site_id, name, kind
		) VALUES (100, ?, ?, ?, 'notes', 'published')`, userID, userID, siteID); err != nil {
		t.Fatal(err)
	}
	if err := migrationTen(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_audit_events (
			occurred_at, actor_user_id, owner_user_id, site_id, name, kind
		) VALUES (101, ?, ?, ?, 'notes', 'release_deleted')`, userID, userID, siteID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var nextVersion, auditCount int
	if err := db.QueryRowContext(ctx, `SELECT next_release_version FROM sites WHERE id = ?`, siteID).Scan(&nextVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM site_audit_events WHERE site_id = ?`, siteID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if nextVersion != 8 || auditCount != 2 {
		t.Fatalf("migration result = next version %d, audit events %d", nextVersion, auditCount)
	}
}

func TestMigrationFourPreservesAssuredSessions(t *testing.T) {
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
	if err := migrationTwo(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := migrationThree(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO users VALUES ('user-1', 'alice', 'hash', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := tx.Exec(`
		INSERT INTO sessions (
			token_hash, user_id, csrf_token, created_at, last_seen, expires_at,
			assurance, authenticated_at, client_ip, user_agent
		) VALUES (?, 'user-1', 'csrf', 1, 1, 100, 'mfa', 1, '192.0.2.1', 'browser')`, digest); err != nil {
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
	var assurance string
	if err := database.db.QueryRow(`SELECT assurance FROM sessions WHERE token_hash = ?`, digest).Scan(&assurance); err != nil {
		t.Fatal(err)
	}
	if assurance != string(auth.AssuranceMFA) {
		t.Fatalf("migrated assurance = %q", assurance)
	}
	user, err := database.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.MFASkipped {
		t.Fatal("migration unexpectedly opted existing user out of MFA")
	}
	if user.Role != auth.RoleSuperuser || user.Status != auth.UserActive {
		t.Fatalf("migrated user authority = (%q, %q)", user.Role, user.Status)
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
