package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func TestMaintenancePrunesExpiredStateAndBoundsAuthEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	user, err := database.CreateUser(ctx, "alice", "hash", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for index := range 8 {
		occurredAt := now.Add(-time.Duration(8-index) * 24 * time.Hour)
		if err := database.RecordAuthEvent(ctx, auth.AuthEvent{
			OccurredAt: occurredAt, Kind: "login_failed", Username: user.Username,
			UserID: user.ID, ClientIP: fmt.Sprintf("192.0.2.%d", index+1),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO sessions (
			token_hash, user_id, csrf_token, created_at, last_seen, expires_at,
			assurance, authenticated_at, client_ip, user_agent
		) VALUES (zeroblob(32), ?, 'csrf', ?, ?, ?, 'mfa', ?, '', '')
	`, user.ID, unix(now.Add(-2*time.Hour)), unix(now.Add(-2*time.Hour)), unix(now.Add(-time.Hour)), unix(now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO user_setup_tokens (
			token_hash, user_id, created_by_user_id, created_at, expires_at
		) VALUES (randomblob(32), ?, ?, ?, ?)
	`, user.ID, user.ID, unix(now.Add(-2*time.Hour)), unix(now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}

	summary, err := database.Maintain(ctx, now, MaintenancePolicy{
		AuthEventRetention: 6 * 24 * time.Hour,
		MaxAuthEvents:      3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ExpiredSessions != 1 || summary.ExpiredSetupTokens != 1 ||
		summary.ExpiredAuthEvents != 2 || summary.ExcessAuthEvents != 3 {
		t.Fatalf("maintenance summary = %+v", summary)
	}
	for table, want := range map[string]int{
		"sessions": 0, "user_setup_tokens": 0, "auth_events": 3,
	} {
		var count int
		if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s count = %d, want %d", table, count, want)
		}
	}
}

func TestMaintenanceRejectsInvalidPolicyWithoutChangingState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Maintain(ctx, time.Now().UTC(), MaintenancePolicy{
		AuthEventRetention: time.Hour, MaxAuthEvents: 100,
	}); err == nil {
		t.Fatal("Maintain() accepted a retention period shorter than one day")
	}
}
