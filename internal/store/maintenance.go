package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultAuthEventRetention = 90 * 24 * time.Hour
	DefaultMaxAuthEvents      = 100_000
)

type MaintenancePolicy struct {
	AuthEventRetention time.Duration
	MaxAuthEvents      int
}

type MaintenanceSummary struct {
	ExpiredSessions          int64
	ExpiredLoginTransactions int64
	ExpiredCeremonies        int64
	ExpiredTOTPEnrollments   int64
	ExpiredSetupTokens       int64
	ExpiredPreviewGrants     int64
	ExpiredPreviewSessions   int64
	ExpiredAuthEvents        int64
	ExcessAuthEvents         int64
}

func DefaultMaintenancePolicy() MaintenancePolicy {
	return MaintenancePolicy{
		AuthEventRetention: DefaultAuthEventRetention,
		MaxAuthEvents:      DefaultMaxAuthEvents,
	}
}

func (s MaintenanceSummary) Removed() int64 {
	return s.ExpiredSessions + s.ExpiredLoginTransactions + s.ExpiredCeremonies +
		s.ExpiredTOTPEnrollments + s.ExpiredSetupTokens + s.ExpiredPreviewGrants +
		s.ExpiredPreviewSessions + s.ExpiredAuthEvents + s.ExcessAuthEvents
}

func (s *SQLite) Maintain(
	ctx context.Context,
	now time.Time,
	policy MaintenancePolicy,
) (MaintenanceSummary, error) {
	if now.IsZero() || policy.AuthEventRetention < 24*time.Hour ||
		policy.AuthEventRetention > 10*365*24*time.Hour ||
		policy.MaxAuthEvents < 1 || policy.MaxAuthEvents > 10_000_000 {
		return MaintenanceSummary{}, errors.New("maintenance policy is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MaintenanceSummary{}, fmt.Errorf("begin installation maintenance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var summary MaintenanceSummary
	expiry := unix(now)
	deletions := []struct {
		query string
		count *int64
		args  []any
	}{
		{`DELETE FROM sessions WHERE expires_at <= ?`, &summary.ExpiredSessions, []any{expiry}},
		{`DELETE FROM login_transactions WHERE expires_at <= ?`, &summary.ExpiredLoginTransactions, []any{expiry}},
		{`DELETE FROM auth_ceremonies WHERE expires_at <= ?`, &summary.ExpiredCeremonies, []any{expiry}},
		{`DELETE FROM totp_enrollments WHERE expires_at <= ?`, &summary.ExpiredTOTPEnrollments, []any{expiry}},
		{`DELETE FROM user_setup_tokens WHERE expires_at <= ?`, &summary.ExpiredSetupTokens, []any{expiry}},
		{`DELETE FROM site_preview_grants WHERE expires_at <= ?`, &summary.ExpiredPreviewGrants, []any{expiry}},
		{`DELETE FROM site_preview_sessions WHERE expires_at <= ?`, &summary.ExpiredPreviewSessions, []any{expiry}},
		{`DELETE FROM auth_events WHERE occurred_at < ?`, &summary.ExpiredAuthEvents, []any{unix(now.Add(-policy.AuthEventRetention))}},
		{`DELETE FROM auth_events WHERE id IN (
			SELECT id FROM auth_events
			ORDER BY occurred_at DESC, id DESC LIMIT -1 OFFSET ?
		)`, &summary.ExcessAuthEvents, []any{policy.MaxAuthEvents}},
	}
	for _, deletion := range deletions {
		result, execErr := tx.ExecContext(ctx, deletion.query, deletion.args...)
		if execErr != nil {
			return MaintenanceSummary{}, fmt.Errorf("prune installation state: %w", execErr)
		}
		if countErr := rowsAffected(result, deletion.count); countErr != nil {
			return MaintenanceSummary{}, countErr
		}
	}
	if err := tx.Commit(); err != nil {
		return MaintenanceSummary{}, fmt.Errorf("commit installation maintenance: %w", err)
	}
	return summary, nil
}

func rowsAffected(result sql.Result, destination *int64) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count pruned installation state: %w", err)
	}
	*destination = count
	return nil
}
