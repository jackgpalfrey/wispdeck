package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func (s *SQLite) TOTPConfigured(ctx context.Context, userID string) (bool, error) {
	var configured bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE user_id = ?)`, userID,
	).Scan(&configured); err != nil {
		return false, fmt.Errorf("check TOTP configuration: %w", err)
	}
	return configured, nil
}

func (s *SQLite) TOTPByUser(ctx context.Context, userID string) (auth.TOTPRecord, error) {
	var record auth.TOTPRecord
	var createdAt int64
	var lastCounter sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, encrypted_secret, created_at, last_used_counter
		FROM totp_credentials WHERE user_id = ?`, userID,
	).Scan(&record.UserID, &record.EncryptedSecret, &createdAt, &lastCounter)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.TOTPRecord{}, auth.ErrTOTPNotConfigured
	}
	if err != nil {
		return auth.TOTPRecord{}, fmt.Errorf("query TOTP credential: %w", err)
	}
	record.CreatedAt = time.Unix(createdAt, 0).UTC()
	if lastCounter.Valid {
		record.LastUsedCounter = &lastCounter.Int64
	}
	return record, nil
}

func (s *SQLite) CreateTOTPEnrollment(ctx context.Context, enrollment auth.TOTPEnrollment) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM totp_enrollments WHERE binding_hash = ?`, enrollment.BindingHash[:],
	); err != nil {
		return fmt.Errorf("replace prior TOTP enrollment: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO totp_enrollments (
			token_hash, binding_hash, user_id, encrypted_secret, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?)`, enrollment.TokenHash[:], enrollment.BindingHash[:],
		enrollment.UserID, enrollment.EncryptedSecret, unix(enrollment.CreatedAt), unix(enrollment.ExpiresAt),
	); err != nil {
		return fmt.Errorf("insert TOTP enrollment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit TOTP enrollment: %w", err)
	}
	return nil
}

func (s *SQLite) TOTPEnrollmentByHash(
	ctx context.Context,
	digest, binding [32]byte,
	now time.Time,
) (auth.TOTPEnrollment, error) {
	var enrollment auth.TOTPEnrollment
	var tokenHash, bindingHash []byte
	var createdAt, expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT token_hash, binding_hash, user_id, encrypted_secret, created_at, expires_at
		FROM totp_enrollments
		WHERE token_hash = ? AND binding_hash = ? AND expires_at > ?`,
		digest[:], binding[:], unix(now),
	).Scan(&tokenHash, &bindingHash, &enrollment.UserID, &enrollment.EncryptedSecret, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.TOTPEnrollment{}, auth.ErrTOTPEnrollmentExpired
	}
	if err != nil {
		return auth.TOTPEnrollment{}, fmt.Errorf("query TOTP enrollment: %w", err)
	}
	if len(tokenHash) != 32 || len(bindingHash) != 32 {
		return auth.TOTPEnrollment{}, errors.New("stored TOTP enrollment digest has invalid length")
	}
	copy(enrollment.TokenHash[:], tokenHash)
	copy(enrollment.BindingHash[:], bindingHash)
	enrollment.CreatedAt = time.Unix(createdAt, 0).UTC()
	enrollment.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return enrollment, nil
}

func (s *SQLite) CompleteTOTPEnrollment(
	ctx context.Context,
	enrollmentDigest, binding [32]byte,
	record auth.TOTPRecord,
	recoveryBatchID string,
	recoveryRecords []auth.RecoveryCodeRecord,
	sessionDigest [32]byte,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP enrollment completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var enrolledUserID string
	err = tx.QueryRowContext(ctx, `
		DELETE FROM totp_enrollments
		WHERE token_hash = ? AND binding_hash = ? AND user_id = ? AND expires_at > ?
		RETURNING user_id`, enrollmentDigest[:], binding[:], record.UserID, unix(now),
	).Scan(&enrolledUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrTOTPEnrollmentExpired
	}
	if err != nil {
		return fmt.Errorf("consume TOTP enrollment: %w", err)
	}
	if enrolledUserID != record.UserID {
		return errors.New("TOTP enrollment user mismatch")
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO totp_credentials (user_id, encrypted_secret, created_at, last_used_counter)
		VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO NOTHING`,
		record.UserID, record.EncryptedSecret, unix(record.CreatedAt), record.LastUsedCounter,
	)
	if err != nil {
		return fmt.Errorf("insert TOTP credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect TOTP credential insert: %w", err)
	}
	if rows != 1 {
		return auth.ErrTOTPAlreadyConfigured
	}
	if len(recoveryRecords) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, record.UserID); err != nil {
			return fmt.Errorf("delete old recovery codes: %w", err)
		}
		for _, recovery := range recoveryRecords {
			if recovery.UserID != record.UserID || recovery.BatchID != recoveryBatchID {
				return errors.New("recovery-code record scope mismatch")
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO recovery_codes (code_digest, user_id, batch_id, created_at)
				VALUES (?, ?, ?, ?)`, recovery.Digest[:], recovery.UserID,
				recovery.BatchID, unix(recovery.CreatedAt),
			); err != nil {
				return fmt.Errorf("insert TOTP recovery code: %w", err)
			}
		}
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE sessions SET assurance = ?, authenticated_at = ?
		WHERE token_hash = ? AND user_id = ?`,
		auth.AssuranceMFA, unix(now), sessionDigest[:], record.UserID,
	)
	if err != nil {
		return fmt.Errorf("elevate TOTP registration session: %w", err)
	}
	if err := requireOneRow(result, "TOTP registration session"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit TOTP enrollment completion: %w", err)
	}
	return nil
}

func (s *SQLite) ConsumeTOTPLogin(
	ctx context.Context,
	transactionDigest [32]byte,
	userID string,
	counter int64,
	now time.Time,
) (auth.LoginTransaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("begin TOTP login: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var transaction auth.LoginTransaction
	var tokenHash []byte
	var createdAt, expiresAt int64
	err = tx.QueryRowContext(ctx, `
		SELECT token_hash, user_id, created_at, expires_at, client_ip, user_agent
		FROM login_transactions
		WHERE token_hash = ? AND user_id = ? AND expires_at > ?`,
		transactionDigest[:], userID, unix(now),
	).Scan(&tokenHash, &transaction.UserID, &createdAt, &expiresAt,
		&transaction.ClientIP, &transaction.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.LoginTransaction{}, ErrLoginTransactionNotFound
	}
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("query TOTP login transaction: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE totp_credentials SET last_used_counter = ?
		WHERE user_id = ? AND (last_used_counter IS NULL OR last_used_counter < ?)`,
		counter, userID, counter,
	)
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("consume TOTP counter: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("inspect TOTP counter consumption: %w", err)
	}
	if rows != 1 {
		return auth.LoginTransaction{}, auth.ErrTOTPReplayed
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM login_transactions WHERE token_hash = ?`, transactionDigest[:],
	); err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("consume TOTP login transaction: %w", err)
	}
	copy(transaction.TokenHash[:], tokenHash)
	transaction.CreatedAt = time.Unix(createdAt, 0).UTC()
	transaction.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if err := tx.Commit(); err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("commit TOTP login: %w", err)
	}
	return transaction, nil
}

func (s *SQLite) DeleteTOTPKeepingFactor(ctx context.Context, userID, rpID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var passkeys int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM webauthn_credentials WHERE user_id = ? AND rp_id = ?`,
		userID, rpID,
	).Scan(&passkeys); err != nil {
		return fmt.Errorf("count passkeys before TOTP deletion: %w", err)
	}
	if passkeys == 0 {
		return auth.ErrLastFactor
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM totp_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete TOTP credential: %w", err)
	}
	if err := requireOneRow(result, "TOTP credential"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit TOTP deletion: %w", err)
	}
	return nil
}
