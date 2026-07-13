package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

var (
	ErrCeremonyNotFound         = errors.New("authentication ceremony not found")
	ErrLoginTransactionNotFound = errors.New("login transaction not found")
	ErrPasskeyNameExists        = auth.ErrPasskeyNameExists
	ErrRecoveryCodeInvalid      = errors.New("invalid or used recovery code")
	ErrLastPasskey              = auth.ErrLastFactor
)

func (s *SQLite) PasskeysByUser(ctx context.Context, userID, rpID string) ([]auth.PasskeyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT credential_id, name, encrypted_record, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = ? AND rp_id = ?
		ORDER BY created_at, credential_id`, userID, rpID)
	if err != nil {
		return nil, fmt.Errorf("query passkeys: %w", err)
	}
	defer rows.Close()
	var records []auth.PasskeyRecord
	for rows.Next() {
		var record auth.PasskeyRecord
		var createdAt int64
		var lastUsedAt sql.NullInt64
		if err := rows.Scan(&record.CredentialID, &record.Name, &record.EncryptedRecord, &createdAt, &lastUsedAt); err != nil {
			return nil, fmt.Errorf("scan passkey: %w", err)
		}
		record.UserID = userID
		record.RPID = rpID
		record.CreatedAt = time.Unix(createdAt, 0).UTC()
		if lastUsedAt.Valid {
			value := time.Unix(lastUsedAt.Int64, 0).UTC()
			record.LastUsedAt = &value
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate passkeys: %w", err)
	}
	return records, nil
}

func (s *SQLite) PasskeyCount(ctx context.Context, userID, rpID string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE user_id = ? AND rp_id = ?`, userID, rpID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count passkeys: %w", err)
	}
	return count, nil
}

func (s *SQLite) SkipMFA(
	ctx context.Context,
	userID, rpID string,
	sessionDigest [32]byte,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin MFA opt-out: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var factorCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM webauthn_credentials WHERE user_id = ? AND rp_id = ?) +
			(SELECT count(*) FROM totp_credentials WHERE user_id = ?)`,
		userID, rpID, userID,
	).Scan(&factorCount); err != nil {
		return fmt.Errorf("count factors before MFA opt-out: %w", err)
	}
	if factorCount != 0 {
		return auth.ErrRecentMFARequired
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE sessions SET assurance = ?, authenticated_at = ?
		WHERE token_hash = ? AND user_id = ? AND assurance = ?`,
		auth.AssurancePassword, unix(now), sessionDigest[:], userID, auth.AssuranceBootstrap,
	)
	if err != nil {
		return fmt.Errorf("convert bootstrap session: %w", err)
	}
	if err := requireOneRow(result, "bootstrap session"); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `UPDATE users SET mfa_skipped = 1, updated_at = ? WHERE id = ?`, unix(now), userID)
	if err != nil {
		return fmt.Errorf("store MFA opt-out: %w", err)
	}
	if err := requireOneRow(result, "MFA opt-out user"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MFA opt-out: %w", err)
	}
	return nil
}

func (s *SQLite) CreatePasskey(ctx context.Context, record auth.PasskeyRecord) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (
			credential_id, user_id, rp_id, name, encrypted_record, created_at, last_used_at
		) VALUES (?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(user_id, rp_id, name) DO NOTHING`,
		record.CredentialID, record.UserID, record.RPID, record.Name, record.EncryptedRecord, unix(record.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("insert passkey: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect passkey insert: %w", err)
	}
	if rows != 1 {
		return ErrPasskeyNameExists
	}
	return nil
}

func (s *SQLite) CompletePasskeyRegistration(
	ctx context.Context,
	record auth.PasskeyRecord,
	recoveryBatchID string,
	recoveryRecords []auth.RecoveryCodeRecord,
	sessionDigest [32]byte,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin passkey registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (
			credential_id, user_id, rp_id, name, encrypted_record, created_at, last_used_at
		) VALUES (?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT(user_id, rp_id, name) DO NOTHING`,
		record.CredentialID, record.UserID, record.RPID, record.Name, record.EncryptedRecord, unix(record.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("insert registered passkey: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect registered passkey: %w", err)
	}
	if rows != 1 {
		return ErrPasskeyNameExists
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET mfa_skipped = 0 WHERE id = ?`, record.UserID); err != nil {
		return fmt.Errorf("clear MFA opt-out after passkey registration: %w", err)
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
				VALUES (?, ?, ?, ?)`, recovery.Digest[:], recovery.UserID, recovery.BatchID, unix(recovery.CreatedAt)); err != nil {
				return fmt.Errorf("insert registration recovery code: %w", err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE user_id = ? AND token_hash <> ? AND assurance <> ?`,
		record.UserID, sessionDigest[:], auth.AssuranceMFA,
	); err != nil {
		return fmt.Errorf("revoke other non-MFA sessions after passkey registration: %w", err)
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE sessions SET assurance = ?, authenticated_at = ?
		WHERE token_hash = ? AND user_id = ?`, auth.AssuranceMFA, unix(now), sessionDigest[:], record.UserID)
	if err != nil {
		return fmt.Errorf("elevate registration session: %w", err)
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect registration session: %w", err)
	}
	if rows != 1 {
		return errors.New("registration session not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit passkey registration: %w", err)
	}
	return nil
}

func (s *SQLite) UpdatePasskey(ctx context.Context, record auth.PasskeyRecord, usedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET encrypted_record = ?, last_used_at = ?
		WHERE credential_id = ? AND user_id = ? AND rp_id = ?`,
		record.EncryptedRecord, unix(usedAt), record.CredentialID, record.UserID, record.RPID,
	)
	if err != nil {
		return fmt.Errorf("update passkey: %w", err)
	}
	return requireOneRow(result, "passkey")
}

func (s *SQLite) DeletePasskeyKeepingOne(ctx context.Context, userID, rpID, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin passkey deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE user_id = ? AND rp_id = ?`, userID, rpID,
	).Scan(&count); err != nil {
		return fmt.Errorf("count passkeys before deletion: %w", err)
	}
	var hasTOTP bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE user_id = ?)`, userID,
	).Scan(&hasTOTP); err != nil {
		return fmt.Errorf("check TOTP before passkey deletion: %w", err)
	}
	if count <= 1 && !hasTOTP {
		return ErrLastPasskey
	}
	result, err := tx.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE user_id = ? AND rp_id = ? AND name = ?`, userID, rpID, name,
	)
	if err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("passkey not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit passkey deletion: %w", err)
	}
	return nil
}

func (s *SQLite) CreateLoginTransaction(ctx context.Context, transaction auth.LoginTransaction) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO login_transactions (token_hash, user_id, created_at, expires_at, client_ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?)`, transaction.TokenHash[:], transaction.UserID,
		unix(transaction.CreatedAt), unix(transaction.ExpiresAt), transaction.ClientIP, transaction.UserAgent)
	if err != nil {
		return fmt.Errorf("insert login transaction: %w", err)
	}
	return nil
}

func (s *SQLite) LoginTransactionByHash(ctx context.Context, digest [32]byte, now time.Time) (auth.LoginTransaction, error) {
	var transaction auth.LoginTransaction
	var tokenHash []byte
	var createdAt, expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT token_hash, user_id, created_at, expires_at, client_ip, user_agent
		FROM login_transactions WHERE token_hash = ? AND expires_at > ?`, digest[:], unix(now),
	).Scan(&tokenHash, &transaction.UserID, &createdAt, &expiresAt, &transaction.ClientIP, &transaction.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.LoginTransaction{}, ErrLoginTransactionNotFound
	}
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("query login transaction: %w", err)
	}
	if len(tokenHash) != len(transaction.TokenHash) {
		return auth.LoginTransaction{}, errors.New("stored login transaction digest has invalid length")
	}
	copy(transaction.TokenHash[:], tokenHash)
	transaction.CreatedAt = time.Unix(createdAt, 0).UTC()
	transaction.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return transaction, nil
}

func (s *SQLite) ConsumeLoginTransaction(ctx context.Context, digest [32]byte, now time.Time) (auth.LoginTransaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("begin login transaction consumption: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var transaction auth.LoginTransaction
	var tokenHash []byte
	var createdAt, expiresAt int64
	err = tx.QueryRowContext(ctx, `
		DELETE FROM login_transactions
		WHERE token_hash = ? AND expires_at > ?
		RETURNING token_hash, user_id, created_at, expires_at, client_ip, user_agent`, digest[:], unix(now),
	).Scan(&tokenHash, &transaction.UserID, &createdAt, &expiresAt, &transaction.ClientIP, &transaction.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.LoginTransaction{}, ErrLoginTransactionNotFound
	}
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("consume login transaction: %w", err)
	}
	copy(transaction.TokenHash[:], tokenHash)
	transaction.CreatedAt = time.Unix(createdAt, 0).UTC()
	transaction.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if err := tx.Commit(); err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("commit login transaction consumption: %w", err)
	}
	return transaction, nil
}

func (s *SQLite) CreateCeremony(ctx context.Context, ceremony auth.Ceremony) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin ceremony creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM auth_ceremonies WHERE binding_hash = ? AND kind = ?`, ceremony.BindingHash[:], ceremony.Kind,
	); err != nil {
		return fmt.Errorf("replace prior ceremony: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_ceremonies (
			token_hash, binding_hash, user_id, kind, encrypted_data, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ceremony.TokenHash[:], ceremony.BindingHash[:], ceremony.UserID, ceremony.Kind,
		ceremony.EncryptedData, unix(ceremony.CreatedAt), unix(ceremony.ExpiresAt),
	); err != nil {
		return fmt.Errorf("insert ceremony: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit ceremony creation: %w", err)
	}
	return nil
}

func (s *SQLite) ConsumeCeremony(ctx context.Context, digest, binding [32]byte, kind string, now time.Time) (auth.Ceremony, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.Ceremony{}, fmt.Errorf("begin ceremony consumption: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ceremony auth.Ceremony
	var tokenHash, bindingHash []byte
	var createdAt, expiresAt int64
	err = tx.QueryRowContext(ctx, `
		DELETE FROM auth_ceremonies
		WHERE token_hash = ? AND binding_hash = ? AND kind = ? AND expires_at > ?
		RETURNING token_hash, binding_hash, user_id, kind, encrypted_data, created_at, expires_at`,
		digest[:], binding[:], kind, unix(now),
	).Scan(&tokenHash, &bindingHash, &ceremony.UserID, &ceremony.Kind, &ceremony.EncryptedData, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Ceremony{}, ErrCeremonyNotFound
	}
	if err != nil {
		return auth.Ceremony{}, fmt.Errorf("consume ceremony: %w", err)
	}
	copy(ceremony.TokenHash[:], tokenHash)
	copy(ceremony.BindingHash[:], bindingHash)
	ceremony.CreatedAt = time.Unix(createdAt, 0).UTC()
	ceremony.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if err := tx.Commit(); err != nil {
		return auth.Ceremony{}, fmt.Errorf("commit ceremony consumption: %w", err)
	}
	return ceremony, nil
}

func (s *SQLite) ReplaceRecoveryCodes(ctx context.Context, userID, batchID string, records []auth.RecoveryCodeRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin recovery-code replacement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete old recovery codes: %w", err)
	}
	for _, record := range records {
		if record.UserID != userID || record.BatchID != batchID {
			return errors.New("recovery-code record scope mismatch")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO recovery_codes (code_digest, user_id, batch_id, created_at)
			VALUES (?, ?, ?, ?)`, record.Digest[:], record.UserID, record.BatchID, unix(record.CreatedAt)); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery-code replacement: %w", err)
	}
	return nil
}

func (s *SQLite) ConsumeRecoveryCode(ctx context.Context, userID string, digest [32]byte, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_digest = ? AND used_at IS NULL`, unix(now), userID, digest[:])
	if err != nil {
		return fmt.Errorf("consume recovery code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect recovery-code consumption: %w", err)
	}
	if rows != 1 {
		return ErrRecoveryCodeInvalid
	}
	return nil
}

func (s *SQLite) ConsumeRecoveryLogin(
	ctx context.Context,
	transactionDigest, codeDigest [32]byte,
	now time.Time,
) (auth.LoginTransaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("begin recovery login: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var transaction auth.LoginTransaction
	var tokenHash []byte
	var createdAt, expiresAt int64
	err = tx.QueryRowContext(ctx, `
		SELECT token_hash, user_id, created_at, expires_at, client_ip, user_agent
		FROM login_transactions WHERE token_hash = ? AND expires_at > ?`, transactionDigest[:], unix(now),
	).Scan(&tokenHash, &transaction.UserID, &createdAt, &expiresAt, &transaction.ClientIP, &transaction.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.LoginTransaction{}, ErrLoginTransactionNotFound
	}
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("query recovery login: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE recovery_codes SET used_at = ?
		WHERE user_id = ? AND code_digest = ? AND used_at IS NULL`, unix(now), transaction.UserID, codeDigest[:])
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("consume recovery login code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("inspect recovery login code: %w", err)
	}
	if rows != 1 {
		return auth.LoginTransaction{}, ErrRecoveryCodeInvalid
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_transactions WHERE token_hash = ?`, transactionDigest[:]); err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("consume recovery login transaction: %w", err)
	}
	copy(transaction.TokenHash[:], tokenHash)
	transaction.CreatedAt = time.Unix(createdAt, 0).UTC()
	transaction.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if err := tx.Commit(); err != nil {
		return auth.LoginTransaction{}, fmt.Errorf("commit recovery login: %w", err)
	}
	return transaction, nil
}

func (s *SQLite) UpdateSessionAssurance(ctx context.Context, digest [32]byte, assurance auth.Assurance, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET assurance = ?, authenticated_at = ? WHERE token_hash = ?`, assurance, unix(now), digest[:])
	if err != nil {
		return fmt.Errorf("update session assurance: %w", err)
	}
	return requireOneRow(result, "session")
}

func (s *SQLite) SessionsByUser(ctx context.Context, userID string) ([]auth.SessionSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT token_hash, assurance, created_at, authenticated_at, last_seen, expires_at, client_ip, user_agent
		FROM sessions WHERE user_id = ? ORDER BY last_seen DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()
	var sessions []auth.SessionSummary
	for rows.Next() {
		var session auth.SessionSummary
		var digest []byte
		var createdAt, authenticatedAt, lastSeen, expiresAt int64
		if err := rows.Scan(&digest, &session.Assurance, &createdAt, &authenticatedAt, &lastSeen, &expiresAt, &session.ClientIP, &session.UserAgent); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		copy(session.TokenHash[:], digest)
		session.CreatedAt = time.Unix(createdAt, 0).UTC()
		session.AuthenticatedAt = time.Unix(authenticatedAt, 0).UTC()
		session.LastSeen = time.Unix(lastSeen, 0).UTC()
		session.ExpiresAt = time.Unix(expiresAt, 0).UTC()
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

func (s *SQLite) DeleteOtherSessions(ctx context.Context, userID string, keep [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keep[:])
	if err != nil {
		return fmt.Errorf("delete other sessions: %w", err)
	}
	return nil
}

func (s *SQLite) ResetUserMFA(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin MFA reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET mfa_skipped = 0 WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("clear MFA opt-out: %w", err)
	}
	for _, statement := range []string{
		`DELETE FROM totp_enrollments WHERE user_id = ?`,
		`DELETE FROM totp_credentials WHERE user_id = ?`,
		`DELETE FROM auth_ceremonies WHERE user_id = ?`,
		`DELETE FROM login_transactions WHERE user_id = ?`,
		`DELETE FROM recovery_codes WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
			return fmt.Errorf("reset MFA state: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MFA reset: %w", err)
	}
	return nil
}

func (s *SQLite) ResetUserAuthentication(ctx context.Context, userID, passwordHash string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local authentication reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, mfa_skipped = 0, updated_at = ? WHERE id = ?`, passwordHash, unix(now), userID,
	)
	if err != nil {
		return fmt.Errorf("update locally reset password: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("local-reset user not found")
	}
	for _, statement := range []string{
		`DELETE FROM totp_enrollments WHERE user_id = ?`,
		`DELETE FROM totp_credentials WHERE user_id = ?`,
		`DELETE FROM auth_ceremonies WHERE user_id = ?`,
		`DELETE FROM login_transactions WHERE user_id = ?`,
		`DELETE FROM recovery_codes WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
			return fmt.Errorf("clear locally reset authentication state: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit local authentication reset: %w", err)
	}
	return nil
}
