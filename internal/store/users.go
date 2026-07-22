package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func (s *SQLite) InstallationInitialized(ctx context.Context) (bool, error) {
	var initialized bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&initialized); err != nil {
		return false, fmt.Errorf("check installation users: %w", err)
	}
	return initialized, nil
}

func (s *SQLite) CreateInitialUser(
	ctx context.Context,
	username, passwordHash, clientIP string,
	now time.Time,
) (auth.User, error) {
	if err := auth.ValidateUsername(username); err != nil || passwordHash == "" || len(clientIP) > 128 {
		return auth.User{}, errors.New("invalid initial user")
	}
	id, err := randomID()
	if err != nil {
		return auth.User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin initial user creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var initialized bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&initialized); err != nil {
		return auth.User{}, fmt.Errorf("check initial user precondition: %w", err)
	}
	if initialized {
		return auth.User{}, auth.ErrAlreadyInitialized
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, created_at, updated_at, role, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, username, passwordHash, unix(now), unix(now), auth.RoleSuperuser, auth.UserActive,
	); err != nil {
		return auth.User{}, fmt.Errorf("insert initial user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO auth_events (occurred_at, kind, username, user_id, client_ip, details)
		VALUES (?, 'initial_superuser_created', ?, ?, NULLIF(?, ''), 'browser onboarding')`,
		unix(now), username, id, clientIP,
	); err != nil {
		return auth.User{}, fmt.Errorf("record initial user creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit initial user creation: %w", err)
	}
	return auth.User{
		ID: id, Username: username, PasswordHash: passwordHash,
		Role: auth.RoleSuperuser, Status: auth.UserActive,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (s *SQLite) CreateManagedUser(
	ctx context.Context,
	username, passwordHash string,
	role auth.Role,
	status auth.UserStatus,
	now time.Time,
) (auth.User, error) {
	if !auth.ValidRole(role) || !auth.ValidUserStatus(status) {
		return auth.User{}, errors.New("invalid user role or status")
	}
	id, err := randomID()
	if err != nil {
		return auth.User{}, err
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, created_at, updated_at, role, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO NOTHING`,
		id, username, passwordHash, unix(now), unix(now), role, status,
	)
	if err != nil {
		return auth.User{}, fmt.Errorf("insert user: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return auth.User{}, fmt.Errorf("inspect user insert: %w", err)
	}
	if rows != 1 {
		return auth.User{}, ErrUserExists
	}
	return auth.User{
		ID: id, Username: username, PasswordHash: passwordHash,
		Role: role, Status: status, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (s *SQLite) CreatePendingUser(
	ctx context.Context,
	username, placeholderHash string,
	role auth.Role,
	setup auth.SetupTokenRecord,
) (auth.User, error) {
	if !auth.ValidRole(role) || setup.CreatedByUserID == "" {
		return auth.User{}, errors.New("invalid pending user")
	}
	id, err := randomID()
	if err != nil {
		return auth.User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin pending user creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, created_at, updated_at, role, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO NOTHING`,
		id, username, placeholderHash, unix(setup.CreatedAt), unix(setup.CreatedAt), role, auth.UserPending,
	)
	if err != nil {
		return auth.User{}, fmt.Errorf("insert pending user: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return auth.User{}, fmt.Errorf("inspect pending user insert: %w", err)
	}
	if rows != 1 {
		return auth.User{}, ErrUserExists
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_setup_tokens (
			token_hash, user_id, created_by_user_id, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?)`,
		setup.TokenHash[:], id, setup.CreatedByUserID, unix(setup.CreatedAt), unix(setup.ExpiresAt),
	); err != nil {
		return auth.User{}, fmt.Errorf("insert initial user setup token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit pending user creation: %w", err)
	}
	return auth.User{
		ID: id, Username: username, PasswordHash: placeholderHash,
		Role: role, Status: auth.UserPending,
		CreatedAt: setup.CreatedAt.UTC(), UpdatedAt: setup.CreatedAt.UTC(),
	}, nil
}

func (s *SQLite) Users(ctx context.Context) ([]auth.UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username, u.role, u.status, u.mfa_skipped,
		       count(s.token_hash), u.created_at, u.updated_at
		FROM users AS u
		LEFT JOIN sessions AS s ON s.user_id = u.id
		GROUP BY u.id
		ORDER BY u.username COLLATE NOCASE, u.id`)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()
	var users []auth.UserSummary
	for rows.Next() {
		var user auth.UserSummary
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&user.ID, &user.Username, &user.Role, &user.Status, &user.MFASkipped,
			&user.SessionCount, &createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		user.CreatedAt = time.Unix(createdAt, 0).UTC()
		user.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

func (s *SQLite) SetupByTokenHash(
	ctx context.Context,
	digest [32]byte,
	now time.Time,
) (auth.UserSetup, error) {
	var setup auth.UserSetup
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, t.expires_at
		FROM user_setup_tokens AS t
		JOIN users AS u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.expires_at > ? AND u.status = ?`,
		digest[:], unix(now), auth.UserPending,
	).Scan(&setup.UserID, &setup.Username, &setup.Role, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.UserSetup{}, auth.ErrInvalidSetupToken
	}
	if err != nil {
		return auth.UserSetup{}, fmt.Errorf("query setup token: %w", err)
	}
	setup.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return setup, nil
}

func (s *SQLite) CompleteUserSetup(
	ctx context.Context,
	digest [32]byte,
	passwordHash string,
	now time.Time,
) (auth.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin user setup completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var userID string
	err = tx.QueryRowContext(ctx, `
		DELETE FROM user_setup_tokens
		WHERE token_hash = ? AND expires_at > ?
		RETURNING user_id`, digest[:], unix(now),
	).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrInvalidSetupToken
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("consume user setup token: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE users
		SET password_hash = ?, status = ?, mfa_skipped = 0, updated_at = ?
		WHERE id = ? AND status = ?`,
		passwordHash, auth.UserActive, unix(now), userID, auth.UserPending,
	)
	if err != nil {
		return auth.User{}, fmt.Errorf("activate setup user: %w", err)
	}
	if err := requireOneRow(result, "pending user"); err != nil {
		return auth.User{}, auth.ErrInvalidSetupToken
	}
	user, err := userByIDTx(ctx, tx, userID)
	if err != nil {
		return auth.User{}, err
	}
	if err := tx.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit user setup completion: %w", err)
	}
	return user, nil
}

func (s *SQLite) ReplaceUserSetupToken(
	ctx context.Context,
	userID string,
	setup auth.SetupTokenRecord,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin setup-token replacement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var status auth.UserStatus
	if err := tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id = ?`, userID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrUserNotFound
		}
		return fmt.Errorf("query setup user: %w", err)
	}
	if status != auth.UserPending {
		return auth.ErrInvalidUserState
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_setup_tokens WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete previous setup token: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_setup_tokens (
			token_hash, user_id, created_by_user_id, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?)`,
		setup.TokenHash[:], userID, setup.CreatedByUserID, unix(setup.CreatedAt), unix(setup.ExpiresAt),
	); err != nil {
		return fmt.Errorf("insert replacement setup token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit setup-token replacement: %w", err)
	}
	return nil
}

func (s *SQLite) UpdateUserRole(
	ctx context.Context,
	userID string,
	role auth.Role,
	now time.Time,
) (auth.User, error) {
	if !auth.ValidRole(role) {
		return auth.User{}, errors.New("invalid role")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin role update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := userByIDTx(ctx, tx, userID)
	if err != nil {
		return auth.User{}, err
	}
	if current.Role == auth.RoleSuperuser && role != auth.RoleSuperuser && current.Status == auth.UserActive {
		if err := requireAnotherActiveSuperuser(ctx, tx, userID); err != nil {
			return auth.User{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, updated_at = ? WHERE id = ?`, role, unix(now), userID); err != nil {
		return auth.User{}, fmt.Errorf("update user role: %w", err)
	}
	current.Role = role
	current.UpdatedAt = now.UTC()
	if err := tx.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit role update: %w", err)
	}
	return current, nil
}

func (s *SQLite) UpdateUserStatus(
	ctx context.Context,
	userID string,
	status auth.UserStatus,
	now time.Time,
) (auth.User, error) {
	if status != auth.UserActive && status != auth.UserDisabled {
		return auth.User{}, auth.ErrInvalidUserState
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin status update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := userByIDTx(ctx, tx, userID)
	if err != nil {
		return auth.User{}, err
	}
	if current.Status == auth.UserPending || current.Status == status {
		return auth.User{}, auth.ErrInvalidUserState
	}
	if current.Role == auth.RoleSuperuser && current.Status == auth.UserActive && status == auth.UserDisabled {
		if err := requireAnotherActiveSuperuser(ctx, tx, userID); err != nil {
			return auth.User{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET status = ?, updated_at = ? WHERE id = ?`, status, unix(now), userID); err != nil {
		return auth.User{}, fmt.Errorf("update user status: %w", err)
	}
	if status == auth.UserDisabled {
		for _, statement := range []string{
			`DELETE FROM totp_enrollments WHERE user_id = ?`,
			`DELETE FROM auth_ceremonies WHERE user_id = ?`,
			`DELETE FROM login_transactions WHERE user_id = ?`,
			`DELETE FROM sessions WHERE user_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, statement, userID); err != nil {
				return auth.User{}, fmt.Errorf("revoke disabled user state: %w", err)
			}
		}
	}
	current.Status = status
	current.UpdatedAt = now.UTC()
	if err := tx.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit status update: %w", err)
	}
	return current, nil
}

func (s *SQLite) DeleteUserSession(ctx context.Context, userID string, digest [32]byte) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash = ?`, userID, digest[:])
	if err != nil {
		return fmt.Errorf("delete user session: %w", err)
	}
	return requireOneRow(result, "session")
}

func requireAnotherActiveSuperuser(ctx context.Context, tx *sql.Tx, excludingUserID string) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM users
			WHERE id <> ? AND role = ? AND status = ?
		)`, excludingUserID, auth.RoleSuperuser, auth.UserActive,
	).Scan(&exists); err != nil {
		return fmt.Errorf("count remaining superusers: %w", err)
	}
	if !exists {
		return auth.ErrLastSuperuser
	}
	return nil
}

func userByIDTx(ctx context.Context, tx *sql.Tx, userID string) (auth.User, error) {
	var user auth.User
	var createdAt, updatedAt int64
	err := tx.QueryRowContext(ctx, `
		SELECT id, username, password_hash, mfa_skipped, role, status, created_at, updated_at
		FROM users WHERE id = ?`, userID,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.MFASkipped,
		&user.Role, &user.Status, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("query managed user: %w", err)
	}
	user.CreatedAt = time.Unix(createdAt, 0).UTC()
	user.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return user, nil
}
