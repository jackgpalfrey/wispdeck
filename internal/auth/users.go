package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const SetupTokenLifetime = 24 * time.Hour

type UserSummary struct {
	ID           string
	Username     string
	Role         Role
	Status       UserStatus
	MFASkipped   bool
	SessionCount int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type SetupTokenRecord struct {
	TokenHash       [32]byte
	CreatedByUserID string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type UserSetup struct {
	UserID    string
	Username  string
	Role      Role
	ExpiresAt time.Time
}

func (s *Service) ListUsers(ctx context.Context, actor Session) ([]UserSummary, error) {
	if !canManageUsers(actor) {
		return nil, ErrForbidden
	}
	users, err := s.repository.Users(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *Service) CreateUserWithPassword(
	ctx context.Context,
	actor Session,
	username, password string,
	role Role,
	checker PasswordChecker,
	passwordContext PasswordContext,
) (User, error) {
	if !canManageUsers(actor) {
		return User{}, ErrForbidden
	}
	username = NormalizeUsername(username)
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	if !ValidRole(role) {
		return User{}, ErrInvalidRole
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	passwordContext.Username = username
	if checker != nil {
		if err := checker.Check(ctx, password, passwordContext); err != nil {
			return User{}, err
		}
	}
	hash, err := s.passwords.Hash(password)
	if err != nil {
		return User{}, fmt.Errorf("hash assigned password: %w", err)
	}
	now := s.now().UTC()
	user, err := s.repository.CreateManagedUser(ctx, username, hash, role, UserActive, now)
	if err != nil {
		return User{}, err
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "user_created", Username: actor.User.Username,
		UserID: actor.User.ID, ClientIP: actor.ClientIP,
		Details: fmt.Sprintf("target=%s role=%s method=password", user.Username, user.Role),
	})
	return user, nil
}

func (s *Service) CreateUserWithSetup(
	ctx context.Context,
	actor Session,
	username string,
	role Role,
) (User, string, error) {
	if !canManageUsers(actor) {
		return User{}, "", ErrForbidden
	}
	username = NormalizeUsername(username)
	if err := ValidateUsername(username); err != nil {
		return User{}, "", err
	}
	if !ValidRole(role) {
		return User{}, "", ErrInvalidRole
	}
	placeholder, err := NewToken()
	if err != nil {
		return User{}, "", err
	}
	placeholderHash, err := s.passwords.Hash(placeholder)
	if err != nil {
		return User{}, "", fmt.Errorf("hash pending-user placeholder: %w", err)
	}
	token, record, err := s.newSetupToken(actor.User.ID)
	if err != nil {
		return User{}, "", err
	}
	user, err := s.repository.CreatePendingUser(ctx, username, placeholderHash, role, record)
	if err != nil {
		return User{}, "", err
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: record.CreatedAt, Kind: "user_created", Username: actor.User.Username,
		UserID: actor.User.ID, ClientIP: actor.ClientIP,
		Details: fmt.Sprintf("target=%s role=%s method=setup_link", user.Username, user.Role),
	})
	return user, token, nil
}

func (s *Service) ReplaceUserSetupToken(
	ctx context.Context,
	actor Session,
	userID string,
) (string, time.Time, error) {
	if !canManageUsers(actor) {
		return "", time.Time{}, ErrForbidden
	}
	token, record, err := s.newSetupToken(actor.User.ID)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.repository.ReplaceUserSetupToken(ctx, userID, record); err != nil {
		return "", time.Time{}, err
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: record.CreatedAt, Kind: "user_setup_link_replaced", Username: actor.User.Username,
		UserID: actor.User.ID, ClientIP: actor.ClientIP, Details: fmt.Sprintf("target_id=%s", userID),
	})
	return token, record.ExpiresAt, nil
}

func (s *Service) UserSetup(ctx context.Context, token string) (UserSetup, error) {
	if !ValidToken(token) {
		return UserSetup{}, ErrInvalidSetupToken
	}
	setup, err := s.repository.SetupByTokenHash(ctx, TokenDigest(token), s.now().UTC())
	if err != nil {
		if errors.Is(err, ErrInvalidSetupToken) {
			return UserSetup{}, ErrInvalidSetupToken
		}
		return UserSetup{}, fmt.Errorf("load user setup: %w", err)
	}
	return setup, nil
}

func (s *Service) CompleteUserSetup(
	ctx context.Context,
	token, password string,
	checker PasswordChecker,
	passwordContext PasswordContext,
	clientIP string,
) (User, error) {
	setup, err := s.UserSetup(ctx, token)
	if err != nil {
		return User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	passwordContext.Username = setup.Username
	if checker != nil {
		if err := checker.Check(ctx, password, passwordContext); err != nil {
			return User{}, err
		}
	}
	hash, err := s.passwords.Hash(password)
	if err != nil {
		return User{}, fmt.Errorf("hash setup password: %w", err)
	}
	now := s.now().UTC()
	user, err := s.repository.CompleteUserSetup(ctx, TokenDigest(token), hash, now)
	if err != nil {
		if errors.Is(err, ErrInvalidSetupToken) {
			return User{}, ErrInvalidSetupToken
		}
		return User{}, fmt.Errorf("complete user setup: %w", err)
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "user_setup_completed", Username: user.Username,
		UserID: user.ID, ClientIP: clientIP, Details: "initial password established",
	})
	return user, nil
}

func (s *Service) SetUserRole(ctx context.Context, actor Session, userID string, role Role) (User, error) {
	if !canManageUsers(actor) {
		return User{}, ErrForbidden
	}
	if !ValidRole(role) {
		return User{}, ErrInvalidRole
	}
	now := s.now().UTC()
	user, err := s.repository.UpdateUserRole(ctx, userID, role, now)
	if err != nil {
		return User{}, err
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "user_role_changed", Username: actor.User.Username,
		UserID: actor.User.ID, ClientIP: actor.ClientIP,
		Details: fmt.Sprintf("target=%s role=%s", user.Username, user.Role),
	})
	return user, nil
}

func (s *Service) SetUserStatus(
	ctx context.Context,
	actor Session,
	userID string,
	status UserStatus,
) (User, error) {
	if !canManageUsers(actor) {
		return User{}, ErrForbidden
	}
	if status != UserActive && status != UserDisabled {
		return User{}, ErrInvalidUserState
	}
	now := s.now().UTC()
	user, err := s.repository.UpdateUserStatus(ctx, userID, status, now)
	if err != nil {
		return User{}, err
	}
	s.recordEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "user_status_changed", Username: actor.User.Username,
		UserID: actor.User.ID, ClientIP: actor.ClientIP,
		Details: fmt.Sprintf("target=%s status=%s", user.Username, user.Status),
	})
	return user, nil
}

func canManageUsers(session Session) bool {
	return session.User.Role == RoleSuperuser &&
		(session.Assurance == AssurancePassword || session.Assurance == AssuranceMFA)
}

func (s *Service) newSetupToken(createdBy string) (string, SetupTokenRecord, error) {
	token, err := NewToken()
	if err != nil {
		return "", SetupTokenRecord{}, err
	}
	now := s.now().UTC()
	return token, SetupTokenRecord{
		TokenHash: TokenDigest(token), CreatedByUserID: createdBy,
		CreatedAt: now, ExpiresAt: now.Add(SetupTokenLifetime),
	}, nil
}
