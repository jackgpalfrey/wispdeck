package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

const (
	totpPeriod             = 30
	totpSecretBytes        = 20
	totpEnrollmentLifetime = 10 * time.Minute
	totpEnrollmentPurpose  = "enrollment"
	totpCredentialPurpose  = "credential"
)

var (
	ErrInvalidTOTP           = errors.New("invalid authenticator code")
	ErrTOTPReplayed          = errors.New("authenticator code has already been used")
	ErrTOTPNotConfigured     = errors.New("authenticator app is not configured")
	ErrTOTPAlreadyConfigured = errors.New("authenticator app is already configured")
	ErrTOTPEnrollmentExpired = errors.New("authenticator enrollment expired")
	ErrLastFactor            = errors.New("cannot delete the last MFA factor")
)

type TOTPRepository interface {
	UserByID(context.Context, string) (User, error)
	TOTPConfigured(context.Context, string) (bool, error)
	TOTPByUser(context.Context, string) (TOTPRecord, error)
	CreateTOTPEnrollment(context.Context, TOTPEnrollment) error
	TOTPEnrollmentByHash(context.Context, [32]byte, [32]byte, time.Time) (TOTPEnrollment, error)
	CompleteTOTPEnrollment(context.Context, [32]byte, [32]byte, TOTPRecord, string, []RecoveryCodeRecord, [32]byte, time.Time) error
	LoginTransactionByHash(context.Context, [32]byte, time.Time) (LoginTransaction, error)
	ConsumeTOTPLogin(context.Context, [32]byte, string, int64, time.Time) (LoginTransaction, error)
	DeleteTOTPKeepingFactor(context.Context, string, string) error
	RecordAuthEvent(context.Context, AuthEvent) error
}

type TOTPService struct {
	repository TOTPRepository
	auth       *Service
	keys       *KeyMaterial
	rpID       string
	now        func() time.Time
}

func NewTOTPService(
	repository TOTPRepository,
	authService *Service,
	keys *KeyMaterial,
	rpID string,
) (*TOTPService, error) {
	if repository == nil || authService == nil || keys == nil || rpID == "" {
		return nil, errors.New("TOTP repository, authentication service, key material, and RP ID are required")
	}
	return &TOTPService{
		repository: repository,
		auth:       authService,
		keys:       keys,
		rpID:       rpID,
		now:        time.Now,
	}, nil
}

func (s *TOTPService) Configured(ctx context.Context, userID string) (bool, error) {
	return s.repository.TOTPConfigured(ctx, userID)
}

func (s *TOTPService) BeginEnrollment(
	ctx context.Context,
	session Session,
) (token, secret string, err error) {
	if err := requireRecentFactorSession(session, s.now().UTC()); err != nil {
		return "", "", err
	}
	configured, err := s.repository.TOTPConfigured(ctx, session.User.ID)
	if err != nil {
		return "", "", fmt.Errorf("check existing TOTP credential: %w", err)
	}
	if configured {
		return "", "", ErrTOTPAlreadyConfigured
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Wispdeck",
		AccountName: session.User.Username,
		Period:      totpPeriod,
		SecretSize:  totpSecretBytes,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	raw, err := decodeTOTPSecret(key.Secret())
	if err != nil {
		return "", "", err
	}
	encrypted, err := s.keys.EncryptTOTPSecret(raw, session.User.ID, totpEnrollmentPurpose)
	if err != nil {
		return "", "", err
	}
	token, err = NewToken()
	if err != nil {
		return "", "", err
	}
	now := s.now().UTC()
	enrollment := TOTPEnrollment{
		TokenHash: TokenDigest(token), BindingHash: session.TokenHash,
		UserID: session.User.ID, EncryptedSecret: encrypted,
		CreatedAt: now, ExpiresAt: now.Add(totpEnrollmentLifetime),
	}
	if err := s.repository.CreateTOTPEnrollment(ctx, enrollment); err != nil {
		return "", "", fmt.Errorf("store TOTP enrollment: %w", err)
	}
	return token, key.Secret(), nil
}

func (s *TOTPService) EnrollmentKey(
	ctx context.Context,
	session Session,
	token string,
) (*otp.Key, error) {
	raw, err := s.enrollmentSecret(ctx, session, token)
	if err != nil {
		return nil, err
	}
	return newTOTPKey(session.User.Username, raw)
}

func (s *TOTPService) ConfirmEnrollment(
	ctx context.Context,
	session Session,
	token, code string,
) ([]string, error) {
	if err := requireRecentFactorSession(session, s.now().UTC()); err != nil {
		return nil, err
	}
	raw, err := s.enrollmentSecret(ctx, session, token)
	if err != nil {
		return nil, err
	}
	counter, matched, err := matchingTOTPCounter(raw, code, s.now().UTC())
	if err != nil {
		return nil, fmt.Errorf("validate TOTP enrollment code: %w", err)
	}
	if !matched {
		return nil, ErrInvalidTOTP
	}
	encrypted, err := s.keys.EncryptTOTPSecret(raw, session.User.ID, totpCredentialPurpose)
	if err != nil {
		return nil, err
	}
	var codes []string
	var records []RecoveryCodeRecord
	var batchID string
	if session.Assurance == AssuranceBootstrap || session.Assurance == AssuranceRecovery {
		codes, records, batchID, err = newRecoveryCodeBatch(s.keys, session.User.ID, s.now().UTC())
		if err != nil {
			return nil, err
		}
	}
	now := s.now().UTC()
	if err := s.repository.CompleteTOTPEnrollment(
		ctx, TokenDigest(token), session.TokenHash,
		TOTPRecord{
			UserID: session.User.ID, EncryptedSecret: encrypted, CreatedAt: now,
			LastUsedCounter: &counter,
		},
		batchID, records, session.TokenHash, now,
	); err != nil {
		return nil, err
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "totp_registered", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP,
	})
	return codes, nil
}

func (s *TOTPService) VerifyLogin(
	ctx context.Context,
	loginToken, code string,
) (string, Session, error) {
	if !ValidToken(loginToken) {
		return "", Session{}, ErrInvalidSession
	}
	now := s.now().UTC()
	digest := TokenDigest(loginToken)
	transaction, err := s.repository.LoginTransactionByHash(ctx, digest, now)
	if err != nil {
		return "", Session{}, ErrInvalidSession
	}
	record, err := s.repository.TOTPByUser(ctx, transaction.UserID)
	if errors.Is(err, ErrTOTPNotConfigured) {
		return "", Session{}, ErrInvalidTOTP
	}
	if err != nil {
		return "", Session{}, fmt.Errorf("load TOTP credential: %w", err)
	}
	raw, err := s.keys.DecryptTOTPSecret(record.EncryptedSecret, record.UserID, totpCredentialPurpose)
	if err != nil {
		return "", Session{}, fmt.Errorf("decrypt TOTP credential: %w", err)
	}
	counter, matched, err := matchingTOTPCounter(raw, code, now)
	if err != nil {
		return "", Session{}, fmt.Errorf("validate TOTP login code: %w", err)
	}
	if !matched {
		return "", Session{}, ErrInvalidTOTP
	}
	transaction, err = s.repository.ConsumeTOTPLogin(ctx, digest, record.UserID, counter, now)
	if err != nil {
		if errors.Is(err, ErrTOTPReplayed) {
			return "", Session{}, ErrInvalidTOTP
		}
		return "", Session{}, err
	}
	user, err := s.repository.UserByID(ctx, transaction.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("load TOTP login user: %w", err)
	}
	token, session, err := s.auth.NewSession(
		ctx, user, AssuranceMFA, transaction.ClientIP, transaction.UserAgent,
	)
	if err != nil {
		return "", Session{}, err
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: now, Kind: "totp_used", Username: user.Username,
		UserID: user.ID, ClientIP: transaction.ClientIP,
	})
	return token, session, nil
}

func (s *TOTPService) Delete(ctx context.Context, session Session) error {
	if session.Assurance != AssuranceMFA || s.now().UTC().Sub(session.AuthenticatedAt) > recentAuthentication {
		return ErrRecentMFARequired
	}
	if err := s.repository.DeleteTOTPKeepingFactor(ctx, session.User.ID, s.rpID); err != nil {
		return err
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "totp_deleted", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP,
	})
	return nil
}

func (s *TOTPService) enrollmentSecret(
	ctx context.Context,
	session Session,
	token string,
) ([]byte, error) {
	if !ValidToken(token) {
		return nil, ErrTOTPEnrollmentExpired
	}
	enrollment, err := s.repository.TOTPEnrollmentByHash(
		ctx, TokenDigest(token), session.TokenHash, s.now().UTC(),
	)
	if errors.Is(err, ErrTOTPEnrollmentExpired) {
		return nil, ErrTOTPEnrollmentExpired
	}
	if err != nil {
		return nil, fmt.Errorf("load TOTP enrollment: %w", err)
	}
	if enrollment.UserID != session.User.ID {
		return nil, ErrTOTPEnrollmentExpired
	}
	return s.keys.DecryptTOTPSecret(
		enrollment.EncryptedSecret, enrollment.UserID, totpEnrollmentPurpose,
	)
}

func newTOTPKey(username string, raw []byte) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      "Wispdeck",
		AccountName: username,
		Period:      totpPeriod,
		Secret:      raw,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

func matchingTOTPCounter(raw []byte, code string, now time.Time) (int64, bool, error) {
	if len(code) != 6 {
		return 0, false, nil
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false, nil
		}
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	current := now.Unix() / totpPeriod
	for _, offset := range []int64{0, -1, 1} {
		counter := current + offset
		if counter < 0 {
			continue
		}
		matched, err := hotp.ValidateCustom(code, uint64(counter), secret, hotp.ValidateOpts{
			Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false, err
		}
		if matched {
			return counter, true, nil
		}
	}
	return 0, false, nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(raw) != totpSecretBytes {
		return nil, errors.New("generated TOTP secret has invalid encoding")
	}
	return raw, nil
}

func requireRecentFactorSession(session Session, now time.Time) error {
	if session.Assurance != AssuranceBootstrap && session.Assurance != AssuranceRecovery && session.Assurance != AssuranceMFA {
		return ErrPasskeyRequired
	}
	if now.Sub(session.AuthenticatedAt) > recentAuthentication {
		return ErrRecentMFARequired
	}
	return nil
}

func newRecoveryCodeBatch(
	keys *KeyMaterial,
	userID string,
	now time.Time,
) ([]string, []RecoveryCodeRecord, string, error) {
	codes, err := GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, nil, "", err
	}
	batchID, err := NewToken()
	if err != nil {
		return nil, nil, "", err
	}
	records := make([]RecoveryCodeRecord, len(codes))
	for i, code := range codes {
		records[i] = RecoveryCodeRecord{
			Digest: keys.RecoveryCodeDigest(userID, code), UserID: userID,
			BatchID: batchID, CreatedAt: now,
		}
	}
	return codes, records, batchID, nil
}
