package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrPasskeyRequired      = errors.New("a passkey is required")
	ErrRecentMFARequired    = errors.New("recent multi-factor authentication is required")
	ErrInvalidRecoveryCode  = errors.New("invalid or used recovery code")
	ErrPasskeyNotConfigured = errors.New("no passkey is configured")
	ErrLastPasskey          = ErrLastFactor
	ErrPasskeyNameExists    = errors.New("passkey name already exists")
)

const (
	loginTransactionLifetime = 5 * time.Minute
	ceremonyLifetime         = 5 * time.Minute
	recentAuthentication     = 10 * time.Minute
	recoveryCodeCount        = 10
)

type PasskeyRepository interface {
	UserByID(context.Context, string) (User, error)
	PasskeysByUser(context.Context, string, string) ([]PasskeyRecord, error)
	PasskeyCount(context.Context, string, string) (int, error)
	TOTPConfigured(context.Context, string) (bool, error)
	SkipMFA(context.Context, string, string, [32]byte, time.Time) error
	UpdatePasskey(context.Context, PasskeyRecord, time.Time) error
	CompletePasskeyRegistration(context.Context, PasskeyRecord, string, []RecoveryCodeRecord, [32]byte, time.Time) error
	DeletePasskeyKeepingOne(context.Context, string, string, string) error
	CreateLoginTransaction(context.Context, LoginTransaction) error
	LoginTransactionByHash(context.Context, [32]byte, time.Time) (LoginTransaction, error)
	ConsumeLoginTransaction(context.Context, [32]byte, time.Time) (LoginTransaction, error)
	CreateCeremony(context.Context, Ceremony) error
	ConsumeCeremony(context.Context, [32]byte, [32]byte, string, time.Time) (Ceremony, error)
	ConsumeRecoveryLogin(context.Context, [32]byte, [32]byte, time.Time) (LoginTransaction, error)
	ReplaceRecoveryCodes(context.Context, string, string, []RecoveryCodeRecord) error
	RecordAuthEvent(context.Context, AuthEvent) error
}

type PasskeyService struct {
	repository PasskeyRepository
	auth       *Service
	keys       *KeyMaterial
	webAuthn   *webauthnlib.WebAuthn
	rpID       string
	now        func() time.Time
}

func (s *PasskeyService) RPID() string { return s.rpID }

func (s *PasskeyService) Passkeys(ctx context.Context, userID string) ([]PasskeyRecord, error) {
	records, err := s.repository.PasskeysByUser(ctx, userID, s.rpID)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	for i := range records {
		records[i].EncryptedRecord = nil
	}
	return records, nil
}

func (s *PasskeyService) DeletePasskey(ctx context.Context, session Session, name string) error {
	if !s.RecentMFA(session) {
		return ErrRecentMFARequired
	}
	name, err := validatePasskeyName(name)
	if err != nil {
		return err
	}
	if err := s.repository.DeletePasskeyKeepingOne(ctx, session.User.ID, s.rpID, name); err != nil {
		return err
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "passkey_deleted", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP, Details: name,
	})
	return nil
}

func (s *PasskeyService) RotateRecoveryCodes(ctx context.Context, session Session) ([]string, error) {
	if !s.RecentMFA(session) {
		return nil, ErrRecentMFARequired
	}
	codes, records, batchID, err := s.newRecoveryCodes(session.User.ID)
	if err != nil {
		return nil, err
	}
	if err := s.repository.ReplaceRecoveryCodes(ctx, session.User.ID, batchID, records); err != nil {
		return nil, fmt.Errorf("rotate recovery codes: %w", err)
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "recovery_codes_rotated", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP,
	})
	return codes, nil
}

func (s *PasskeyService) RecentMFA(session Session) bool {
	return session.Assurance == AssuranceMFA && s.now().UTC().Sub(session.AuthenticatedAt) <= recentAuthentication
}

// SkipMFA records an explicit password-only choice for an account that has no
// enrolled factor. The repository changes the account preference and current
// bootstrap session atomically so a partially applied opt-out cannot grant
// access.
func (s *PasskeyService) SkipMFA(ctx context.Context, session Session) error {
	if session.Assurance != AssuranceBootstrap {
		return ErrRecentMFARequired
	}
	if err := s.repository.SkipMFA(ctx, session.User.ID, s.rpID, session.TokenHash, s.now().UTC()); err != nil {
		return fmt.Errorf("skip MFA: %w", err)
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "mfa_skipped", Username: session.User.Username,
		UserID: session.User.ID, ClientIP: session.ClientIP,
	})
	return nil
}

func NewPasskeyService(
	repository PasskeyRepository,
	authService *Service,
	keys *KeyMaterial,
	appOrigin *url.URL,
) (*PasskeyService, error) {
	if repository == nil || authService == nil || keys == nil {
		return nil, errors.New("passkey repository, authentication service, and key material are required")
	}
	if appOrigin == nil || appOrigin.Hostname() == "" || appOrigin.Scheme == "" {
		return nil, errors.New("valid application origin is required for WebAuthn")
	}
	origin := appOrigin.Scheme + "://" + appOrigin.Host
	rpID := appOrigin.Hostname()
	webAuthn, err := webauthnlib.New(&webauthnlib.Config{
		RPDisplayName:         "Wispdeck",
		RPID:                  rpID,
		RPOrigins:             []string{origin},
		RPAllowCrossOrigin:    false,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthnlib.TimeoutsConfig{
			Login:        webauthnlib.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime},
			Registration: webauthnlib.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn: %w", err)
	}
	return &PasskeyService{
		repository: repository,
		auth:       authService,
		keys:       keys,
		webAuthn:   webAuthn,
		rpID:       rpID,
		now:        time.Now,
	}, nil
}

// AfterPassword creates either a constrained first-factor bootstrap session or
// a short-lived transaction that must be completed with a passkey/recovery code.
func (s *PasskeyService) AfterPassword(
	ctx context.Context,
	user User,
	clientIP, userAgent string,
) (token string, session Session, passkeyRequired bool, err error) {
	count, err := s.repository.PasskeyCount(ctx, user.ID, s.rpID)
	if err != nil {
		return "", Session{}, false, fmt.Errorf("count passkeys: %w", err)
	}
	hasTOTP, err := s.repository.TOTPConfigured(ctx, user.ID)
	if err != nil {
		return "", Session{}, false, fmt.Errorf("check TOTP configuration: %w", err)
	}
	if count == 0 && !hasTOTP {
		assurance := AssuranceBootstrap
		if user.MFASkipped {
			assurance = AssurancePassword
		}
		token, session, err = s.auth.NewSession(ctx, user, assurance, clientIP, userAgent)
		return token, session, false, err
	}
	token, err = NewToken()
	if err != nil {
		return "", Session{}, false, err
	}
	now := s.now().UTC()
	transaction := LoginTransaction{
		TokenHash: TokenDigest(token), UserID: user.ID,
		CreatedAt: now, ExpiresAt: now.Add(loginTransactionLifetime),
		ClientIP: clientIP, UserAgent: boundedUserAgent(userAgent),
	}
	if err := s.repository.CreateLoginTransaction(ctx, transaction); err != nil {
		return "", Session{}, false, fmt.Errorf("create login transaction: %w", err)
	}
	return token, Session{}, true, nil
}

type LoginMethods struct {
	Passkey bool
	TOTP    bool
}

func (s *PasskeyService) MethodsForLogin(ctx context.Context, loginToken string) (LoginMethods, error) {
	if !ValidToken(loginToken) {
		return LoginMethods{}, ErrInvalidSession
	}
	transaction, err := s.repository.LoginTransactionByHash(ctx, TokenDigest(loginToken), s.now().UTC())
	if err != nil {
		return LoginMethods{}, ErrInvalidSession
	}
	count, err := s.repository.PasskeyCount(ctx, transaction.UserID, s.rpID)
	if err != nil {
		return LoginMethods{}, fmt.Errorf("count login passkeys: %w", err)
	}
	hasTOTP, err := s.repository.TOTPConfigured(ctx, transaction.UserID)
	if err != nil {
		return LoginMethods{}, fmt.Errorf("check login TOTP configuration: %w", err)
	}
	return LoginMethods{Passkey: count > 0, TOTP: hasTOTP}, nil
}

func (s *PasskeyService) BeginLogin(
	ctx context.Context,
	loginToken string,
) (*protocol.CredentialAssertion, string, error) {
	if !ValidToken(loginToken) {
		return nil, "", ErrInvalidSession
	}
	binding := TokenDigest(loginToken)
	transaction, err := s.repository.LoginTransactionByHash(ctx, binding, s.now().UTC())
	if err != nil {
		return nil, "", ErrInvalidSession
	}
	user, err := s.repository.UserByID(ctx, transaction.UserID)
	if err != nil {
		return nil, "", fmt.Errorf("load passkey login user: %w", err)
	}
	webUser, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	if len(webUser.credentials) == 0 {
		return nil, "", ErrPasskeyNotConfigured
	}
	assertion, sessionData, err := s.webAuthn.BeginLogin(webUser,
		webauthnlib.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin passkey login: %w", err)
	}
	ceremonyToken, err := s.storeCeremony(ctx, binding, user.ID, CeremonyPasskeyLogin, sessionData, "")
	if err != nil {
		return nil, "", err
	}
	return assertion, ceremonyToken, nil
}

func (s *PasskeyService) FinishLogin(
	ctx context.Context,
	loginToken, ceremonyToken string,
	response *http.Request,
) (string, Session, error) {
	if !ValidToken(loginToken) || !ValidToken(ceremonyToken) {
		return "", Session{}, ErrInvalidSession
	}
	binding := TokenDigest(loginToken)
	transaction, err := s.repository.LoginTransactionByHash(ctx, binding, s.now().UTC())
	if err != nil {
		return "", Session{}, ErrInvalidSession
	}
	ceremony, err := s.repository.ConsumeCeremony(
		ctx, TokenDigest(ceremonyToken), binding, CeremonyPasskeyLogin, s.now().UTC(),
	)
	if err != nil || ceremony.UserID != transaction.UserID {
		return "", Session{}, ErrInvalidSession
	}
	payload, err := s.loadCeremony(ceremony)
	if err != nil {
		return "", Session{}, err
	}
	user, err := s.repository.UserByID(ctx, transaction.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("load passkey login user: %w", err)
	}
	webUser, records, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return "", Session{}, err
	}
	credential, err := s.webAuthn.FinishLogin(webUser, payload.Session, response)
	if err != nil {
		return "", Session{}, fmt.Errorf("validate passkey login: %w", err)
	}
	if err := s.persistUsedCredential(ctx, credential, records); err != nil {
		return "", Session{}, err
	}
	transaction, err = s.repository.ConsumeLoginTransaction(ctx, binding, s.now().UTC())
	if err != nil {
		return "", Session{}, ErrInvalidSession
	}
	return s.auth.NewSession(ctx, user, AssuranceMFA, transaction.ClientIP, transaction.UserAgent)
}

func (s *PasskeyService) BeginRegistration(
	ctx context.Context,
	session Session,
	name string,
) (*protocol.CredentialCreation, string, error) {
	name, err := validatePasskeyName(name)
	if err != nil {
		return nil, "", err
	}
	if err := s.requireRegistrationSession(session); err != nil {
		return nil, "", err
	}
	user, err := s.repository.UserByID(ctx, session.User.ID)
	if err != nil {
		return nil, "", fmt.Errorf("load passkey registration user: %w", err)
	}
	webUser, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	creation, sessionData, err := s.webAuthn.BeginRegistration(webUser,
		webauthnlib.WithExclusions(webauthnlib.Credentials(webUser.credentials).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin passkey registration: %w", err)
	}
	ceremonyToken, err := s.storeCeremony(
		ctx, session.TokenHash, user.ID, CeremonyPasskeyRegister, sessionData, name,
	)
	if err != nil {
		return nil, "", err
	}
	return creation, ceremonyToken, nil
}

func (s *PasskeyService) FinishRegistration(
	ctx context.Context,
	session Session,
	ceremonyToken string,
	response *http.Request,
) ([]string, error) {
	if err := s.requireRegistrationSession(session); err != nil {
		return nil, err
	}
	if !ValidToken(ceremonyToken) {
		return nil, ErrInvalidSession
	}
	ceremony, err := s.repository.ConsumeCeremony(
		ctx, TokenDigest(ceremonyToken), session.TokenHash, CeremonyPasskeyRegister, s.now().UTC(),
	)
	if err != nil || ceremony.UserID != session.User.ID {
		return nil, ErrInvalidSession
	}
	payload, err := s.loadCeremony(ceremony)
	if err != nil {
		return nil, err
	}
	user, err := s.repository.UserByID(ctx, session.User.ID)
	if err != nil {
		return nil, fmt.Errorf("load passkey registration user: %w", err)
	}
	webUser, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	credential, err := s.webAuthn.FinishRegistration(webUser, payload.Session, response)
	if err != nil {
		return nil, fmt.Errorf("validate passkey registration: %w", err)
	}
	record, err := s.protectCredential(user.ID, payload.Name, credential, s.now().UTC())
	if err != nil {
		return nil, err
	}

	var codes []string
	var batchID string
	var recoveryRecords []RecoveryCodeRecord
	if session.Assurance == AssuranceBootstrap || session.Assurance == AssurancePassword || session.Assurance == AssuranceRecovery {
		codes, recoveryRecords, batchID, err = s.newRecoveryCodes(user.ID)
		if err != nil {
			return nil, err
		}
	}
	if err := s.repository.CompletePasskeyRegistration(
		ctx, record, batchID, recoveryRecords, session.TokenHash, s.now().UTC(),
	); err != nil {
		return nil, fmt.Errorf("complete passkey registration: %w", err)
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "passkey_registered", Username: user.Username,
		UserID: user.ID, ClientIP: session.ClientIP, Details: payload.Name,
	})
	return codes, nil
}

func (s *PasskeyService) Recover(
	ctx context.Context,
	loginToken, recoveryCode string,
) (string, Session, error) {
	if !ValidToken(loginToken) {
		return "", Session{}, ErrInvalidSession
	}
	binding := TokenDigest(loginToken)
	transaction, err := s.repository.LoginTransactionByHash(ctx, binding, s.now().UTC())
	if err != nil {
		return "", Session{}, ErrInvalidSession
	}
	digest := s.keys.RecoveryCodeDigest(transaction.UserID, recoveryCode)
	transaction, err = s.repository.ConsumeRecoveryLogin(ctx, binding, digest, s.now().UTC())
	if err != nil {
		return "", Session{}, ErrInvalidRecoveryCode
	}
	user, err := s.repository.UserByID(ctx, transaction.UserID)
	if err != nil {
		return "", Session{}, fmt.Errorf("load recovery user: %w", err)
	}
	token, session, err := s.auth.NewSession(ctx, user, AssuranceRecovery, transaction.ClientIP, transaction.UserAgent)
	if err != nil {
		return "", Session{}, err
	}
	_ = s.repository.RecordAuthEvent(ctx, AuthEvent{
		OccurredAt: s.now().UTC(), Kind: "recovery_code_used", Username: user.Username,
		UserID: user.ID, ClientIP: transaction.ClientIP,
	})
	return token, session, nil
}

func (s *PasskeyService) requireRegistrationSession(session Session) error {
	return requireRecentFactorSession(session, s.now().UTC())
}

type ceremonyPayload struct {
	Session webauthnlib.SessionData `json:"session"`
	Name    string                  `json:"name,omitempty"`
}

func (s *PasskeyService) storeCeremony(
	ctx context.Context,
	binding [32]byte,
	userID, kind string,
	sessionData *webauthnlib.SessionData,
	name string,
) (string, error) {
	serialized, err := json.Marshal(ceremonyPayload{Session: *sessionData, Name: name})
	if err != nil {
		return "", fmt.Errorf("serialize WebAuthn ceremony: %w", err)
	}
	encrypted, err := s.keys.EncryptCeremony(serialized, userID, kind)
	if err != nil {
		return "", err
	}
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	ceremony := Ceremony{
		TokenHash: TokenDigest(token), BindingHash: binding, UserID: userID,
		Kind: kind, EncryptedData: encrypted, CreatedAt: now, ExpiresAt: now.Add(ceremonyLifetime),
	}
	if err := s.repository.CreateCeremony(ctx, ceremony); err != nil {
		return "", fmt.Errorf("store WebAuthn ceremony: %w", err)
	}
	return token, nil
}

func (s *PasskeyService) loadCeremony(ceremony Ceremony) (ceremonyPayload, error) {
	serialized, err := s.keys.DecryptCeremony(ceremony.EncryptedData, ceremony.UserID, ceremony.Kind)
	if err != nil {
		return ceremonyPayload{}, err
	}
	var payload ceremonyPayload
	if err := json.Unmarshal(serialized, &payload); err != nil {
		return ceremonyPayload{}, fmt.Errorf("decode WebAuthn ceremony: %w", err)
	}
	return payload, nil
}

type webAuthnUser struct {
	user        User
	handle      []byte
	credentials []webauthnlib.Credential
}

func (u webAuthnUser) WebAuthnID() []byte                            { return u.handle }
func (u webAuthnUser) WebAuthnName() string                          { return u.user.Username }
func (u webAuthnUser) WebAuthnDisplayName() string                   { return u.user.Username }
func (u webAuthnUser) WebAuthnCredentials() []webauthnlib.Credential { return u.credentials }

func (s *PasskeyService) loadWebAuthnUser(
	ctx context.Context,
	user User,
) (webAuthnUser, []PasskeyRecord, error) {
	records, err := s.repository.PasskeysByUser(ctx, user.ID, s.rpID)
	if err != nil {
		return webAuthnUser{}, nil, fmt.Errorf("load passkeys: %w", err)
	}
	credentials := make([]webauthnlib.Credential, len(records))
	for i, record := range records {
		serialized, err := s.keys.DecryptCredential(record.EncryptedRecord, user.ID, s.rpID)
		if err != nil {
			return webAuthnUser{}, nil, fmt.Errorf("decrypt passkey %q: %w", record.Name, err)
		}
		if err := json.Unmarshal(serialized, &credentials[i]); err != nil {
			return webAuthnUser{}, nil, fmt.Errorf("decode passkey %q: %w", record.Name, err)
		}
		if !bytes.Equal(credentials[i].ID, record.CredentialID) {
			return webAuthnUser{}, nil, errors.New("encrypted passkey ID does not match its indexed ID")
		}
	}
	return webAuthnUser{
		user: user, handle: s.keys.WebAuthnUserHandle(user.ID, s.rpID), credentials: credentials,
	}, records, nil
}

func (s *PasskeyService) persistUsedCredential(
	ctx context.Context,
	credential *webauthnlib.Credential,
	records []PasskeyRecord,
) error {
	for _, record := range records {
		if !bytes.Equal(record.CredentialID, credential.ID) {
			continue
		}
		serialized, err := json.Marshal(credential)
		if err != nil {
			return fmt.Errorf("serialize used passkey: %w", err)
		}
		record.EncryptedRecord, err = s.keys.EncryptCredential(serialized, record.UserID, record.RPID)
		if err != nil {
			return err
		}
		if err := s.repository.UpdatePasskey(ctx, record, s.now().UTC()); err != nil {
			return fmt.Errorf("persist used passkey: %w", err)
		}
		return nil
	}
	return errors.New("validated passkey does not belong to the user")
}

func (s *PasskeyService) protectCredential(
	userID, name string,
	credential *webauthnlib.Credential,
	now time.Time,
) (PasskeyRecord, error) {
	serialized, err := json.Marshal(credential)
	if err != nil {
		return PasskeyRecord{}, fmt.Errorf("serialize registered passkey: %w", err)
	}
	encrypted, err := s.keys.EncryptCredential(serialized, userID, s.rpID)
	if err != nil {
		return PasskeyRecord{}, err
	}
	return PasskeyRecord{
		CredentialID: credential.ID, UserID: userID, RPID: s.rpID,
		Name: name, EncryptedRecord: encrypted, CreatedAt: now,
	}, nil
}

func (s *PasskeyService) newRecoveryCodes(userID string) ([]string, []RecoveryCodeRecord, string, error) {
	return newRecoveryCodeBatch(s.keys, userID, s.now().UTC())
}

func validatePasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 80 {
		return "", errors.New("passkey name must contain 1-80 Unicode characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.New("passkey name must not contain control characters")
		}
	}
	return name, nil
}
