package auth

import "time"

type PasskeyRecord struct {
	CredentialID    []byte
	UserID          string
	RPID            string
	Name            string
	EncryptedRecord []byte
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

type LoginTransaction struct {
	TokenHash [32]byte
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	ClientIP  string
	UserAgent string
}

type Ceremony struct {
	TokenHash     [32]byte
	BindingHash   [32]byte
	UserID        string
	Kind          string
	EncryptedData []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

const (
	CeremonyPasskeyLogin    = "passkey_login"
	CeremonyPasskeyRegister = "passkey_register"
)

type RecoveryCodeRecord struct {
	Digest    [32]byte
	UserID    string
	BatchID   string
	CreatedAt time.Time
}

type TOTPRecord struct {
	UserID          string
	EncryptedSecret []byte
	CreatedAt       time.Time
	LastUsedCounter *int64
}

type TOTPEnrollment struct {
	TokenHash       [32]byte
	BindingHash     [32]byte
	UserID          string
	EncryptedSecret []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type SessionSummary struct {
	TokenHash       [32]byte
	Assurance       Assurance
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	LastSeen        time.Time
	ExpiresAt       time.Time
	ClientIP        string
	UserAgent       string
}
