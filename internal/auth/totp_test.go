package auth_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	totplib "github.com/pquerna/otp/totp"
	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
)

func TestTOTPEnrollmentLoginReplayAndFactorLifecycle(t *testing.T) {
	ctx := context.Background()
	database, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	keys, err := auth.NewKeyMaterial(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := auth.NewPasswordManager(keys)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.Hash("saffron-planetary-cello-woodland")
	if err != nil {
		t.Fatal(err)
	}
	user, err := database.CreateUser(ctx, "alice", hash, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(database, passwords)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse("https://admin.example.test")
	passkeys, err := auth.NewPasskeyService(database, authService, keys, origin)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := auth.NewTOTPService(database, authService, keys, passkeys.RPID())
	if err != nil {
		t.Fatal(err)
	}

	bootstrapToken, bootstrap, required, err := passkeys.AfterPassword(ctx, user, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if required || bootstrap.Assurance != auth.AssuranceBootstrap {
		t.Fatalf("bootstrap result = (%q, %#v, %v)", bootstrapToken, bootstrap, required)
	}
	enrollmentToken, secret, err := authenticator.BeginEnrollment(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.ValidToken(enrollmentToken) || secret == "" {
		t.Fatalf("enrollment = (%q, %q)", enrollmentToken, secret)
	}
	key, err := authenticator.EnrollmentKey(ctx, bootstrap, enrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	if key.Secret() != secret || key.Issuer() != "Wispdeck" || key.AccountName() != "alice" {
		t.Fatalf("enrollment key = %q", key.URL())
	}
	if _, err := authenticator.ConfirmEnrollment(ctx, bootstrap, enrollmentToken, "invalid"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Fatalf("invalid enrollment code error = %v", err)
	}
	code, err := totplib.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := authenticator.ConfirmEnrollment(ctx, bootstrap, enrollmentToken, code)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("recovery code count = %d", len(codes))
	}
	if _, err := authenticator.EnrollmentKey(ctx, bootstrap, enrollmentToken); !errors.Is(err, auth.ErrTOTPEnrollmentExpired) {
		t.Fatalf("consumed enrollment error = %v", err)
	}
	elevated, err := authService.Authenticate(ctx, bootstrapToken)
	if err != nil || elevated.Assurance != auth.AssuranceMFA {
		t.Fatalf("elevated session = (%#v, %v)", elevated, err)
	}
	record, err := database.TOTPByUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record.EncryptedSecret, []byte(secret)) || record.LastUsedCounter == nil {
		t.Fatalf("TOTP record was not encrypted or replay-initialized: %#v", record)
	}

	loginToken, _, required, err := passkeys.AfterPassword(ctx, user, "192.0.2.1", "browser")
	if err != nil || !required {
		t.Fatalf("factor login = (%q, %v, %v)", loginToken, required, err)
	}
	methods, err := passkeys.MethodsForLogin(ctx, loginToken)
	if err != nil || methods.Passkey || !methods.TOTP {
		t.Fatalf("login methods = (%#v, %v)", methods, err)
	}
	if _, _, err := authenticator.VerifyLogin(ctx, loginToken, "000000"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Fatalf("invalid-code error = %v", err)
	}
	nextCode, err := totplib.GenerateCode(secret, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := authenticator.VerifyLogin(ctx, loginToken, nextCode)
	if err != nil || session.Assurance != auth.AssuranceMFA {
		t.Fatalf("TOTP login = (%#v, %v)", session, err)
	}
	replayToken, _, _, err := passkeys.AfterPassword(ctx, user, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authenticator.VerifyLogin(ctx, replayToken, nextCode); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Fatalf("replayed-code error = %v", err)
	}
	if err := authenticator.Delete(ctx, session); !errors.Is(err, auth.ErrLastFactor) {
		t.Fatalf("last-factor deletion error = %v", err)
	}
	if err := database.CreatePasskey(ctx, auth.PasskeyRecord{
		CredentialID: []byte("credential"), UserID: user.ID, RPID: passkeys.RPID(),
		Name: "security key", EncryptedRecord: []byte("encrypted"), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := passkeys.DeletePasskey(ctx, session, "security key"); err != nil {
		t.Fatalf("delete passkey while TOTP remains: %v", err)
	}
	if err := database.CreatePasskey(ctx, auth.PasskeyRecord{
		CredentialID: []byte("replacement"), UserID: user.ID, RPID: passkeys.RPID(),
		Name: "replacement key", EncryptedRecord: []byte("encrypted"), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Delete(ctx, session); err != nil {
		t.Fatal(err)
	}
	if configured, err := authenticator.Configured(ctx, user.ID); err != nil || configured {
		t.Fatalf("TOTP configured after deletion = (%v, %v)", configured, err)
	}
}
