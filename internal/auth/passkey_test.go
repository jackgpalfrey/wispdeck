package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
)

func TestPasskeyServiceUsesBootstrapThenPendingTransaction(t *testing.T) {
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
	if passkeys.RPID() != "admin.example.test" {
		t.Fatalf("RP ID = %q", passkeys.RPID())
	}

	token, session, required, err := passkeys.AfterPassword(ctx, user, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if required || session.Assurance != auth.AssuranceBootstrap || !auth.ValidToken(token) {
		t.Fatalf("bootstrap result = (%q, %#v, %v)", token, session, required)
	}
	creation, ceremonyToken, err := passkeys.BeginRegistration(ctx, session, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.ValidToken(ceremonyToken) || creation.Response.RelyingParty.ID != "admin.example.test" {
		t.Fatalf("registration options = %#v, ceremony = %q", creation, ceremonyToken)
	}

	credential := webauthnlib.Credential{ID: []byte("credential")}
	serialized, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := keys.EncryptCredential(serialized, user.ID, passkeys.RPID())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreatePasskey(ctx, auth.PasskeyRecord{
		CredentialID: []byte("credential"), UserID: user.ID, RPID: passkeys.RPID(),
		Name: "laptop", EncryptedRecord: encrypted, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	token, session, required, err = passkeys.AfterPassword(ctx, user, "192.0.2.1", "browser")
	if err != nil {
		t.Fatal(err)
	}
	if !required || session.Assurance != "" || !auth.ValidToken(token) {
		t.Fatalf("pending result = (%q, %#v, %v)", token, session, required)
	}
	if _, err := database.LoginTransactionByHash(ctx, auth.TokenDigest(token), time.Now().UTC()); err != nil {
		t.Fatalf("pending transaction not stored: %v", err)
	}
	assertion, ceremonyToken, err := passkeys.BeginLogin(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.ValidToken(ceremonyToken) || len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("login options = %#v, ceremony = %q", assertion, ceremonyToken)
	}

	codes, err := auth.GenerateRecoveryCodes(1)
	if err != nil {
		t.Fatal(err)
	}
	digest := keys.RecoveryCodeDigest(user.ID, codes[0])
	if err := database.ReplaceRecoveryCodes(ctx, user.ID, "batch", []auth.RecoveryCodeRecord{{
		Digest: digest, UserID: user.ID, BatchID: "batch", CreatedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	recoveryToken, recoverySession, err := passkeys.Recover(ctx, token, codes[0])
	if err != nil {
		t.Fatal(err)
	}
	if !auth.ValidToken(recoveryToken) || recoverySession.Assurance != auth.AssuranceRecovery {
		t.Fatalf("recovery session = (%q, %#v)", recoveryToken, recoverySession)
	}
	if _, _, err := passkeys.Recover(ctx, token, codes[0]); !errors.Is(err, auth.ErrInvalidSession) && !errors.Is(err, auth.ErrInvalidRecoveryCode) {
		t.Fatalf("replayed recovery error = %v", err)
	}
}
