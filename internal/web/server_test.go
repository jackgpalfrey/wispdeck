package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
)

type testServer struct {
	handler     http.Handler
	authService *auth.Service
	database    *store.SQLite
	keys        *auth.KeyMaterial
	passkeys    *auth.PasskeyService
}

func newTestServer(t *testing.T, production bool) testServer {
	t.Helper()
	ctx := context.Background()
	database, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	keyMaterial, err := auth.NewKeyMaterial(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := auth.NewPasswordManager(keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser(ctx, "alice", hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(database, passwords)
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if production {
		scheme = "https"
	}
	origin, _ := url.Parse(scheme + "://admin.example.test")
	passkeyService, err := auth.NewPasskeyService(database, authService, keyMaterial, origin)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AdminOrigin:     origin,
		Development:     !production,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordChecker: auth.NewStaticPasswordChecker(),
	}, authService, passkeyService)
	if err != nil {
		t.Fatal(err)
	}
	return testServer{
		handler: server.Handler(), authService: authService,
		database: database, keys: keyMaterial, passkeys: passkeyService,
	}
}

func request(method, target string, body url.Values) *http.Request {
	var encoded string
	if body != nil {
		encoded = body.Encode()
	}
	r := httptest.NewRequest(method, target, strings.NewReader(encoded))
	r.Host = "admin.example.test"
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r
}

func TestAdminBoundaryRejectsWrongHostAndSetsHeaders(t *testing.T) {
	server := newTestServer(t, true)
	r := request(http.MethodGet, "https://admin.example.test/login", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	for _, name := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Cache-Control"} {
		if w.Header().Get(name) == "" {
			t.Errorf("missing %s", name)
		}
	}

	r = request(http.MethodGet, "https://admin.example.test/login", nil)
	r.Host = "site.example.test"
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong-host status = %d", w.Code)
	}
}

func TestLoginRequiresOriginAndSetsHardenedCookie(t *testing.T) {
	server := newTestServer(t, true)
	values := url.Values{"username": {"alice"}, "password": {"correct horse battery staple"}}

	r := request(http.MethodPost, "https://admin.example.test/login", values)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing-origin status = %d", w.Code)
	}

	r = request(http.MethodPost, "https://admin.example.test/login", values)
	r.Header.Set("Origin", "https://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body = %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != productionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.Path != "/" {
		t.Fatalf("session cookie = %#v", cookie)
	}
}

func TestInvalidLoginsUseSameResponse(t *testing.T) {
	server := newTestServer(t, false)
	login := func(username, password string) *httptest.ResponseRecorder {
		r := request(http.MethodPost, "http://admin.example.test/login", url.Values{
			"username": {username}, "password": {password},
		})
		r.Header.Set("Origin", "http://admin.example.test")
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, r)
		return w
	}
	unknown := login("unknown", "incorrect password phrase")
	incorrect := login("alice", "incorrect password phrase")
	if unknown.Code != incorrect.Code {
		t.Fatalf("statuses differ: unknown=%d, incorrect=%d", unknown.Code, incorrect.Code)
	}
	for name, response := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "incorrect": incorrect} {
		if !strings.Contains(response.Body.String(), "Invalid username or password.") {
			t.Errorf("%s response was not generic: %q", name, response.Body.String())
		}
	}
}

func TestAuthenticatedLogoutRequiresCSRFAndInvalidatesSession(t *testing.T) {
	server := newTestServer(t, false)
	r := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	r.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	cookie := w.Result().Cookies()[0]
	session, err := server.authService.Authenticate(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	r = request(http.MethodGet, "http://admin.example.test/", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/security/passkeys" {
		t.Fatalf("bootstrap dashboard response = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	r = request(http.MethodGet, "http://admin.example.test/security/passkeys", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Add your first passkey") {
		t.Fatalf("passkey settings response = (%d, %q)", w.Code, w.Body.String())
	}

	r = request(http.MethodPost, "http://admin.example.test/logout", url.Values{"csrf_token": {"invalid"}})
	r.Header.Set("Origin", "http://admin.example.test")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("invalid-CSRF status = %d", w.Code)
	}

	r = request(http.MethodPost, "http://admin.example.test/logout", url.Values{"csrf_token": {session.CSRFToken}})
	r.Header.Set("Origin", "http://admin.example.test")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, body = %s", w.Code, w.Body.String())
	}
	if _, err := server.authService.Authenticate(context.Background(), cookie.Value); err != auth.ErrInvalidSession {
		t.Fatalf("old session error = %v", err)
	}
}

func TestClientAddressTrustsOnlyConfiguredProxies(t *testing.T) {
	networks, err := parseTrustedProxies([]string{"127.0.0.1/32", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{trustedProxies: networks}

	r := httptest.NewRequest(http.MethodGet, "http://admin.example.test/", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	if got := server.clientAddress(r); got != "192.0.2.10" {
		t.Fatalf("untrusted proxy address = %q", got)
	}

	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.8, 10.0.0.2")
	if got := server.clientAddress(r); got != "198.51.100.8" {
		t.Fatalf("trusted proxy address = %q", got)
	}

	r.Header.Set("X-Forwarded-For", "malformed, 10.0.0.2")
	if got := server.clientAddress(r); got != "127.0.0.1" {
		t.Fatalf("malformed chain address = %q", got)
	}
}

func TestBootstrapCanBeginPasskeyRegistration(t *testing.T) {
	server := newTestServer(t, false)
	r := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	r.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	cookie := w.Result().Cookies()[0]
	session, err := server.authService.Authenticate(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader(`{"name":"laptop"}`)
	r = httptest.NewRequest(http.MethodPost, "http://admin.example.test/api/auth/passkey/register/begin", body)
	r.Host = "admin.example.test"
	r.Header.Set("Origin", "http://admin.example.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("registration begin = (%d, %q)", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != "wispdeck_ceremony" {
		t.Fatalf("ceremony cookies = %#v", w.Result().Cookies())
	}
}

func TestEnrolledAccountRequiresPasskeyPhase(t *testing.T) {
	server := newTestServer(t, false)
	user, err := server.authService.VerifyCredentials(context.Background(), "alice", "correct horse battery staple", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	credential := webauthnlib.Credential{ID: []byte("credential")}
	serialized, _ := json.Marshal(credential)
	encrypted, err := server.keys.EncryptCredential(serialized, user.ID, server.passkeys.RPID())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.database.CreatePasskey(context.Background(), auth.PasskeyRecord{
		CredentialID: credential.ID, UserID: user.ID, RPID: server.passkeys.RPID(),
		Name: "laptop", EncryptedRecord: encrypted, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	r := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	r.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/passkey" {
		t.Fatalf("password phase = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	loginCookie := w.Result().Cookies()[0]
	if loginCookie.Name != "wispdeck_login" {
		t.Fatalf("login cookie = %#v", loginCookie)
	}

	r = request(http.MethodPost, "http://admin.example.test/api/auth/passkey/login/begin", nil)
	r.Header.Set("Origin", "http://admin.example.test")
	r.AddCookie(loginCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "publicKey") {
		t.Fatalf("passkey begin = (%d, %q)", w.Code, w.Body.String())
	}
}
