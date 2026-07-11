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
	totplib "github.com/pquerna/otp/totp"
	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
)

type testServer struct {
	handler     http.Handler
	authService *auth.Service
	database    *store.SQLite
	keys        *auth.KeyMaterial
	passkeys    *auth.PasskeyService
	totp        *auth.TOTPService
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
	totpService, err := auth.NewTOTPService(database, authService, keyMaterial, passkeyService.RPID())
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AdminOrigin:     origin,
		Development:     !production,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordChecker: auth.NewStaticPasswordChecker(),
	}, authService, passkeyService, totpService)
	if err != nil {
		t.Fatal(err)
	}
	return testServer{
		handler: server.Handler(), authService: authService,
		database: database, keys: keyMaterial, passkeys: passkeyService,
		totp: totpService,
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

func responseCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q: %#v", name, response.Cookies())
	return nil
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

func TestLoginAcceptsBrowserControlledSameOriginFallback(t *testing.T) {
	server := newTestServer(t, false)
	values := url.Values{"username": {"alice"}, "password": {"correct horse battery staple"}}

	r := request(http.MethodPost, "http://admin.example.test/login", values)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin fetch status = %d, body = %s", w.Code, w.Body.String())
	}

	r = request(http.MethodPost, "http://admin.example.test/login", values)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "http://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site fetch status = %d", w.Code)
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Add a passkey or authenticator app") {
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

func TestTOTPBootstrapAndLoginFlow(t *testing.T) {
	server := newTestServer(t, false)
	login := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/security/passkeys" {
		t.Fatalf("bootstrap login = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	sessionCookie := responseCookie(t, w.Result(), "wispdeck_session")
	session, err := server.authService.Authenticate(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	setup := request(http.MethodPost, "http://admin.example.test/security/totp/setup", url.Values{
		"csrf_token": {session.CSRFToken},
	})
	setup.Header.Set("Origin", "http://admin.example.test")
	setup.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, setup)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Set up authenticator app") {
		t.Fatalf("TOTP setup = (%d, %q)", w.Code, w.Body.String())
	}
	enrollmentCookie := responseCookie(t, w.Result(), "wispdeck_totp_enrollment")
	key, err := server.totp.EnrollmentKey(context.Background(), session, enrollmentCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	qr := request(http.MethodGet, "http://admin.example.test/security/totp/qr", nil)
	qr.AddCookie(sessionCookie)
	qr.AddCookie(enrollmentCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, qr)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" || w.Body.Len() < 100 {
		t.Fatalf("TOTP QR = (%d, %q, %d bytes)", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
	code, err := totplib.GenerateCode(key.Secret(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	confirm := request(http.MethodPost, "http://admin.example.test/security/totp/confirm", url.Values{
		"csrf_token": {session.CSRFToken}, "totp_code": {code},
	})
	confirm.Header.Set("Origin", "http://admin.example.test")
	confirm.AddCookie(sessionCookie)
	confirm.AddCookie(enrollmentCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, confirm)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Save these recovery codes") {
		t.Fatalf("TOTP confirmation = (%d, %q)", w.Code, w.Body.String())
	}
	elevated, err := server.authService.Authenticate(context.Background(), sessionCookie.Value)
	if err != nil || elevated.Assurance != auth.AssuranceMFA {
		t.Fatalf("elevated bootstrap session = (%#v, %v)", elevated, err)
	}

	login = request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/passkey" {
		t.Fatalf("factor login = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	loginCookie := responseCookie(t, w.Result(), "wispdeck_login")
	factorPage := request(http.MethodGet, "http://admin.example.test/login/passkey", nil)
	factorPage.AddCookie(loginCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, factorPage)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Authenticator code") || strings.Contains(w.Body.String(), "Use passkey") {
		t.Fatalf("factor page = (%d, %q)", w.Code, w.Body.String())
	}
	nextCode, err := totplib.GenerateCode(key.Secret(), time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verify := request(http.MethodPost, "http://admin.example.test/login/totp", url.Values{
		"totp_code": {nextCode},
	})
	verify.Header.Set("Origin", "http://admin.example.test")
	verify.AddCookie(loginCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, verify)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("TOTP login = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	mfaCookie := responseCookie(t, w.Result(), "wispdeck_session")
	if authenticated, err := server.authService.Authenticate(context.Background(), mfaCookie.Value); err != nil || authenticated.Assurance != auth.AssuranceMFA {
		t.Fatalf("TOTP session = (%#v, %v)", authenticated, err)
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
