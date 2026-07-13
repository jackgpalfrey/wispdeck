package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	totplib "github.com/pquerna/otp/totp"
	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
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
	shortLinkService, err := shortlink.NewService(database)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AppOrigin:       origin,
		Development:     !production,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordChecker: auth.NewStaticPasswordChecker(),
	}, authService, passkeyService, totpService, shortLinkService)
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

func passwordOnlyLogin(t *testing.T, server testServer, username, password string) (*http.Cookie, auth.Session) {
	t.Helper()
	login := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {username}, "password": {password},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("password login status = %d, body = %q", w.Code, w.Body.String())
	}
	cookie := responseCookie(t, w.Result(), "wispdeck_session")
	session, err := server.authService.Authenticate(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if session.Assurance == auth.AssuranceBootstrap {
		skip := request(http.MethodPost, "http://admin.example.test/security/mfa/skip", url.Values{
			"csrf_token": {session.CSRFToken},
		})
		skip.Header.Set("Origin", "http://admin.example.test")
		skip.AddCookie(cookie)
		w = httptest.NewRecorder()
		server.handler.ServeHTTP(w, skip)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("MFA skip status = %d, body = %q", w.Code, w.Body.String())
		}
		session, err = server.authService.Authenticate(context.Background(), cookie.Value)
		if err != nil {
			t.Fatal(err)
		}
	}
	if session.Assurance != auth.AssurancePassword {
		t.Fatalf("password-only assurance = %q", session.Assurance)
	}
	return cookie, session
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

func TestShortLinkCreateResolveAndDisable(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	create := request(http.MethodPost, "http://admin.example.test/links/create", url.Values{
		"csrf_token": {session.CSRFToken},
		"slug":       {"Release-Notes"},
		"target_url": {"https://example.com/releases/v1?from=wispdeck"},
	})
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("create short link = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	resolve := request(http.MethodGet, "http://admin.example.test/RELEASE-NOTES", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, resolve)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://example.com/releases/v1?from=wispdeck" {
		t.Fatalf("resolve short link = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	dashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	dashboard.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/release-notes") || !strings.Contains(w.Body.String(), "1 redirect") {
		t.Fatalf("short-link dashboard = (%d, %q)", w.Code, w.Body.String())
	}
	links, err := server.database.ShortLinks(context.Background(), session.User.ID, false)
	if err != nil || len(links) != 1 {
		t.Fatalf("stored short links = (%#v, %v)", links, err)
	}

	disable := request(http.MethodPost, "http://admin.example.test/links/state", url.Values{
		"csrf_token": {session.CSRFToken}, "link_id": {links[0].ID}, "enabled": {"false"},
	})
	disable.Header.Set("Origin", "http://admin.example.test")
	disable.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, disable)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable short link = (%d, %q)", w.Code, w.Body.String())
	}

	resolve = request(http.MethodGet, "http://admin.example.test/release-notes", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, resolve)
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled short link status = %d", w.Code)
	}

	retireWithoutConfirmation := request(http.MethodPost, "http://admin.example.test/links/retire", url.Values{
		"csrf_token": {session.CSRFToken}, "link_id": {links[0].ID},
	})
	retireWithoutConfirmation.Header.Set("Origin", "http://admin.example.test")
	retireWithoutConfirmation.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, retireWithoutConfirmation)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed retirement status = %d", w.Code)
	}

	retire := request(http.MethodPost, "http://admin.example.test/links/retire", url.Values{
		"csrf_token": {session.CSRFToken}, "link_id": {links[0].ID}, "confirm": {"yes"},
	})
	retire.Header.Set("Origin", "http://admin.example.test")
	retire.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, retire)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retire short link = (%d, %q)", w.Code, w.Body.String())
	}

	reclaim := request(http.MethodPost, "http://admin.example.test/links/create", url.Values{
		"csrf_token": {session.CSRFToken}, "slug": {"release-notes"}, "target_url": {"https://replacement.example"},
	})
	reclaim.Header.Set("Origin", "http://admin.example.test")
	reclaim.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, reclaim)
	if w.Code != http.StatusConflict {
		t.Fatalf("retired-name reclaim status = %d, body = %q", w.Code, w.Body.String())
	}
}

func TestShortLinkFormsValidateOriginSlugAndTarget(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	tests := []struct {
		name   string
		values url.Values
		origin string
		status int
		body   string
	}{
		{
			name: "missing origin",
			values: url.Values{
				"csrf_token": {session.CSRFToken}, "slug": {"valid"}, "target_url": {"https://example.com"},
			},
			status: http.StatusForbidden,
		},
		{
			name: "reserved slug",
			values: url.Values{
				"csrf_token": {session.CSRFToken}, "slug": {"login"}, "target_url": {"https://example.com"},
			},
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "reserved by Wispdeck",
		},
		{
			name: "unsafe target",
			values: url.Values{
				"csrf_token": {session.CSRFToken}, "slug": {"unsafe"}, "target_url": {"javascript:alert(1)"},
			},
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "absolute HTTP or HTTPS URL",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := request(http.MethodPost, "http://admin.example.test/links/create", test.values)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, r)
			if w.Code != test.status || (test.body != "" && !strings.Contains(w.Body.String(), test.body)) {
				t.Fatalf("response = (%d, %q)", w.Code, w.Body.String())
			}
		})
	}
}

func TestShortLinkOwnershipAndSuperuserManagement(t *testing.T) {
	server := newTestServer(t, false)
	ctx := context.Background()
	passwords, err := auth.NewPasswordManager(server.keys)
	if err != nil {
		t.Fatal(err)
	}
	bobHash, err := passwords.Hash("bob correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := server.database.CreateManagedUser(ctx, "bob", bobHash, auth.RoleUser, auth.UserActive, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	alice, err := server.database.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	aliceLink, err := server.database.CreateShortLink(ctx, alice.ID, "alice-link", "https://alice.example", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bobLink, err := server.database.CreateShortLink(ctx, bob.ID, "bob-link", "https://bob.example", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	bobCookie, bobSession := passwordOnlyLogin(t, server, "bob", "bob correct horse battery staple")
	bobDashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	bobDashboard.AddCookie(bobCookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, bobDashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/bob-link") || strings.Contains(w.Body.String(), "/alice-link") {
		t.Fatalf("Bob dashboard = (%d, %q)", w.Code, w.Body.String())
	}

	crossOwnerUpdate := request(http.MethodPost, "http://admin.example.test/links/target", url.Values{
		"csrf_token": {bobSession.CSRFToken}, "link_id": {aliceLink.ID}, "target_url": {"https://changed.example"},
	})
	crossOwnerUpdate.Header.Set("Origin", "http://admin.example.test")
	crossOwnerUpdate.AddCookie(bobCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, crossOwnerUpdate)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-owner update status = %d, body = %q", w.Code, w.Body.String())
	}

	aliceCookie, aliceSession := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	aliceDashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	aliceDashboard.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, aliceDashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Owned by bob") || !strings.Contains(w.Body.String(), "/alice-link") {
		t.Fatalf("superuser dashboard = (%d, %q)", w.Code, w.Body.String())
	}

	disableBob := request(http.MethodPost, "http://admin.example.test/links/state", url.Values{
		"csrf_token": {aliceSession.CSRFToken}, "link_id": {bobLink.ID}, "enabled": {"false"},
	})
	disableBob.Header.Set("Origin", "http://admin.example.test")
	disableBob.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, disableBob)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("superuser disable status = %d, body = %q", w.Code, w.Body.String())
	}

	resolveBob := request(http.MethodGet, "http://admin.example.test/bob-link", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, resolveBob)
	if w.Code != http.StatusNotFound {
		t.Fatalf("superuser-disabled link status = %d", w.Code)
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

func TestBootstrapCanPersistentlySkipMFA(t *testing.T) {
	server := newTestServer(t, false)
	login := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/security/passkeys" {
		t.Fatalf("initial login = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	sessionCookie := responseCookie(t, w.Result(), "wispdeck_session")
	session, err := server.authService.Authenticate(context.Background(), sessionCookie.Value)
	if err != nil || session.Assurance != auth.AssuranceBootstrap {
		t.Fatalf("bootstrap session = (%#v, %v)", session, err)
	}

	settings := request(http.MethodGet, "http://admin.example.test/security/passkeys", nil)
	settings.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, settings)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Skip MFA for now") {
		t.Fatalf("bootstrap settings = (%d, %q)", w.Code, w.Body.String())
	}

	invalid := request(http.MethodPost, "http://admin.example.test/security/mfa/skip", url.Values{
		"csrf_token": {"invalid"},
	})
	invalid.Header.Set("Origin", "http://admin.example.test")
	invalid.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, invalid)
	if w.Code != http.StatusForbidden {
		t.Fatalf("invalid-CSRF MFA opt-out status = %d", w.Code)
	}

	skip := request(http.MethodPost, "http://admin.example.test/security/mfa/skip", url.Values{
		"csrf_token": {session.CSRFToken},
	})
	skip.Header.Set("Origin", "http://admin.example.test")
	skip.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, skip)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("MFA opt-out = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	session, err = server.authService.Authenticate(context.Background(), sessionCookie.Value)
	if err != nil || session.Assurance != auth.AssurancePassword {
		t.Fatalf("password-only session = (%#v, %v)", session, err)
	}

	dashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	dashboard.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "MFA is not enabled") {
		t.Fatalf("password-only dashboard = (%d, %q)", w.Code, w.Body.String())
	}

	setup := request(http.MethodPost, "http://admin.example.test/security/totp/setup", url.Values{
		"csrf_token": {session.CSRFToken},
	})
	setup.Header.Set("Origin", "http://admin.example.test")
	setup.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, setup)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Set up authenticator app") {
		t.Fatalf("password-only MFA setup = (%d, %q)", w.Code, w.Body.String())
	}
	enrollmentCookie := responseCookie(t, w.Result(), "wispdeck_totp_enrollment")
	key, err := server.totp.EnrollmentKey(context.Background(), session, enrollmentCookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	login = request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("password-only repeat login = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	repeatCookie := responseCookie(t, w.Result(), "wispdeck_session")
	repeatSession, err := server.authService.Authenticate(context.Background(), repeatCookie.Value)
	if err != nil || repeatSession.Assurance != auth.AssurancePassword {
		t.Fatalf("repeat password-only session = (%#v, %v)", repeatSession, err)
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
		t.Fatalf("password-only TOTP confirmation = (%d, %q)", w.Code, w.Body.String())
	}
	elevated, err := server.authService.Authenticate(context.Background(), sessionCookie.Value)
	if err != nil || elevated.Assurance != auth.AssuranceMFA {
		t.Fatalf("elevated password-only session = (%#v, %v)", elevated, err)
	}
	if _, err := server.authService.Authenticate(context.Background(), repeatCookie.Value); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("other password-only session survived MFA enrollment: %v", err)
	}
	user, err := server.database.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.MFASkipped {
		t.Fatal("MFA enrollment did not clear persisted opt-out")
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Authenticator code") || strings.Contains(w.Body.String(), "Skip MFA") {
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

func TestPasskeyLoginPageOffersAnotherFactor(t *testing.T) {
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
	loginCookie := w.Result().Cookies()[0]

	r = request(http.MethodGet, "http://admin.example.test/login/passkey", nil)
	r.AddCookie(loginCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Use another method") || !strings.Contains(w.Body.String(), "Use passkey") || strings.Contains(w.Body.String(), "Skip MFA") {
		t.Fatalf("passkey page = (%d, %q)", w.Code, w.Body.String())
	}
}

func TestPasswordOnlySuperuserCanManageUsers(t *testing.T) {
	server := newTestServer(t, false)
	aliceCookie, alice := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	users := request(http.MethodGet, "http://admin.example.test/settings/users", nil)
	users.AddCookie(aliceCookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, users)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Create with a permanent password") {
		t.Fatalf("user management page = (%d, %q)", w.Code, w.Body.String())
	}

	const bobPassword = "saffron-planetary-cello-woodland"
	createPassword := request(http.MethodPost, "http://admin.example.test/settings/users/create-password", url.Values{
		"csrf_token": {alice.CSRFToken}, "username": {"bob"}, "role": {"user"},
		"password": {bobPassword}, "confirm_password": {bobPassword},
	})
	createPassword.Header.Set("Origin", "http://admin.example.test")
	createPassword.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, createPassword)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "bob") || strings.Contains(w.Body.String(), bobPassword) {
		t.Fatalf("permanent-password user creation = (%d, %q)", w.Code, w.Body.String())
	}
	bobCookie, bob := passwordOnlyLogin(t, server, "bob", bobPassword)

	forbidden := request(http.MethodGet, "http://admin.example.test/settings/users", nil)
	forbidden.AddCookie(bobCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, forbidden)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ordinary-user management status = %d", w.Code)
	}

	createSetup := request(http.MethodPost, "http://admin.example.test/settings/users/create-setup", url.Values{
		"csrf_token": {alice.CSRFToken}, "username": {"charlie"}, "role": {"user"},
	})
	createSetup.Header.Set("Origin", "http://admin.example.test")
	createSetup.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, createSetup)
	if w.Code != http.StatusCreated {
		t.Fatalf("setup-link user creation = (%d, %q)", w.Code, w.Body.String())
	}
	match := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 || !auth.ValidToken(match[1]) {
		t.Fatalf("setup token not found in response: %q", w.Body.String())
	}
	setupToken := match[1]
	events, err := server.authService.Events(context.Background(), alice, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(event.Details, setupToken) {
			t.Fatal("setup token was written to the audit trail")
		}
	}

	setupPage := request(http.MethodGet, "http://admin.example.test/setup?token="+url.QueryEscape(setupToken), nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, setupPage)
	if w.Code != http.StatusOK || w.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(w.Body.String(), "charlie") {
		t.Fatalf("setup page = (%d, %q, %q)", w.Code, w.Header().Get("Referrer-Policy"), w.Body.String())
	}
	const charliePassword = "harbour-citron-orchestra-violet"
	crossOrigin := request(http.MethodPost, "http://admin.example.test/setup", url.Values{
		"token": {setupToken}, "password": {charliePassword}, "confirm_password": {charliePassword},
	})
	crossOrigin.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, crossOrigin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin setup status = %d", w.Code)
	}
	complete := func() *httptest.ResponseRecorder {
		r := request(http.MethodPost, "http://admin.example.test/setup", url.Values{
			"token": {setupToken}, "password": {charliePassword}, "confirm_password": {charliePassword},
		})
		r.Header.Set("Origin", "http://admin.example.test")
		response := httptest.NewRecorder()
		server.handler.ServeHTTP(response, r)
		return response
	}
	w = complete()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Account ready") {
		t.Fatalf("setup completion = (%d, %q)", w.Code, w.Body.String())
	}
	w = complete()
	if w.Code != http.StatusGone {
		t.Fatalf("reused setup status = %d", w.Code)
	}
	_, _ = passwordOnlyLogin(t, server, "charlie", charliePassword)

	bobRecord, err := server.database.UserByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	disable := request(http.MethodPost, "http://admin.example.test/settings/users/status", url.Values{
		"csrf_token": {alice.CSRFToken}, "user_id": {bobRecord.ID}, "status": {"disabled"},
	})
	disable.Header.Set("Origin", "http://admin.example.test")
	disable.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, disable)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable user = (%d, %q)", w.Code, w.Body.String())
	}
	if _, err := server.authService.Authenticate(context.Background(), bobCookie.Value); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("disabled user's session survived: %v", err)
	}
	if bob.User.ID != bobRecord.ID {
		t.Fatalf("bob session principal = %#v", bob.User)
	}

	demoteFinal := request(http.MethodPost, "http://admin.example.test/settings/users/role", url.Values{
		"csrf_token": {alice.CSRFToken}, "user_id": {alice.User.ID}, "role": {"user"},
	})
	demoteFinal.Header.Set("Origin", "http://admin.example.test")
	demoteFinal.AddCookie(aliceCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, demoteFinal)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least one active superuser") {
		t.Fatalf("final-superuser response = (%d, %q)", w.Code, w.Body.String())
	}
}

func TestPasswordOnlySelfServicePasswordAndSessions(t *testing.T) {
	server := newTestServer(t, false)
	firstCookie, first := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	secondCookie, second := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	security := request(http.MethodGet, "http://admin.example.test/security/passkeys", nil)
	security.AddCookie(firstCookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, security)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Change password") || !strings.Contains(w.Body.String(), "Revoke session") {
		t.Fatalf("password-only self-service page = (%d, %q)", w.Code, w.Body.String())
	}

	revoke := request(http.MethodPost, "http://admin.example.test/security/sessions/revoke", url.Values{
		"csrf_token": {first.CSRFToken}, "session": {fmt.Sprintf("%x", second.TokenHash)},
	})
	revoke.Header.Set("Origin", "http://admin.example.test")
	revoke.AddCookie(firstCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, revoke)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("individual session revoke = (%d, %q)", w.Code, w.Body.String())
	}
	if _, err := server.authService.Authenticate(context.Background(), secondCookie.Value); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("revoked session error = %v", err)
	}

	passwordPage := request(http.MethodGet, "http://admin.example.test/security/password", nil)
	passwordPage.AddCookie(firstCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, passwordPage)
	if w.Code != http.StatusOK {
		t.Fatalf("password-only password page = (%d, %q)", w.Code, w.Body.String())
	}
	const newPassword = "marigold-telescope-river-canvas"
	change := request(http.MethodPost, "http://admin.example.test/security/password", url.Values{
		"csrf_token": {first.CSRFToken}, "current_password": {"correct horse battery staple"},
		"new_password": {newPassword}, "confirm_password": {newPassword},
	})
	change.Header.Set("Origin", "http://admin.example.test")
	change.AddCookie(firstCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, change)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Password changed") {
		t.Fatalf("password-only password change = (%d, %q)", w.Code, w.Body.String())
	}
	if _, err := server.authService.Authenticate(context.Background(), firstCookie.Value); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("password-changing session survived: %v", err)
	}
	_, _ = passwordOnlyLogin(t, server, "alice", newPassword)
}
