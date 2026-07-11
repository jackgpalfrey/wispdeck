package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/store"
)

type testServer struct {
	handler     http.Handler
	authService *auth.Service
}

func newTestServer(t *testing.T, production bool) testServer {
	t.Helper()
	ctx := context.Background()
	database, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "wispdeck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser(ctx, "alice", hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(database)
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if production {
		scheme = "https"
	}
	origin, _ := url.Parse(scheme + "://admin.example.test")
	server, err := New(Config{
		AdminOrigin: origin,
		Development: !production,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, authService)
	if err != nil {
		t.Fatal(err)
	}
	return testServer{handler: server.Handler(), authService: authService}
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Signed in as <strong>alice</strong>") {
		t.Fatalf("dashboard response = (%d, %q)", w.Code, w.Body.String())
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
