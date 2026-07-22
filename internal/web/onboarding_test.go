package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wispdeck/wispdeck/internal/auth"
)

func TestOnboardingSetupCodeAttemptsAreProcessWide(t *testing.T) {
	t.Parallel()
	server := newOnboardingTestServer(t, false)
	password := "saffron-planetary-cello-woodland"
	for attempt, code := range []string{"AAAAA2", "BBBBB2", "CCCCC2", "DDDDD2", "EEEEE2"} {
		r := request(http.MethodPost, "http://admin.example.test/onboarding", url.Values{
			"setup_code": {code}, "username": {"owner"},
			"password": {password}, "confirm_password": {password},
		})
		r.Header.Set("Origin", "http://admin.example.test")
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", attempt+1)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-code attempt %d status = %d", attempt+1, w.Code)
		}
	}
	r := request(http.MethodPost, "http://admin.example.test/onboarding", url.Values{
		"setup_code": {server.setupCode}, "username": {"owner"},
		"password": {password}, "confirm_password": {password},
	})
	r.Header.Set("Origin", "http://admin.example.test")
	r.RemoteAddr = "198.51.100.1:1234"
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth process-wide setup attempt status = %d", w.Code)
	}
}

func TestFreshInstallationOnboardingLifecycle(t *testing.T) {
	t.Parallel()
	server := newOnboardingTestServer(t, false)

	root := request(http.MethodGet, "http://admin.example.test/", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, root)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/onboarding" {
		t.Fatalf("fresh root = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	login := request(http.MethodGet, "http://admin.example.test/login", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/onboarding" {
		t.Fatalf("fresh login = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	asset := request(http.MethodGet, "http://admin.example.test/assets/admin.css", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, asset)
	if w.Code != http.StatusOK {
		t.Fatalf("onboarding asset status = %d", w.Code)
	}

	page := request(http.MethodGet, "http://admin.example.test/onboarding", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, page)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Welcome to Wispdeck") ||
		!strings.Contains(w.Body.String(), "six-character code shown in the server terminal") {
		t.Fatalf("onboarding page = (%d, %q)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), server.setupCode) {
		t.Fatal("onboarding page disclosed its setup code")
	}

	password := "saffron-planetary-cello-woodland"
	values := url.Values{
		"setup_code": {" " + strings.ToLower(server.setupCode) + " "}, "username": {"Owner"},
		"password": {password}, "confirm_password": {password},
	}
	crossOrigin := request(http.MethodPost, "http://admin.example.test/onboarding", values)
	crossOrigin.Header.Set("Origin", "http://attacker.example")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, crossOrigin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin onboarding status = %d", w.Code)
	}

	wrongCode := request(http.MethodPost, "http://admin.example.test/onboarding", url.Values{
		"setup_code": {"ZZZZZZ"}, "username": {"owner"},
		"password": {password}, "confirm_password": {password},
	})
	wrongCode.Header.Set("Origin", "http://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, wrongCode)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "setup code is incorrect") {
		t.Fatalf("wrong setup code = (%d, %q)", w.Code, w.Body.String())
	}

	complete := request(http.MethodPost, "http://admin.example.test/onboarding", values)
	complete.Header.Set("Origin", "http://admin.example.test")
	complete.Header.Set("User-Agent", "onboarding test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, complete)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/security/passkeys" {
		t.Fatalf("complete onboarding = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	cookie := responseCookie(t, w.Result(), "wispdeck_session")
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("onboarding session cookie = %#v", cookie)
	}

	user, err := server.database.UserByUsername(context.Background(), "owner")
	if err != nil || user.Role != auth.RoleSuperuser || user.Status != auth.UserActive {
		t.Fatalf("initial superuser = (%+v, %v)", user, err)
	}
	events, err := server.database.AuthEventsByUser(context.Background(), user.ID, 10)
	if err != nil || len(events) < 1 || events[len(events)-1].Kind != "initial_superuser_created" {
		t.Fatalf("initial superuser events = (%+v, %v)", events, err)
	}

	reused := request(http.MethodPost, "http://admin.example.test/onboarding", values)
	reused.Header.Set("Origin", "http://admin.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, reused)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("reused onboarding = (%d, %q)", w.Code, w.Header().Get("Location"))
	}

	security := request(http.MethodGet, "http://admin.example.test/security/passkeys", nil)
	security.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, security)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Add a passkey") {
		t.Fatalf("post-onboarding security page = (%d, %q)", w.Code, w.Body.String())
	}
}
