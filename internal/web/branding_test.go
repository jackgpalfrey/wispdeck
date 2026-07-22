package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/branding"
)

func TestSuperuserBrandingAppliesAcrossApplicationAndContentOrigins(t *testing.T) {
	t.Parallel()
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	change := request(http.MethodPost, "http://admin.example.test/settings/branding", url.Values{
		"csrf_token":           {session.CSRFToken},
		"instance_name":        {"Jack’s Deck"},
		"tagline":              {"Useful things, in one place."},
		"accent":               {"ocean"},
		"landing_page_enabled": {"true"},
	})
	change.Header.Set("Origin", "http://admin.example.test")
	change.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, change)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings?branding=saved#branding" {
		t.Fatalf("change branding = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	stored, err := server.database.BrandingSettings(context.Background())
	if err != nil || stored.Name != "Jack’s Deck" || stored.Tagline != "Useful things, in one place." ||
		stored.Accent != "ocean" || !stored.LandingPageEnabled {
		t.Fatalf("stored branding = (%+v, %v)", stored, err)
	}

	for _, target := range []string{"http://admin.example.test/", "http://admin.example.test/login"} {
		page := request(http.MethodGet, target, nil)
		w = httptest.NewRecorder()
		server.handler.ServeHTTP(w, page)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Jack’s Deck") ||
			!strings.Contains(w.Body.String(), "Useful things, in one place.") {
			t.Fatalf("branded page %s = (%d, %q)", target, w.Code, w.Body.String())
		}
	}

	stylesheet := request(http.MethodGet, "http://admin.example.test/assets/branding.css", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, stylesheet)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/css; charset=utf-8" ||
		w.Body.String() != ":root { --accbg: #315f8c; }\n" {
		t.Fatalf("branding stylesheet = (%d, %q, %q)", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	etag := w.Header().Get("ETag")
	stylesheet = request(http.MethodGet, "http://admin.example.test/assets/branding.css", nil)
	stylesheet.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, stylesheet)
	if w.Code != http.StatusNotModified {
		t.Fatalf("conditional branding stylesheet status = %d", w.Code)
	}

	if _, err := server.sites.Create(context.Background(), siteActor(session), "reserved", "Reserved site"); err != nil {
		t.Fatal(err)
	}
	placeholder := httptest.NewRequest(http.MethodGet, "http://reserved.sites.example.test/", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, placeholder)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Jack’s Deck") ||
		!strings.Contains(w.Body.String(), `class="accent-ocean"`) ||
		!strings.Contains(w.Body.String(), `aria-hidden="true">J</div>`) {
		t.Fatalf("branded site placeholder = (%d, %q)", w.Code, w.Body.String())
	}
}

func TestDisabledLandingPageRedirectsOnlySignedOutRoot(t *testing.T) {
	t.Parallel()
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	create := request(http.MethodPost, "http://admin.example.test/links/create",
		directShortLinkValues(session.CSRFToken, "public-test", "https://example.com/public"))
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create public link = (%d, %q)", w.Code, w.Body.String())
	}

	change := request(http.MethodPost, "http://admin.example.test/settings/branding", url.Values{
		"csrf_token": {session.CSRFToken}, "instance_name": {"Private Deck"},
		"tagline": {"Sign in to continue."}, "accent": {"violet"},
	})
	change.Header.Set("Origin", "http://admin.example.test")
	change.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, change)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable landing page = (%d, %q)", w.Code, w.Body.String())
	}

	root := request(http.MethodGet, "http://admin.example.test/", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, root)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Fatalf("signed-out root = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	publicLink := request(http.MethodGet, "http://admin.example.test/public-test", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicLink)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://example.com/public" {
		t.Fatalf("public link with disabled landing = (%d, %q)", w.Code, w.Header().Get("Location"))
	}

	login := request(http.MethodGet, "http://admin.example.test/login", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "back to the front page") {
		t.Fatalf("login with disabled landing = (%d, %q)", w.Code, w.Body.String())
	}

	root.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, root)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "My Links") {
		t.Fatalf("signed-in root = (%d, %q)", w.Code, w.Body.String())
	}
}

func TestBrandingChangeRejectsInvalidInputAndOrdinaryUsers(t *testing.T) {
	t.Parallel()
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	invalid := request(http.MethodPost, "http://admin.example.test/settings/branding", url.Values{
		"csrf_token": {session.CSRFToken}, "instance_name": {"Unsafe\nName"},
		"tagline": {"A valid tagline"}, "accent": {"url(javascript:bad)"},
	})
	invalid.Header.Set("Origin", "http://admin.example.test")
	invalid.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, invalid)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "available colours") {
		t.Fatalf("invalid branding = (%d, %q)", w.Code, w.Body.String())
	}
	if current := server.branding.Current(); current.Name != "sites.example.test" || current.Accent != branding.DefaultAccent {
		t.Fatalf("invalid change altered branding: %+v", current)
	}

	ordinaryCookie, ordinarySession := createOrdinaryTestUser(t, server)
	forbidden := request(http.MethodPost, "http://admin.example.test/settings/branding", url.Values{
		"csrf_token": {ordinarySession.CSRFToken}, "instance_name": {"Not allowed"},
		"tagline": {"Still not allowed"}, "accent": {"forest"},
	})
	forbidden.Header.Set("Origin", "http://admin.example.test")
	forbidden.AddCookie(ordinaryCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, forbidden)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ordinary-user branding status = %d", w.Code)
	}
}

func createOrdinaryTestUser(t *testing.T, server testServer) (*http.Cookie, auth.Session) {
	t.Helper()
	password := "ordinary correct horse battery staple"
	passwords, err := auth.NewPasswordManager(server.keys)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.database.CreateManagedUser(
		context.Background(), "ordinary", hash, auth.RoleUser, auth.UserActive, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	return passwordOnlyLogin(t, server, "ordinary", password)
}
