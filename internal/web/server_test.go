package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
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
	"github.com/wispdeck/wispdeck/internal/branding"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	"github.com/wispdeck/wispdeck/internal/site"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/internal/updater"
	"github.com/wispdeck/wispdeck/wispist"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
)

type testServer struct {
	handler     http.Handler
	authService *auth.Service
	database    *store.SQLite
	keys        *auth.KeyMaterial
	passkeys    *auth.PasskeyService
	totp        *auth.TOTPService
	links       *shortlink.Service
	sites       *site.Service
	wispist     *wispist.Engine
	branding    *branding.Service
	updates     *updater.Manager
	setupCode   string
}

func newTestServer(t *testing.T, production bool) testServer {
	return newTestServerWithUpdates(t, production, nil)
}

func newTestServerWithUpdates(
	t *testing.T,
	production bool,
	updateFactory func(*store.SQLite) *updater.Manager,
) testServer {
	return newTestServerState(t, production, updateFactory, true)
}

func newOnboardingTestServer(t *testing.T, production bool) testServer {
	return newTestServerState(t, production, nil, false)
}

func newTestServerState(
	t *testing.T,
	production bool,
	updateFactory func(*store.SQLite) *updater.Manager,
	createInitialUser bool,
) testServer {
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
	if createInitialUser {
		hash, err := passwords.Hash("correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.CreateUser(ctx, "alice", hash, time.Now()); err != nil {
			t.Fatal(err)
		}
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
	shortLinkService, err := shortlink.NewService(database, shortlink.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	siteService, err := site.NewService(database, site.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	wispistStores, err := wispistsqlite.NewFactory(filepath.Join(t.TempDir(), "wispist"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wispistStores.Close() })
	wispistEngine, err := wispist.NewEngine(wispist.Config{
		StoreFactory: wispistStores,
		Limits:       wispist.DefaultLimits(),
		RateLimits:   wispist.DefaultRateLimits(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var updateManager *updater.Manager
	if updateFactory != nil {
		updateManager = updateFactory(database)
	}
	brandingService, err := branding.NewService(ctx, database, "sites.example.test")
	if err != nil {
		t.Fatal(err)
	}
	setupCode := "ABCD23"
	server, err := New(Config{
		AppOrigin:        origin,
		SiteDomain:       "sites.example.test",
		Development:      !production,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordChecker:  auth.NewStaticPasswordChecker(),
		InitialSetupCode: setupCode,
	}, authService, passkeyService, totpService, shortLinkService, siteService,
		wispistEngine, brandingService, updateManager)
	if err != nil {
		t.Fatal(err)
	}
	return testServer{
		handler: server.Handler(), authService: authService,
		database: database, keys: keyMaterial, passkeys: passkeyService,
		totp: totpService, links: shortLinkService, sites: siteService, wispist: wispistEngine,
		branding: brandingService, updates: updateManager, setupCode: setupCode,
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

func TestHealthzIsMinimalAndDoesNotCaptureSiteOrigins(t *testing.T) {
	server := newTestServer(t, false)
	for _, host := range []string{"admin.example.test", "127.0.0.1:8080", "[::1]:8080"} {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/healthz", nil)
		r.Host = host
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != "ok\n" ||
			w.Header().Get("Cache-Control") != "no-store" ||
			w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("health for %q = (%d, %#v, %q)", host, w.Code, w.Header(), w.Body.String())
		}
	}

	post := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/healthz", nil)
	post.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, post)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("health POST = (%d, %#v)", w.Code, w.Header())
	}

	siteRequest := httptest.NewRequest(http.MethodGet, "http://notes.sites.example.test/healthz", nil)
	siteRequest.Host = "notes.sites.example.test"
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, siteRequest)
	if w.Code != http.StatusNotFound || w.Body.String() == "ok\n" {
		t.Fatalf("site-origin health path = (%d, %q)", w.Code, w.Body.String())
	}
}

func directShortLinkValues(csrf, slug, target string) url.Values {
	return url.Values{
		"csrf_token":   {csrf},
		"slug":         {slug},
		"mode":         {string(shortlink.ModeRedirect)},
		"target_label": {""},
		"target_url":   {target},
	}
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

func TestValidSiteDomain(t *testing.T) {
	tests := []struct {
		value string
		valid bool
	}{
		{value: "example.com", valid: true},
		{value: "sites.example.com", valid: true},
		{value: "localhost", valid: true},
		{value: "", valid: false},
		{value: "https://example.com", valid: false},
		{value: "*.example.com", valid: false},
		{value: "example.com:8443", valid: false},
		{value: "Example.com", valid: false},
		{value: "127.0.0.1", valid: false},
		{value: "-sites.example.com", valid: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := validSiteDomain(test.value); got != test.valid {
				t.Fatalf("validSiteDomain(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
	origin, err := url.Parse("http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(Config{
		AppOrigin: origin, SiteDomain: "localhost", PreviewDomain: "localhost", Development: true,
	}); err == nil {
		t.Fatal("accepted identical public and preview domains")
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

	create := request(http.MethodPost, "http://admin.example.test/links/create",
		directShortLinkValues(session.CSRFToken, "Release-Notes", "https://example.com/releases/v1?from=wispdeck"))
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/?created=release-notes" {
		t.Fatalf("create short link = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	createdLocation := w.Header().Get("Location")

	resolve := request(http.MethodGet, "http://admin.example.test/RELEASE-NOTES", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, resolve)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://example.com/releases/v1?from=wispdeck" {
		t.Fatalf("resolve short link = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	dashboard := request(http.MethodGet, "http://admin.example.test"+createdLocation, nil)
	dashboard.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/release-notes") ||
		!strings.Contains(w.Body.String(), `<span class="num">1</span>`) ||
		!strings.Contains(w.Body.String(), "Your short link is ready") {
		t.Fatalf("short-link dashboard = (%d, %q)", w.Code, w.Body.String())
	}
	links, err := server.database.ShortLinks(context.Background(), session.User.ID, false)
	if err != nil || len(links) != 1 {
		t.Fatalf("stored short links = (%#v, %v)", links, err)
	}

	detail := request(http.MethodGet, "http://admin.example.test/links/"+links[0].ID, nil)
	detail.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, detail)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "admin.example.test/release-notes") ||
		!strings.Contains(w.Body.String(), "1</span> visit · all time") {
		t.Fatalf("short-link detail = (%d, %q)", w.Code, w.Body.String())
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

	reclaim := request(http.MethodPost, "http://admin.example.test/links/create",
		directShortLinkValues(session.CSRFToken, "release-notes", "https://replacement.example"))
	reclaim.Header.Set("Origin", "http://admin.example.test")
	reclaim.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, reclaim)
	if w.Code != http.StatusConflict {
		t.Fatalf("retired-name reclaim status = %d, body = %q", w.Code, w.Body.String())
	}
}

func TestHostedSiteDraftPreviewPublishRollbackAndAliases(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")

	create := request(http.MethodPost, "http://admin.example.test/sites/create", url.Values{
		"csrf_token": {session.CSRFToken}, "name": {"Docs"}, "title": {"Product docs"},
	})
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sites/docs" {
		t.Fatalf("create site = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	siteDetail := request(http.MethodGet, "http://admin.example.test/sites/docs", nil)
	siteDetail.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, siteDetail)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "docs.sites.example.test") ||
		!strings.Contains(w.Body.String(), "Upload a new draft") {
		t.Fatalf("site detail = (%d, %q)", w.Code, w.Body.String())
	}

	empty := siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, empty)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "This address is ready") ||
		!strings.Contains(w.Body.String(), "Manage this site") || strings.Contains(w.Body.String(), "Product docs") {
		t.Fatalf("empty site placeholder = (%d, %q)", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("empty site headers = %#v", w.Header())
	}

	values := directShortLinkValues(session.CSRFToken, "docs", "https://example.com")
	link := request(http.MethodPost, "http://admin.example.test/links/create", values)
	link.Header.Set("Origin", "http://admin.example.test")
	link.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, link)
	if w.Code != http.StatusConflict {
		t.Fatalf("site/link global-name collision = (%d, %q)", w.Code, w.Body.String())
	}

	sites, err := server.database.Sites(context.Background(), session.User.ID, false)
	if err != nil || len(sites) != 1 {
		t.Fatalf("created sites = (%#v, %v)", sites, err)
	}
	firstZIP := webZIP(t, map[string]string{
		"index.html":       "<!doctype html><title>One</title><h1>Version one</h1>",
		"guide/index.html": "<h1>Guide one</h1>",
	})
	upload := multipartSiteRequest(t, session.CSRFToken, sites[0].ID, "docs", firstZIP)
	upload.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, upload)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload first draft = (%d, %q)", w.Code, w.Body.String())
	}

	alias := request(http.MethodGet, "http://admin.example.test/docs?from=short", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, alias)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "http://docs.sites.example.test/?from=short" {
		t.Fatalf("root site alias = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	nestedAlias := request(http.MethodGet, "http://admin.example.test/docs/guide/?from=short", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, nestedAlias)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "http://docs.sites.example.test/guide/?from=short" {
		t.Fatalf("nested site alias = (%d, %q)", w.Code, w.Header().Get("Location"))
	}

	draft := siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	draft.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, draft)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "currently a draft") || strings.Contains(w.Body.String(), "Version one") {
		t.Fatalf("public draft gate = (%d, %q)", w.Code, w.Body.String())
	}

	preview := request(http.MethodPost, "http://admin.example.test/sites/preview", url.Values{
		"csrf_token": {session.CSRFToken}, "site_name": {"docs"},
	})
	preview.Header.Set("Origin", "http://admin.example.test")
	preview.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, preview)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create preview grant = (%d, %q)", w.Code, w.Body.String())
	}
	previewURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil || !strings.HasSuffix(previewURL.Host, ".preview.sites.example.test") ||
		previewURL.Query().Get("code") == "" {
		t.Fatalf("preview grant URL = (%q, %v)", w.Header().Get("Location"), err)
	}
	accept := siteRequest(http.MethodGet, previewURL.String(), previewURL.Host)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, accept)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("accept preview = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("preview handoff headers = %#v", w.Header())
	}
	previewCookies := w.Result().Cookies()
	if len(previewCookies) != 2 {
		t.Fatalf("preview cookies = %#v", previewCookies)
	}
	reusedGrant := siteRequest(http.MethodGet, previewURL.String(), previewURL.Host)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, reusedGrant)
	if w.Code != http.StatusNotFound {
		t.Fatalf("reused preview grant status = %d", w.Code)
	}
	previewOrigin := previewURL.Scheme + "://" + previewURL.Host
	previewPage := siteRequest(http.MethodGet, previewOrigin+"/", previewURL.Host)
	for _, previewCookie := range previewCookies {
		previewPage.AddCookie(previewCookie)
	}
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, previewPage)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version one") ||
		!strings.Contains(w.Body.String(), "Draft preview") || !strings.Contains(w.Body.String(), "Publish…") {
		t.Fatalf("private draft preview = (%d, %q)", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Vary") != "Cookie" {
		t.Fatalf("private draft cache headers = %#v", w.Header())
	}
	if w.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" ||
		w.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" ||
		w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("private draft embedding headers = %#v", w.Header())
	}
	previewETag := w.Header().Get("ETag")
	previewHead := siteRequest(http.MethodHead, previewOrigin+"/", previewURL.Host)
	for _, previewCookie := range previewCookies {
		previewHead.AddCookie(previewCookie)
	}
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, previewHead)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("ETag") != previewETag {
		t.Fatalf("private draft HEAD = (%d, %q, %q)", w.Code, w.Header().Get("ETag"), w.Body.String())
	}
	publicWithPreviewCookie := siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	for _, previewCookie := range previewCookies {
		publicWithPreviewCookie.AddCookie(previewCookie)
	}
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicWithPreviewCookie)
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "Version one") {
		t.Fatalf("preview cookie escaped to public origin = (%d, %q)", w.Code, w.Body.String())
	}

	sites, err = server.database.Sites(context.Background(), session.User.ID, false)
	if err != nil || len(sites[0].Releases) != 1 {
		t.Fatalf("first release = (%#v, %v)", sites, err)
	}
	firstRelease := sites[0].Releases[0].ID
	publish := request(http.MethodPost, "http://admin.example.test/sites/publish", url.Values{
		"csrf_token": {session.CSRFToken}, "site_id": {sites[0].ID},
		"site_name": {"docs"}, "release_id": {firstRelease},
	})
	publish.Header.Set("Origin", "http://admin.example.test")
	publish.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publish)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("publish first release = (%d, %q)", w.Code, w.Body.String())
	}
	public := siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, public)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version one") || strings.Contains(w.Body.String(), "Draft preview") {
		t.Fatalf("first public release = (%d, %q)", w.Code, w.Body.String())
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("public release omitted ETag")
	}
	conditional := siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	conditional.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, conditional)
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("conditional site response = (%d, %q)", w.Code, w.Body.String())
	}
	head := siteRequest(http.MethodHead, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, head)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD site response = (%d, %q, %q)", w.Code, w.Header().Get("Content-Length"), w.Body.String())
	}
	appRouteOnSite := siteRequest(http.MethodGet, "http://docs.sites.example.test/login", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, appRouteOnSite)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "Sign in") {
		t.Fatalf("application route escaped to content host = (%d, %q)", w.Code, w.Body.String())
	}
	nonCanonical := siteRequest(http.MethodGet, "http://docs.sites.example.test/guide/../index.html", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, nonCanonical)
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-canonical hosted path status = %d", w.Code)
	}

	secondZIP := webZIP(t, map[string]string{"index.html": "<!doctype html><h1>Version two</h1>"})
	upload = multipartSiteRequest(t, session.CSRFToken, sites[0].ID, "docs", secondZIP)
	upload.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, upload)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload second draft = (%d, %q)", w.Code, w.Body.String())
	}
	public = siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, public)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version one") || strings.Contains(w.Body.String(), "Version two") {
		t.Fatalf("draft replaced public release = (%d, %q)", w.Code, w.Body.String())
	}

	previewTokenCookie, previewViewCookie, secondPreviewURL := grantSitePreview(t, server, cookie, session.CSRFToken, "docs")
	if secondPreviewURL.Host == previewURL.Host {
		t.Fatalf("preview origin was reused: %q", secondPreviewURL.Host)
	}
	secondPreviewOrigin := secondPreviewURL.Scheme + "://" + secondPreviewURL.Host
	draftTwo := siteRequest(http.MethodGet, secondPreviewOrigin+"/", secondPreviewURL.Host)
	draftTwo.AddCookie(previewTokenCookie)
	draftTwo.AddCookie(previewViewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, draftTwo)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version two") ||
		!strings.Contains(w.Body.String(), ">Current</a>") || strings.Contains(w.Body.String(), "Version one") {
		t.Fatalf("second private draft preview = (%d, %q)", w.Code, w.Body.String())
	}
	selectCurrent := siteRequest(
		http.MethodGet,
		secondPreviewOrigin+"/_wispdeck/preview/view/current?return=/",
		secondPreviewURL.Host,
	)
	selectCurrent.AddCookie(previewTokenCookie)
	selectCurrent.AddCookie(previewViewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, selectCurrent)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("select current preview = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	currentViewCookie := responseCookie(t, w.Result(), "wispdeck_preview_view")
	currentPreview := siteRequest(http.MethodGet, secondPreviewOrigin+"/", secondPreviewURL.Host)
	currentPreview.AddCookie(previewTokenCookie)
	currentPreview.AddCookie(currentViewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, currentPreview)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version one") ||
		!strings.Contains(w.Body.String(), "<strong>Current</strong>") || strings.Contains(w.Body.String(), "Version two") {
		t.Fatalf("current release preview = (%d, %q)", w.Code, w.Body.String())
	}

	sites, err = server.database.Sites(context.Background(), session.User.ID, false)
	if err != nil || len(sites[0].Releases) != 2 {
		t.Fatalf("second release = (%#v, %v)", sites, err)
	}
	secondRelease := sites[0].Releases[0].ID
	publish = request(http.MethodPost, "http://admin.example.test/sites/publish", url.Values{
		"csrf_token": {session.CSRFToken}, "site_id": {sites[0].ID},
		"site_name": {"docs"}, "release_id": {secondRelease},
	})
	publish.Header.Set("Origin", "http://admin.example.test")
	publish.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publish)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("publish second release = (%d, %q)", w.Code, w.Body.String())
	}
	public = siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, public)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version two") {
		t.Fatalf("second public release = (%d, %q)", w.Code, w.Body.String())
	}

	rollback := request(http.MethodPost, "http://admin.example.test/sites/publish", url.Values{
		"csrf_token": {session.CSRFToken}, "site_id": {sites[0].ID},
		"site_name": {"docs"}, "release_id": {firstRelease},
	})
	rollback.Header.Set("Origin", "http://admin.example.test")
	rollback.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, rollback)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("roll back release = (%d, %q)", w.Code, w.Body.String())
	}
	public = siteRequest(http.MethodGet, "http://docs.sites.example.test/", "docs.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, public)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version one") || strings.Contains(w.Body.String(), "Version two") {
		t.Fatalf("rolled-back public release = (%d, %q)", w.Code, w.Body.String())
	}

	state := request(http.MethodPost, "http://admin.example.test/sites/state", url.Values{
		"csrf_token": {session.CSRFToken}, "site_id": {sites[0].ID},
		"site_name": {"docs"}, "enabled": {"false"},
	})
	state.Header.Set("Origin", "http://admin.example.test")
	state.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, state)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable site = (%d, %q)", w.Code, w.Body.String())
	}
	for _, target := range []string{"http://docs.sites.example.test/", "http://admin.example.test/docs"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w = httptest.NewRecorder()
		server.handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("disabled site %s status = %d", target, w.Code)
		}
	}
	state = request(http.MethodPost, "http://admin.example.test/sites/state", url.Values{
		"csrf_token": {session.CSRFToken}, "site_id": {sites[0].ID},
		"site_name": {"docs"}, "enabled": {"true"},
	})
	state.Header.Set("Origin", "http://admin.example.test")
	state.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, state)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("re-enable site = (%d, %q)", w.Code, w.Body.String())
	}

	unknownHost := siteRequest(http.MethodGet, "http://unconfigured.example.test/", "unconfigured.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, unknownHost)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host status = %d", w.Code)
	}
	invalidPreviewHost := siteRequest(
		http.MethodGet, "http://docs.preview.sites.example.test/", "docs.preview.sites.example.test",
	)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, invalidPreviewHost)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("invalid preview host status = %d", w.Code)
	}
}

func TestDraftPreviewEntryContinuesThroughLogin(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	created, err := server.sites.Create(context.Background(), site.Actor{UserID: session.User.ID}, "private", "")
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes := webZIP(t, map[string]string{"index.html": "draft"})
	bundle, err := site.ReadZIP(bytes.NewReader(bundleBytes), int64(len(bundleBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.sites.Upload(context.Background(), site.Actor{UserID: session.User.ID}, created.ID, bundle); err != nil {
		t.Fatal(err)
	}

	entry := request(http.MethodGet, "http://admin.example.test/sites/private/preview-entry", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, entry)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous preview entry = (%d, %q)", w.Code, w.Header().Get("Location"))
	}
	returnCookie := responseCookie(t, w.Result(), "wispdeck_preview_return")

	login := request(http.MethodPost, "http://admin.example.test/login", url.Values{
		"username": {"alice"}, "password": {"correct horse battery staple"},
	})
	login.Header.Set("Origin", "http://admin.example.test")
	login.AddCookie(returnCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sites/private/preview-entry" {
		t.Fatalf("preview login continuation = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	_ = cookie
}

func TestWispistHostedSiteLiveDraftIsolation(t *testing.T) {
	server := newTestServer(t, false)
	sessionCookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	actor := site.Actor{UserID: session.User.ID}
	created, err := server.sites.Create(context.Background(), actor, "itinerary", "Holiday itinerary")
	if err != nil {
		t.Fatal(err)
	}
	declaration := `{"version":1,"collections":{"before-you-go":{"access":"shared"}}}`
	firstZIP := webZIP(t, map[string]string{
		"index.html":   `<html><head><script>window.ready = Boolean(wispist)</script></head><body>One</body></html>`,
		"wispist.json": declaration,
	})
	firstBundle, err := site.ReadZIP(bytes.NewReader(firstZIP), int64(len(firstZIP)))
	if err != nil {
		t.Fatal(err)
	}
	firstRelease, err := server.sites.Upload(context.Background(), actor, created.ID, firstBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.sites.Publish(context.Background(), actor, created.ID, firstRelease.ID); err != nil {
		t.Fatal(err)
	}

	publicPage := siteRequest(http.MethodGet, "http://itinerary.sites.example.test/", "itinerary.sites.example.test")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicPage)
	bootstrap := `<head><script src="/_wispist/client/v1.js" data-wispist-bootstrap data-wispist-mode="live" data-wispist-read-only="false"></script><script>`
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), bootstrap) {
		t.Fatalf("public bootstrap = (%d, %q)", w.Code, w.Body.String())
	}

	publicOrigin := "http://itinerary.sites.example.test"
	publicCreate := httptest.NewRequest(http.MethodPut, publicOrigin+"/_wispist/v1/collections/before-you-go/documents/passport", strings.NewReader(`{"data":{"text":"Pack passport","done":false}}`))
	publicCreate.Host = "itinerary.sites.example.test"
	publicCreate.Header.Set("Origin", publicOrigin)
	publicCreate.Header.Set("Content-Type", "application/json")
	publicCreate.Header.Set("If-None-Match", "*")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicCreate)
	if w.Code != http.StatusCreated {
		t.Fatalf("public Wispist create = (%d, %q)", w.Code, w.Body.String())
	}
	var liveDocument struct {
		Revision string `json:"revision"`
		Data     struct {
			Done bool `json:"done"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &liveDocument); err != nil {
		t.Fatal(err)
	}

	secondZIP := webZIP(t, map[string]string{
		"index.html":   `<html><head></head><body>Two</body></html>`,
		"wispist.json": declaration,
	})
	secondBundle, err := site.ReadZIP(bytes.NewReader(secondZIP), int64(len(secondZIP)))
	if err != nil {
		t.Fatal(err)
	}
	secondRelease, err := server.sites.Upload(context.Background(), actor, created.ID, secondBundle)
	if err != nil {
		t.Fatal(err)
	}
	previewCookie, viewCookie, previewURL := grantSitePreview(t, server, sessionCookie, session.CSRFToken, "itinerary")
	previewOrigin := previewURL.Scheme + "://" + previewURL.Host
	draftPage := siteRequest(http.MethodGet, previewOrigin+"/", previewURL.Host)
	draftPage.AddCookie(previewCookie)
	draftPage.AddCookie(viewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, draftPage)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-wispist-mode="draft"`) ||
		!strings.Contains(w.Body.String(), `data-wispist-read-only="false"`) {
		t.Fatalf("draft bootstrap = (%d, %q)", w.Code, w.Body.String())
	}

	draftCreate := httptest.NewRequest(http.MethodPut, previewOrigin+"/_wispist/v1/collections/before-you-go/documents/passport", strings.NewReader(`{"data":{"text":"Draft passport","done":true}}`))
	draftCreate.Host = previewURL.Host
	draftCreate.Header.Set("Origin", previewOrigin)
	draftCreate.Header.Set("Content-Type", "application/json")
	draftCreate.Header.Set("If-None-Match", "*")
	draftCreate.AddCookie(previewCookie)
	draftCreate.AddCookie(viewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, draftCreate)
	if w.Code != http.StatusCreated {
		t.Fatalf("draft Wispist create = (%d, %q)", w.Code, w.Body.String())
	}

	publicRead := siteRequest(http.MethodGet, publicOrigin+"/_wispist/v1/collections/before-you-go/documents/passport", "itinerary.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicRead)
	if w.Code != http.StatusOK {
		t.Fatalf("public Wispist read = (%d, %q)", w.Code, w.Body.String())
	}
	var stillLive struct {
		Revision string `json:"revision"`
		Data     struct {
			Done bool `json:"done"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stillLive); err != nil {
		t.Fatal(err)
	}
	if stillLive.Data.Done || stillLive.Revision != liveDocument.Revision {
		t.Fatalf("draft data leaked into live: %+v", stillLive)
	}

	selectCurrent := siteRequest(http.MethodGet, previewOrigin+"/_wispdeck/preview/view/current?return=/", previewURL.Host)
	selectCurrent.AddCookie(previewCookie)
	selectCurrent.AddCookie(viewCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, selectCurrent)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("select current = (%d, %q)", w.Code, w.Body.String())
	}
	currentCookie := responseCookie(t, w.Result(), "wispdeck_preview_view")
	currentMutation := httptest.NewRequest(http.MethodPut, previewOrigin+"/_wispist/v1/collections/before-you-go/documents/passport", strings.NewReader(`{"data":{"done":true}}`))
	currentMutation.Host = previewURL.Host
	currentMutation.Header.Set("Origin", previewOrigin)
	currentMutation.Header.Set("Content-Type", "application/json")
	currentMutation.Header.Set("If-Match", `"`+liveDocument.Revision+`"`)
	currentMutation.AddCookie(previewCookie)
	currentMutation.AddCookie(currentCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, currentMutation)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), wispist.ProblemBaseURL+"forbidden/") {
		t.Fatalf("current-preview mutation = (%d, %q)", w.Code, w.Body.String())
	}

	if err := server.sites.Publish(context.Background(), actor, created.ID, secondRelease.ID); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, publicRead.Clone(context.Background()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"done":false`) {
		t.Fatalf("publish changed live data = (%d, %q)", w.Code, w.Body.String())
	}

	invalidZIP := webZIP(t, map[string]string{
		"index.html":   "invalid declaration",
		"wispist.json": `{"version":1,"collections":{"items":{"access":"secret"}}}`,
	})
	invalidUpload := multipartSiteRequest(t, session.CSRFToken, created.ID, created.Name, invalidZIP)
	invalidUpload.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, invalidUpload)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid wispist.json") {
		t.Fatalf("invalid declaration upload = (%d, %q)", w.Code, w.Body.String())
	}
}

func TestWispistManagementExportRepairCleanupAndPermanentSiteName(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	actor := site.Actor{UserID: session.User.ID}
	created, err := server.sites.Create(context.Background(), actor, "shared-list", "Shared list")
	if err != nil {
		t.Fatal(err)
	}
	declaration := `{"version":1,"collections":{"items":{"access":"shared"},"empty":{"access":"shared"}}}`
	bundleBytes := webZIP(t, map[string]string{
		"index.html": "<html><head></head><body>Shared</body></html>", "wispist.json": declaration,
	})
	bundle, err := site.ReadZIP(bytes.NewReader(bundleBytes), int64(len(bundleBytes)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := server.sites.Upload(context.Background(), actor, created.ID, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.sites.Publish(context.Background(), actor, created.ID, first.ID); err != nil {
		t.Fatal(err)
	}

	publicOrigin := "http://shared-list.sites.example.test"
	createDocument := httptest.NewRequest(
		http.MethodPut, publicOrigin+"/_wispist/v1/collections/items/documents/passport",
		strings.NewReader(`{"data":{"done":false,"text":"Pack passport"}}`),
	)
	createDocument.Host = "shared-list.sites.example.test"
	createDocument.Header.Set("Origin", publicOrigin)
	createDocument.Header.Set("Content-Type", "application/json")
	createDocument.Header.Set("If-None-Match", "*")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, createDocument)
	if w.Code != http.StatusCreated {
		t.Fatalf("create managed document = (%d, %q)", w.Code, w.Body.String())
	}
	var original struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &original); err != nil {
		t.Fatal(err)
	}

	dataPage := request(http.MethodGet, "http://admin.example.test/sites/shared-list/data?namespace=live&collection=items", nil)
	dataPage.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dataPage)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Site data") ||
		!strings.Contains(w.Body.String(), "passport") || !strings.Contains(w.Body.String(), "empty") ||
		!strings.Contains(w.Body.String(), "10.0 MiB") {
		t.Fatalf("site data page = (%d, %q)", w.Code, w.Body.String())
	}

	update := request(http.MethodPost, "http://admin.example.test/sites/shared-list/data/update", url.Values{
		"csrf_token": {session.CSRFToken}, "namespace": {"live"}, "collection": {"items"},
		"document_id": {"passport"}, "revision": {original.Revision},
		"data": {`{"done":true,"text":"Packed passport"}`},
	})
	update.Header.Set("Origin", "http://admin.example.test")
	update.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, update)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "collection=items") {
		t.Fatalf("managed document update = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	stale := request(http.MethodPost, "http://admin.example.test/sites/shared-list/data/update", url.Values{
		"csrf_token": {session.CSRFToken}, "namespace": {"live"}, "collection": {"items"},
		"document_id": {"passport"}, "revision": {original.Revision}, "data": {`{"done":false}`},
	})
	stale.Header.Set("Origin", "http://admin.example.test")
	stale.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, stale)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "changed after this page loaded") {
		t.Fatalf("stale managed update = (%d, %q)", w.Code, w.Body.String())
	}

	exportRequest := request(http.MethodGet, "http://admin.example.test/sites/shared-list/data/export", nil)
	exportRequest.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, exportRequest)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), "shared-list-wispist.json") {
		t.Fatalf("site data export = (%d, %#v, %q)", w.Code, w.Header(), w.Body.String())
	}
	var exported struct {
		Format     string                               `json:"format"`
		Namespaces map[string]wispist.NamespaceSnapshot `json:"namespaces"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	var exportedData struct {
		Done bool   `json:"done"`
		Text string `json:"text"`
	}
	live := exported.Namespaces["live"]
	if len(live.Collections["items"]) == 1 {
		if err := json.Unmarshal(live.Collections["items"][0].Data, &exportedData); err != nil {
			t.Fatal(err)
		}
	}
	if exported.Format != "wispist-site-export" || len(exported.Namespaces) != 2 ||
		len(live.Collections["items"]) != 1 || len(live.Collections["empty"]) != 0 ||
		!exportedData.Done || exportedData.Text != "Packed passport" {
		t.Fatalf("exported data = %+v", exported)
	}

	clear := request(http.MethodPost, "http://admin.example.test/sites/shared-list/data/clear", url.Values{
		"csrf_token": {session.CSRFToken}, "namespace": {"live"}, "collection": {"items"}, "confirm": {"items"},
	})
	clear.Header.Set("Origin", "http://admin.example.test")
	clear.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, clear)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("clear collection = (%d, %q)", w.Code, w.Body.String())
	}
	usage, err := server.wispist.NamespaceUsage(context.Background(), wispist.NamespaceRef{
		StoreKey: created.ID, Namespace: "live",
	})
	if err != nil || usage.Documents != 0 {
		t.Fatalf("usage after clear = (%+v, %v)", usage, err)
	}

	second, err := server.sites.Upload(context.Background(), actor, created.ID, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.sites.Upload(context.Background(), actor, created.ID, bundle); err != nil {
		t.Fatal(err)
	}
	deleteRelease := request(http.MethodPost, "http://admin.example.test/sites/shared-list/releases/delete", url.Values{
		"csrf_token": {session.CSRFToken}, "release_id": {second.ID},
	})
	deleteRelease.Header.Set("Origin", "http://admin.example.test")
	deleteRelease.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, deleteRelease)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete old release = (%d, %q)", w.Code, w.Body.String())
	}

	purge := request(http.MethodPost, "http://admin.example.test/sites/shared-list/purge", url.Values{
		"csrf_token": {session.CSRFToken}, "confirm": {"shared-list"},
	})
	purge.Header.Set("Origin", "http://admin.example.test")
	purge.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, purge)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sites/shared-list" {
		t.Fatalf("purge site = (%d, %q, %q)", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	public := siteRequest(http.MethodGet, publicOrigin+"/", "shared-list.sites.example.test")
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, public)
	if w.Code != http.StatusNotFound {
		t.Fatalf("purged public site status = %d", w.Code)
	}
	sites, err := server.database.Sites(context.Background(), session.User.ID, false)
	if err != nil || len(sites) != 1 || sites[0].Enabled || len(sites[0].Releases) != 0 {
		t.Fatalf("purged managed site = (%+v, %v)", sites, err)
	}
	usage, err = server.wispist.NamespaceUsage(context.Background(), wispist.NamespaceRef{
		StoreKey: created.ID, Namespace: "live",
	})
	if err != nil || usage.Documents != 0 || usage.Bytes != 0 {
		t.Fatalf("purged Wispist data = (%+v, %v)", usage, err)
	}
	if _, err := server.sites.Create(context.Background(), actor, "shared-list", "replacement"); !errors.Is(err, site.ErrNameUnavailable) {
		t.Fatalf("purge released public name: %v", err)
	}
}

func siteRequest(method, target, host string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	return r
}

func grantSitePreview(
	t *testing.T,
	server testServer,
	sessionCookie *http.Cookie,
	csrf, name string,
) (*http.Cookie, *http.Cookie, *url.URL) {
	t.Helper()
	preview := request(http.MethodPost, "http://admin.example.test/sites/preview", url.Values{
		"csrf_token": {csrf}, "site_name": {name},
	})
	preview.Header.Set("Origin", "http://admin.example.test")
	preview.AddCookie(sessionCookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, preview)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create preview grant for %q = (%d, %q)", name, w.Code, w.Body.String())
	}
	previewURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil || previewURL.Query().Get("code") == "" {
		t.Fatalf("preview grant URL for %q = (%q, %v)", name, w.Header().Get("Location"), err)
	}
	accept := siteRequest(http.MethodGet, previewURL.String(), previewURL.Host)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, accept)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("accept preview for %q = (%d, %q)", name, w.Code, w.Body.String())
	}
	return responseCookie(t, w.Result(), "wispdeck_preview"),
		responseCookie(t, w.Result(), "wispdeck_preview_view"), previewURL
}

func multipartSiteRequest(t *testing.T, csrf, siteID, siteName string, bundle []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range map[string]string{
		"csrf_token": csrf, "site_id": siteID, "site_name": siteName,
	} {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	file, err := writer.CreateFormFile("bundle", "site.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(bundle); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://admin.example.test/sites/upload", &body)
	r.Host = "admin.example.test"
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Origin", "http://admin.example.test")
	return r
}

func webZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, contents := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
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
			name:   "missing origin",
			values: directShortLinkValues(session.CSRFToken, "valid", "https://example.com"),
			status: http.StatusForbidden,
		},
		{
			name:   "reserved slug",
			values: directShortLinkValues(session.CSRFToken, "login", "https://example.com"),
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "reserved by Wispdeck",
		},
		{
			name:   "unsafe target",
			values: directShortLinkValues(session.CSRFToken, "unsafe", "javascript:alert(1)"),
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "absolute HTTP or HTTPS URL",
		},
		{
			name: "multiple redirect targets",
			values: url.Values{
				"csrf_token": {session.CSRFToken}, "slug": {"many"}, "mode": {"redirect"},
				"target_label": {"One", "Two"}, "target_url": {"https://one.example", "https://two.example"},
			},
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "between 1 and 25 destinations",
		},
		{
			name: "past expiry",
			values: url.Values{
				"csrf_token": {session.CSRFToken}, "slug": {"expired"}, "mode": {"redirect"},
				"target_label": {""}, "target_url": {"https://example.com"}, "expires_at": {"2000-01-01T00:00"},
			},
			origin: "http://admin.example.test", status: http.StatusBadRequest, body: "future UTC",
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

func TestIndexAndOpenAllModesKeepPrivateMetadataPrivateAndBufferVisits(t *testing.T) {
	server := newTestServer(t, false)
	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	indexValues := url.Values{
		"csrf_token": {session.CSRFToken}, "slug": {"reading"}, "mode": {"index"},
		"title": {"SECRET private reading list"}, "description": {"SECRET internal notes"},
		"target_label": {"Documentation", "Source code"},
		"target_url":   {"https://docs.example/path", "https://source.example/repository"},
	}
	create := request(http.MethodPost, "http://admin.example.test/links/create", indexValues)
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create index link = (%d, %q)", w.Code, w.Body.String())
	}

	head := request(http.MethodHead, "http://admin.example.test/reading", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, head)
	if w.Code != http.StatusOK {
		t.Fatalf("index HEAD status = %d", w.Code)
	}
	if err := server.links.FlushVisits(context.Background()); err != nil {
		t.Fatal(err)
	}
	links, err := server.database.ShortLinks(context.Background(), session.User.ID, false)
	if err != nil || len(links) != 1 || links[0].VisitCount != 0 {
		t.Fatalf("HEAD-counted links = (%#v, %v)", links, err)
	}

	index := request(http.MethodGet, "http://admin.example.test/reading", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, index)
	body := w.Body.String()
	if w.Code != http.StatusOK || w.Header().Get("X-Robots-Tag") != "noindex, nofollow" ||
		!strings.Contains(body, "Documentation") || !strings.Contains(body, "Source code") ||
		strings.Contains(body, "SECRET") {
		t.Fatalf("public index = (%d, %#v, %q)", w.Code, w.Header(), body)
	}
	if err := server.links.FlushVisits(context.Background()); err != nil {
		t.Fatal(err)
	}
	links, err = server.database.ShortLinks(context.Background(), session.User.ID, false)
	if err != nil || len(links) != 1 || links[0].VisitCount != 1 {
		t.Fatalf("GET visit count = (%#v, %v)", links, err)
	}
	stats, err := server.database.ShortLinkDailyStats(context.Background(), session.User.ID, false, time.Now().UTC().Add(-24*time.Hour))
	if err != nil || len(stats) != 1 || stats[0].Visits != 1 {
		t.Fatalf("daily visit stats = (%#v, %v)", stats, err)
	}
	dashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	dashboard.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dashboard)
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "data-copy=") ||
		!strings.Contains(body, "SECRET private reading list") {
		t.Fatalf("management metadata = (%d, %q)", w.Code, body)
	}
	detail := request(http.MethodGet, "http://admin.example.test/links/"+links[0].ID, nil)
	detail.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, detail)
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "SECRET internal notes") ||
		!strings.Contains(body, "1 visit · "+stats[0].Day.Format("Jan 2")) {
		t.Fatalf("management stats detail = (%d, %q)", w.Code, body)
	}

	openValues := url.Values{
		"csrf_token": {session.CSRFToken}, "slug": {"workspace"}, "mode": {"open_all"},
		"title": {"SECRET open-all title"}, "description": {"SECRET open-all notes"},
		"target_label": {"Mail", "Calendar"},
		"target_url":   {"https://mail.example", "https://calendar.example"},
	}
	create = request(http.MethodPost, "http://admin.example.test/links/create", openValues)
	create.Header.Set("Origin", "http://admin.example.test")
	create.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, create)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create open-all link = (%d, %q)", w.Code, w.Body.String())
	}
	openAll := request(http.MethodGet, "http://admin.example.test/workspace", nil)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, openAll)
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "/assets/open-all.js") ||
		!strings.Contains(body, "data-open-all") || !strings.Contains(body, "data-open-target") ||
		strings.Contains(body, "SECRET") {
		t.Fatalf("public open-all page = (%d, %q)", w.Code, body)
	}
}

func TestExpiredShortLinkIsPubliclyNotFound(t *testing.T) {
	server := newTestServer(t, false)
	ctx := context.Background()
	user, err := server.database.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := server.database.CreateShortLink(ctx, user.ID, shortlink.Link{
		Slug: "old", Mode: shortlink.ModeRedirect, ExpiresAt: createdAt.Add(time.Hour),
		Destinations: []shortlink.Destination{{URL: "https://example.com"}},
	}, shortlink.DefaultLimits(), createdAt); err != nil {
		t.Fatal(err)
	}
	r := request(http.MethodGet, "http://admin.example.test/old", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expired link status = %d", w.Code)
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
	aliceLink, err := server.database.CreateShortLink(ctx, alice.ID, shortlink.Link{
		Slug: "alice-link", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://alice.example"}},
	}, shortlink.DefaultLimits(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bobLink, err := server.database.CreateShortLink(ctx, bob.ID, shortlink.Link{
		Slug: "bob-link", Mode: shortlink.ModeRedirect,
		Destinations: []shortlink.Destination{{URL: "https://bob.example"}},
	}, shortlink.DefaultLimits(), time.Now().UTC())
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

	crossOwnerValues := directShortLinkValues(bobSession.CSRFToken, "", "https://changed.example")
	crossOwnerValues.Set("link_id", aliceLink.ID)
	crossOwnerUpdate := request(http.MethodPost, "http://admin.example.test/links/update", crossOwnerValues)
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Owner <strong>bob</strong>") || !strings.Contains(w.Body.String(), "/alice-link") {
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

	bobDashboard = request(http.MethodGet, "http://admin.example.test/", nil)
	bobDashboard.AddCookie(bobCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, bobDashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "alice</strong> disabled /bob-link") {
		t.Fatalf("cross-owner audit dashboard = (%d, %q)", w.Code, w.Body.String())
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
