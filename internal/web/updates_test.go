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
	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/store"
	"github.com/wispdeck/wispdeck/internal/updater"
)

type webUpdateClient struct {
	release updater.Release
}

func (c webUpdateClient) Check(context.Context) (updater.Release, bool, error) {
	return c.release, true, nil
}

func (c webUpdateClient) Stage(context.Context, updater.Release, string) (string, error) {
	return "/tmp/staged-wispdeck", nil
}

func TestSuperuserUpdateUIAndPolicy(t *testing.T) {
	release := updater.Release{
		Version: "v1.1.0", PublishedAt: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC),
		Notes: "A signed stable release.",
	}
	server := newTestServerWithUpdates(t, false, func(database *store.SQLite) *updater.Manager {
		manager, err := updater.NewManager(context.Background(), updater.ManagerConfig{
			Client: webUpdateClient{release: release}, Repository: database,
			Current: buildinfo.Info{Version: "v1.0.0"}, StagingDir: t.TempDir(),
			RequestApply: func(updater.ApplyRequest) error { return nil },
			InitialDelay: time.Hour, CheckInterval: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	})
	server.updates.Start(context.Background())
	t.Cleanup(server.updates.Close)
	if !server.updates.QueueCheck(updater.Actor{}) {
		t.Fatal("failed to queue update check")
	}
	deadline := time.Now().Add(time.Second)
	for !server.updates.Snapshot().Available && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.updates.Snapshot().Available {
		t.Fatal("update never became available")
	}

	cookie, session := passwordOnlyLogin(t, server, "alice", "correct horse battery staple")
	get := request(http.MethodGet, "http://admin.example.test/settings/updates", nil)
	get.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "v1.1.0") ||
		!strings.Contains(w.Body.String(), "A signed stable release") {
		t.Fatalf("updates page = (%d, %q)", w.Code, w.Body.String())
	}

	dashboard := request(http.MethodGet, "http://admin.example.test/", nil)
	dashboard.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, dashboard)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Wispdeck v1.1.0 is available") {
		t.Fatalf("dashboard update banner = (%d, %q)", w.Code, w.Body.String())
	}

	change := request(http.MethodPost, "http://admin.example.test/settings/updates/mode", url.Values{
		"csrf_token": {session.CSRFToken}, "mode": {string(updater.ModeDisabled)},
	})
	change.Header.Set("Origin", "http://admin.example.test")
	change.AddCookie(cookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, change)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("change update mode = (%d, %q)", w.Code, w.Body.String())
	}
	settings, err := server.database.UpdateSettings(context.Background())
	if err != nil || settings.Mode != updater.ModeDisabled {
		t.Fatalf("stored update settings = (%+v, %v)", settings, err)
	}

	passwords, err := auth.NewPasswordManager(server.keys)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := passwords.Hash("another correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.database.CreateManagedUser(
		context.Background(), "bob", hash, auth.RoleUser, auth.UserActive, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	bobCookie, _ := passwordOnlyLogin(t, server, "bob", "another correct horse battery staple")
	forbidden := request(http.MethodGet, "http://admin.example.test/settings/updates", nil)
	forbidden.AddCookie(bobCookie)
	w = httptest.NewRecorder()
	server.handler.ServeHTTP(w, forbidden)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ordinary user update page status = %d", w.Code)
	}
}
