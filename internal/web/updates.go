package web

import (
	"net/http"
	"net/url"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/updater"
)

type updatesView struct {
	Shell          shellView
	CSRFToken      string
	Configured     bool
	CurrentVersion string
	Mode           updater.Mode
	Available      bool
	LatestVersion  string
	PublishedAt    string
	Notes          string
	SkippedVersion string
	Checking       bool
	Applying       bool
	LastChecked    string
	LastError      string
	Message        string
}

func (s *Server) updatesPage(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		http.NotFound(w, r)
		return
	}
	session := sessionFromContext(r.Context())
	snapshot := s.updates.Snapshot()
	lastChecked := "Never"
	if !snapshot.LastCheckedAt.IsZero() {
		lastChecked = snapshot.LastCheckedAt.Format("2006-01-02 15:04 UTC")
	}
	publishedAt := ""
	if !snapshot.Latest.PublishedAt.IsZero() {
		publishedAt = snapshot.Latest.PublishedAt.Format("2006-01-02")
	}
	messages := map[string]string{
		"checking":  "The release check has been queued.",
		"policy":    "Update policy saved.",
		"skipped":   "That release will no longer be offered.",
		"unskipped": "The skipped release can be offered again.",
		"applying":  "The update is being downloaded and verified. Wispdeck will restart when it is ready.",
	}
	s.render(w, http.StatusOK, "updates.html", updatesView{
		Shell: s.shell(session, "settings"), CSRFToken: session.CSRFToken,
		Configured: snapshot.Configured, CurrentVersion: snapshot.Current.Version,
		Mode: snapshot.Mode, Available: snapshot.Available,
		LatestVersion: snapshot.Latest.Version, PublishedAt: publishedAt,
		Notes: snapshot.Latest.Notes, SkippedVersion: snapshot.SkippedVersion,
		Checking: snapshot.Checking, Applying: snapshot.Applying,
		LastChecked: lastChecked, LastError: snapshot.LastError,
		Message: messages[r.URL.Query().Get("message")],
	})
}

func (s *Server) changeUpdateMode(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validUpdateForm(w, r)
	if !ok {
		return
	}
	if err := s.updates.SetMode(r.Context(), updateActor(session, s.clientAddress(r)), updater.Mode(r.PostForm.Get("mode"))); err != nil {
		s.config.Logger.ErrorContext(r.Context(), "change update mode", "error", err)
		http.Error(w, "update policy could not be changed", http.StatusBadRequest)
		return
	}
	s.redirectUpdates(w, r, "policy")
}

func (s *Server) checkForUpdates(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validUpdateForm(w, r)
	if !ok {
		return
	}
	if !s.updates.Snapshot().Configured {
		http.Error(w, "release updates are not configured", http.StatusConflict)
		return
	}
	if !s.updates.QueueCheck(updateActor(session, s.clientAddress(r))) {
		http.Error(w, "an update operation is already queued", http.StatusConflict)
		return
	}
	s.redirectUpdates(w, r, "checking")
}

func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validUpdateForm(w, r)
	if !ok {
		return
	}
	if !s.updates.Snapshot().Available {
		http.Error(w, "there is no available update", http.StatusConflict)
		return
	}
	if !s.updates.QueueApply(updateActor(session, s.clientAddress(r))) {
		http.Error(w, "an update operation is already queued", http.StatusConflict)
		return
	}
	s.redirectUpdates(w, r, "applying")
}

func (s *Server) skipUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validUpdateForm(w, r)
	if !ok {
		return
	}
	if err := s.updates.SkipLatest(r.Context(), updateActor(session, s.clientAddress(r))); err != nil {
		http.Error(w, "release could not be skipped", http.StatusConflict)
		return
	}
	s.redirectUpdates(w, r, "skipped")
}

func (s *Server) unskipUpdate(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validUpdateForm(w, r)
	if !ok {
		return
	}
	if err := s.updates.ClearSkipped(r.Context(), updateActor(session, s.clientAddress(r))); err != nil {
		s.config.Logger.ErrorContext(r.Context(), "clear skipped update", "error", err)
		http.Error(w, "skipped release could not be cleared", http.StatusInternalServerError)
		return
	}
	s.redirectUpdates(w, r, "unskipped")
}

func (s *Server) validUpdateForm(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	if s.updates == nil {
		http.NotFound(w, r)
		return auth.Session{}, false
	}
	return s.validPrivilegedForm(w, r)
}

func updateActor(session auth.Session, clientIP string) updater.Actor {
	return updater.Actor{
		UserID: session.User.ID, Username: session.User.Username, ClientIP: clientIP,
	}
}

func (s *Server) redirectUpdates(w http.ResponseWriter, r *http.Request, message string) {
	target := &url.URL{Path: "/settings/updates", RawQuery: url.Values{"message": {message}}.Encode()}
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}
