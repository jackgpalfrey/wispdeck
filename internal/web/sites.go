package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	hostedsite "github.com/wispdeck/wispdeck/internal/site"
)

const previewReturnLifetime = 10 * time.Minute

type siteReleaseView struct {
	ID          string
	Version     int
	FileCount   int
	TotalSize   string
	CreatedAt   string
	PublishedAt string
	Draft       bool
	Current     bool
}

type siteView struct {
	ID            string
	OwnerUsername string
	Name          string
	Title         string
	URL           string
	Enabled       bool
	HasDraft      bool
	HasPublished  bool
	Selected      bool
	Releases      []siteReleaseView
}

func siteActor(session auth.Session) hostedsite.Actor {
	return hostedsite.Actor{
		UserID: session.User.ID, Superuser: session.User.Role == auth.RoleSuperuser,
	}
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	created, err := s.sites.Create(
		r.Context(), siteActor(session), r.PostForm.Get("name"), r.PostForm.Get("title"),
	)
	if err != nil {
		s.renderSiteManagementError(w, r, err, "Site not created")
		return
	}
	http.Redirect(w, r, "/?site_created="+url.QueryEscape(created.Name)+"#sites", http.StatusSeeOther)
}

func (s *Server) uploadSite(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, hostedsite.MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		s.renderSiteManagementError(w, r, hostedsite.ErrInvalidBundle, "Draft not uploaded")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	session := sessionFromContext(r.Context())
	if !validParsedCSRF(r.PostForm.Get("csrf_token"), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	file, header, err := r.FormFile("bundle")
	if err != nil {
		s.renderSiteManagementError(w, r, hostedsite.ErrInvalidBundle, "Draft not uploaded")
		return
	}
	defer file.Close()
	if header.Size < 1 || header.Size > hostedsite.MaxUploadBytes {
		s.renderSiteManagementError(w, r, hostedsite.ErrInvalidBundle, "Draft not uploaded")
		return
	}
	readerAt, ok := file.(io.ReaderAt)
	if !ok {
		s.config.Logger.ErrorContext(r.Context(), "multipart site upload is not seekable")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	bundle, err := hostedsite.ReadZIP(readerAt, header.Size)
	if err == nil {
		_, err = s.sites.Upload(r.Context(), siteActor(session), r.PostForm.Get("site_id"), bundle)
	}
	if err != nil {
		s.renderSiteManagementError(w, r, err, "Draft not uploaded")
		return
	}
	http.Redirect(w, r, "/?site="+url.QueryEscape(r.PostForm.Get("site_name"))+"#sites", http.StatusSeeOther)
}

func (s *Server) publishSite(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	if err := s.sites.Publish(
		r.Context(), siteActor(session), r.PostForm.Get("site_id"), r.PostForm.Get("release_id"),
	); err != nil {
		s.renderSiteManagementError(w, r, err, "Release not published")
		return
	}
	http.Redirect(w, r, "/?site="+url.QueryEscape(r.PostForm.Get("site_name"))+"#sites", http.StatusSeeOther)
}

func (s *Server) setSiteState(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	var enabled bool
	switch r.PostForm.Get("enabled") {
	case "true":
		enabled = true
	case "false":
		enabled = false
	default:
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if err := s.sites.SetEnabled(r.Context(), siteActor(session), r.PostForm.Get("site_id"), enabled); err != nil {
		s.renderSiteManagementError(w, r, err, "Site state not changed")
		return
	}
	http.Redirect(w, r, "/?site="+url.QueryEscape(r.PostForm.Get("site_name"))+"#sites", http.StatusSeeOther)
}

func (s *Server) previewSite(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	s.redirectToSitePreview(w, r, session, r.PostForm.Get("site_name"))
}

func (s *Server) previewSiteEntry(w http.ResponseWriter, r *http.Request) {
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	token, ok := s.sessionFromRequest(r)
	if !ok {
		s.setPreviewReturnCookie(w, name)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, err := s.auth.Authenticate(r.Context(), token)
	if errors.Is(err, auth.ErrInvalidSession) {
		s.clearSessionCookie(w)
		s.setPreviewReturnCookie(w, name)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "authenticate site preview entry", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if session.Assurance != auth.AssuranceMFA && session.Assurance != auth.AssurancePassword {
		s.setPreviewReturnCookie(w, name)
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	s.clearPreviewReturnCookie(w)
	s.redirectToSitePreview(w, r, session, name)
}

func (s *Server) redirectToSitePreview(w http.ResponseWriter, r *http.Request, session auth.Session, name string) {
	grant, err := s.sites.GrantPreview(r.Context(), siteActor(session), name)
	if err != nil {
		s.renderSiteManagementError(w, r, err, "Draft preview unavailable")
		return
	}
	u := s.previewURL(grant.OriginLabel, "/_wispdeck/preview/accept")
	u.RawQuery = url.Values{"code": {grant.Code}}.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) validSiteForm(w http.ResponseWriter, r *http.Request, limit int64) (auth.Session, bool) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRFWithLimit(w, r, session.CSRFToken, limit) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return auth.Session{}, false
	}
	return session, true
}

func validParsedCSRF(actual, expected string) bool {
	if !auth.ValidToken(actual) || !auth.ValidToken(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func (s *Server) renderSiteManagementError(w http.ResponseWriter, r *http.Request, err error, title string) {
	status := http.StatusBadRequest
	message := "The requested site change could not be completed."
	switch {
	case errors.Is(err, hostedsite.ErrNotFound), errors.Is(err, hostedsite.ErrForbidden):
		status = http.StatusNotFound
		message = "That site does not exist or you are not allowed to manage it."
	case errors.Is(err, hostedsite.ErrNameUnavailable):
		status = http.StatusConflict
		message = err.Error()
	case errors.Is(err, hostedsite.ErrInvalidName), errors.Is(err, hostedsite.ErrInvalidTitle),
		errors.Is(err, shortlink.ErrReservedSlug), errors.Is(err, hostedsite.ErrInvalidBundle),
		errors.Is(err, hostedsite.ErrBundleTooLarge), errors.Is(err, hostedsite.ErrTooManyFiles),
		errors.Is(err, hostedsite.ErrInvalidFile), errors.Is(err, hostedsite.ErrNoDraft),
		errors.Is(err, hostedsite.ErrInvalidPreview):
		message = err.Error()
	default:
		s.config.Logger.ErrorContext(r.Context(), "manage hosted site", "title", title, "error", err)
		status = http.StatusInternalServerError
		message = "The site change failed internally. No partial release was published."
	}
	s.renderManagementMessage(w, status, title, message)
}

func (s *Server) hostBoundary(application http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if equalHost(r.Host, s.config.AppOrigin.Host) {
			application.ServeHTTP(w, r)
			return
		}
		if originLabel, ok := s.previewOriginFromHost(r.Host); ok {
			s.siteSecurityHeaders(w)
			s.serveSitePreviewHost(w, r, originLabel)
			return
		}
		name, ok := s.siteNameFromHost(r.Host)
		if !ok {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		s.siteSecurityHeaders(w)
		s.serveSiteHost(w, r, name)
	})
}

func (s *Server) siteSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !s.config.Development {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func (s *Server) siteNameFromHost(value string) (string, bool) {
	name, ok := s.hostLabel(value, s.config.SiteDomain)
	if !ok {
		return "", false
	}
	normalized, err := hostedsite.NormalizeName(name)
	return normalized, err == nil && normalized == name
}

func (s *Server) previewOriginFromHost(value string) (string, bool) {
	label, ok := s.hostLabel(value, s.config.PreviewDomain)
	if !ok || len(label) != 33 || label[0] != 'p' {
		return "", false
	}
	for _, char := range []byte(label[1:]) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return "", false
		}
	}
	return label, true
}

func (s *Server) hostLabel(value, suffixDomain string) (string, bool) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Contains(value, ":") {
			return "", false
		}
		host = value
	}
	if port != s.config.AppOrigin.Port() {
		return "", false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix := "." + suffixDomain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}

func (s *Server) siteURL(name, filePath string) *url.URL {
	u := *s.config.AppOrigin
	host := name + "." + s.config.SiteDomain
	if port := s.config.AppOrigin.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	u.Path = filePath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

func (s *Server) previewURL(originLabel, filePath string) *url.URL {
	u := *s.config.AppOrigin
	host := originLabel + "." + s.config.PreviewDomain
	if port := s.config.AppOrigin.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	u.Path = filePath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

func (s *Server) resolvePublicName(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("slug")
	value, err := s.sites.SiteByName(r.Context(), name)
	if err == nil {
		if !value.Enabled {
			http.NotFound(w, r)
			return
		}
		u := s.siteURL(value.Name, "/")
		u.RawQuery = r.URL.RawQuery
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return
	}
	if !errors.Is(err, hostedsite.ErrNotFound) {
		s.config.Logger.ErrorContext(r.Context(), "resolve public site alias", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.resolveShortLink(w, r)
}

func (s *Server) redirectSiteAlias(w http.ResponseWriter, r *http.Request) {
	value, err := s.sites.SiteByName(r.Context(), r.PathValue("slug"))
	if errors.Is(err, hostedsite.ErrNotFound) || (err == nil && !value.Enabled) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "resolve nested public site alias", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	u := s.siteURL(value.Name, "/"+r.PathValue("rest"))
	u.RawQuery = r.URL.RawQuery
	http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
}

func (s *Server) serveSiteHost(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(strings.ToLower(r.URL.Path), "/_wispdeck/") {
		http.NotFound(w, r)
		return
	}
	value, err := s.sites.SiteByName(r.Context(), name)
	if errors.Is(err, hostedsite.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "resolve hosted site", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !value.Enabled {
		http.NotFound(w, r)
		return
	}
	releaseID := value.PublishedReleaseID
	if releaseID == "" {
		if value.DraftReleaseID != "" {
			s.renderDraftGate(w, r, value)
			return
		}
		s.renderEmptySite(w, r, value)
		return
	}
	s.serveSiteFile(w, r, value, releaseID, "current", false)
}

func (s *Server) serveSitePreviewHost(w http.ResponseWriter, r *http.Request, originLabel string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case r.URL.Path == "/_wispdeck/preview/accept":
		s.acceptSitePreview(w, r, originLabel)
		return
	case strings.HasPrefix(r.URL.Path, "/_wispdeck/preview/view/"):
		s.selectSitePreviewView(w, r, originLabel)
		return
	case strings.HasPrefix(strings.ToLower(r.URL.Path), "/_wispdeck/"):
		http.NotFound(w, r)
		return
	}

	preview, ok := s.sitePreview(r, originLabel)
	if !ok {
		http.NotFound(w, r)
		return
	}
	view := s.previewView(r)
	releaseID := preview.DraftReleaseID
	if view == "current" && preview.PublishedReleaseID != "" {
		releaseID = preview.PublishedReleaseID
	} else {
		view = "draft"
	}
	s.serveSiteFile(w, r, preview.Site, releaseID, view, true)
}

func (s *Server) serveSiteFile(
	w http.ResponseWriter,
	r *http.Request,
	value hostedsite.Site,
	releaseID, view string,
	hasPreview bool,
) {
	filePath, ok := hostedFilePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	file, err := s.sites.File(r.Context(), releaseID, filePath)
	if errors.Is(err, hostedsite.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "load hosted site file", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	body := file.Body
	digest := file.Digest
	if hasPreview && strings.HasPrefix(file.ContentType, "text/html") {
		body = s.addPreviewToolbar(body, value, view, r.URL.RequestURI())
		digest = sha256.Sum256(body)
	}
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	if hasPreview {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Vary", "Cookie")
		w.Header().Set("X-Frame-Options", "DENY")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", file.ContentType)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	http.ServeContent(w, r, file.Path, time.Time{}, bytes.NewReader(body))
}

func hostedFilePath(requestPath string) (string, bool) {
	if requestPath == "" || requestPath[0] != '/' || strings.Contains(requestPath, "\\") || strings.ContainsRune(requestPath, 0) {
		return "", false
	}
	value := strings.TrimPrefix(requestPath, "/")
	if value == "" || strings.HasSuffix(value, "/") {
		value += "index.html"
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || len(clean) > 4096 {
		return "", false
	}
	return clean, true
}

func (s *Server) renderDraftGate(w http.ResponseWriter, r *http.Request, value hostedsite.Site) {
	entry := *s.config.AppOrigin
	entry.Path = "/sites/" + value.Name + "/preview-entry"
	s.renderSiteState(w, http.StatusUnauthorized, siteStateView{
		Draft: true, Name: value.Name, ActionURL: entry.String(),
	})
}

func (s *Server) renderEmptySite(w http.ResponseWriter, _ *http.Request, value hostedsite.Site) {
	manage := *s.config.AppOrigin
	manage.Path = "/"
	manage.RawQuery = url.Values{"site": {value.Name}}.Encode()
	manage.Fragment = "sites"
	s.renderSiteState(w, http.StatusOK, siteStateView{
		Name: value.Name, ActionURL: manage.String(),
	})
}

type siteStateView struct {
	Draft     bool
	Name      string
	ActionURL string
}

func (s *Server) renderSiteState(w http.ResponseWriter, status int, view siteStateView) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	s.render(w, status, "site_state.html", view)
}

func (s *Server) acceptSitePreview(w http.ResponseWriter, r *http.Request, originLabel string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	token, _, err := s.sites.ExchangePreview(r.Context(), originLabel, r.URL.Query().Get("code"))
	if err != nil {
		s.clearSitePreviewCookie(w)
		http.NotFound(w, r)
		return
	}
	s.setOpaqueCookie(w, s.previewCookieName, token)
	s.setPreviewViewCookie(w, "draft")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) selectSitePreviewView(w http.ResponseWriter, r *http.Request, originLabel string) {
	w.Header().Set("Cache-Control", "no-store")
	preview, ok := s.sitePreview(r, originLabel)
	if !ok {
		http.NotFound(w, r)
		return
	}
	view := strings.TrimPrefix(r.URL.Path, "/_wispdeck/preview/view/")
	if view != "draft" && (view != "current" || preview.PublishedReleaseID == "") {
		http.NotFound(w, r)
		return
	}
	s.setPreviewViewCookie(w, view)
	returnTo := r.URL.Query().Get("return")
	if !safeSiteReturn(returnTo) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func safeSiteReturn(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/") &&
		!strings.HasPrefix(strings.ToLower(parsed.Path), "/_wispdeck/")
}

func (s *Server) sitePreview(r *http.Request, originLabel string) (hostedsite.Preview, bool) {
	token, ok := s.opaqueCookie(r, s.previewCookieName)
	if !ok {
		return hostedsite.Preview{}, false
	}
	preview, err := s.sites.Preview(r.Context(), originLabel, token)
	return preview, err == nil
}

func (s *Server) previewView(r *http.Request) string {
	cookie, err := r.Cookie(s.previewViewCookieName)
	if err == nil && cookie.Value == "current" {
		return "current"
	}
	return "draft"
}

func (s *Server) setPreviewViewCookie(w http.ResponseWriter, value string) {
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name: s.previewViewCookieName, Value: value, Path: "/",
		MaxAge: int(hostedsite.PreviewLifetime.Seconds()), Secure: !s.config.Development,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSitePreviewCookie(w http.ResponseWriter) {
	s.clearOpaqueCookie(w, s.previewCookieName)
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name: s.previewViewCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: !s.config.Development, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) addPreviewToolbar(body []byte, value hostedsite.Site, view, returnTo string) []byte {
	current := ""
	if value.PublishedReleaseID != "" {
		currentURL := "/_wispdeck/preview/view/current?" + url.Values{"return": {returnTo}}.Encode()
		current = `<a href="` + html.EscapeString(currentURL) + `">Current</a>`
		if view == "current" {
			current = `<strong>Current</strong>`
		}
	}
	draftURL := "/_wispdeck/preview/view/draft?" + url.Values{"return": {returnTo}}.Encode()
	draft := `<a href="` + html.EscapeString(draftURL) + `">Draft</a>`
	if view == "draft" {
		draft = `<strong>Draft</strong>`
	}
	manage := *s.config.AppOrigin
	manage.Path = "/"
	manage.RawQuery = url.Values{"site": {value.Name}}.Encode()
	manage.Fragment = "sites"
	bar := `<style id="wispdeck-preview-style">#wispdeck-preview-bar{position:fixed;z-index:2147483647;top:0;left:0;right:0;min-height:44px;box-sizing:border-box;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:8px 14px;background:#171820;color:#f7f7fb;border-bottom:1px solid #363845;font:600 14px/1.3 system-ui,sans-serif}#wispdeck-preview-bar div{display:flex;align-items:center;gap:12px}#wispdeck-preview-bar a{color:#b5aaff;text-decoration:none}#wispdeck-preview-bar strong{color:#fff}#wispdeck-preview-bar .wispdeck-draft{padding:3px 7px;border-radius:999px;background:#443b78;color:#ddd7ff;font-size:11px;text-transform:uppercase;letter-spacing:.06em}</style><div id="wispdeck-preview-bar"><div><span class="wispdeck-draft">Draft preview</span><span>` + html.EscapeString(value.Name) + `</span></div><div>` + current + draft + `<a href="` + html.EscapeString(manage.String()) + `">Publish…</a></div></div>`
	lower := bytes.ToLower(body)
	if start := bytes.Index(lower, []byte("<body")); start >= 0 {
		if end := bytes.IndexByte(body[start:], '>'); end >= 0 {
			position := start + end + 1
			result := make([]byte, 0, len(body)+len(bar))
			result = append(result, body[:position]...)
			result = append(result, bar...)
			result = append(result, body[position:]...)
			return result
		}
	}
	return append([]byte(bar), body...)
}

func (s *Server) setPreviewReturnCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name: s.previewReturnCookieName, Value: name, Path: "/",
		MaxAge: int(previewReturnLifetime.Seconds()), Secure: !s.config.Development,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearPreviewReturnCookie(w http.ResponseWriter) {
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name: s.previewReturnCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: !s.config.Development, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) afterLoginPath(w http.ResponseWriter, r *http.Request, fallback string) string {
	cookie, err := r.Cookie(s.previewReturnCookieName)
	if err != nil {
		return fallback
	}
	name, err := hostedsite.NormalizeName(cookie.Value)
	s.clearPreviewReturnCookie(w)
	if err != nil {
		return fallback
	}
	return "/sites/" + name + "/preview-entry"
}

func formatBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	if value < unit*unit {
		return fmt.Sprintf("%.1f KiB", float64(value)/unit)
	}
	return fmt.Sprintf("%.1f MiB", float64(value)/(unit*unit))
}

func siteViews(values []hostedsite.Site, s *Server, selected string) []siteView {
	views := make([]siteView, 0, len(values))
	for _, value := range values {
		view := siteView{
			ID: value.ID, OwnerUsername: value.OwnerUsername, Name: value.Name,
			Title: value.Title, URL: s.siteURL(value.Name, "/").String(), Enabled: value.Enabled,
			HasDraft: value.DraftReleaseID != "", HasPublished: value.PublishedReleaseID != "",
			Selected: value.Name == selected,
		}
		for _, release := range value.Releases {
			publishedAt := "Never"
			if !release.PublishedAt.IsZero() {
				publishedAt = release.PublishedAt.Format("2006-01-02 15:04 UTC")
			}
			view.Releases = append(view.Releases, siteReleaseView{
				ID: release.ID, Version: release.Version, FileCount: release.FileCount,
				TotalSize: formatBytes(release.TotalBytes),
				CreatedAt: release.CreatedAt.Format("2006-01-02 15:04 UTC"), PublishedAt: publishedAt,
				Draft: release.ID == value.DraftReleaseID, Current: release.ID == value.PublishedReleaseID,
			})
		}
		views = append(views, view)
	}
	return views
}
