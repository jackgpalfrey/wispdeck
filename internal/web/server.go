// Package web implements Wispdeck's trusted application HTTP boundary.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image/png"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/limit"
	"github.com/wispdeck/wispdeck/internal/shortlink"
)

const productionCookieName = "__Host-wispdeck_session"

const (
	productionLoginCookieName          = "__Host-wispdeck_login"
	productionCeremonyCookieName       = "__Host-wispdeck_ceremony"
	productionTOTPEnrollmentCookieName = "__Host-wispdeck_totp_enrollment"
)

type Config struct {
	AppOrigin         *url.URL
	Development       bool
	Logger            *slog.Logger
	PasswordChecker   auth.PasswordChecker
	TrustedProxyCIDRs []string
}

type Server struct {
	config                   Config
	auth                     *auth.Service
	passkeys                 *auth.PasskeyService
	totp                     *auth.TOTPService
	links                    *shortlink.Service
	passwordChecker          auth.PasswordChecker
	limiter                  *limit.LoginLimiter
	templates                *template.Template
	handler                  http.Handler
	cookieName               string
	loginCookieName          string
	ceremonyCookieName       string
	totpEnrollmentCookieName string
	trustedProxies           []*net.IPNet
}

type sessionContextKey struct{}

//go:embed templates/*.html assets/*
var files embed.FS

func New(
	config Config,
	authService *auth.Service,
	passkeyService *auth.PasskeyService,
	totpService *auth.TOTPService,
	shortLinkService *shortlink.Service,
) (*Server, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if authService == nil || passkeyService == nil || totpService == nil || shortLinkService == nil {
		return nil, errors.New("authentication, passkey, TOTP, and short-link services are required")
	}
	if config.PasswordChecker == nil {
		return nil, errors.New("password checker is required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	templates, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	trustedProxies, err := parseTrustedProxies(config.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	s := &Server{
		config:                   config,
		auth:                     authService,
		passkeys:                 passkeyService,
		totp:                     totpService,
		links:                    shortLinkService,
		passwordChecker:          config.PasswordChecker,
		limiter:                  limit.NewLoginLimiter(),
		templates:                templates,
		cookieName:               productionCookieName,
		loginCookieName:          productionLoginCookieName,
		ceremonyCookieName:       productionCeremonyCookieName,
		totpEnrollmentCookieName: productionTOTPEnrollmentCookieName,
		trustedProxies:           trustedProxies,
	}
	if config.Development {
		s.cookieName = "wispdeck_session"
		s.loginCookieName = "wispdeck_login"
		s.ceremonyCookieName = "wispdeck_ceremony"
		s.totpEnrollmentCookieName = "wispdeck_totp_enrollment"
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func validateConfig(config Config) error {
	if config.AppOrigin == nil {
		return errors.New("application origin is required")
	}
	u := config.AppOrigin
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("application origin must contain only a scheme and host")
	}
	if u.Scheme != "https" && !(config.Development && u.Scheme == "http") {
		return errors.New("application origin must use HTTPS outside development mode")
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", s.assets())
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /setup", s.userSetupPage)
	mux.HandleFunc("POST /setup", s.completeUserSetup)
	mux.HandleFunc("GET /login/passkey", s.passkeyLoginPage)
	mux.HandleFunc("POST /login/recovery", s.recoveryLogin)
	mux.HandleFunc("POST /login/totp", s.totpLogin)
	mux.HandleFunc("POST /api/auth/passkey/login/begin", s.beginPasskeyLogin)
	mux.HandleFunc("POST /api/auth/passkey/login/finish", s.finishPasskeyLogin)
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.dashboard)))
	mux.Handle("POST /logout", s.requireSession(http.HandlerFunc(s.logout)))
	mux.Handle("POST /links/create", s.requireSession(s.requireManagedSession(http.HandlerFunc(s.createShortLink))))
	mux.Handle("POST /links/target", s.requireSession(s.requireManagedSession(http.HandlerFunc(s.updateShortLinkTarget))))
	mux.Handle("POST /links/state", s.requireSession(s.requireManagedSession(http.HandlerFunc(s.setShortLinkState))))
	mux.Handle("POST /links/retire", s.requireSession(s.requireManagedSession(http.HandlerFunc(s.retireShortLink))))
	mux.Handle("GET /security/passkeys", s.requireSession(http.HandlerFunc(s.passkeySettings)))
	mux.Handle("POST /security/mfa/skip", s.requireSession(http.HandlerFunc(s.skipMFA)))
	mux.Handle("POST /api/auth/passkey/register/begin", s.requireSession(http.HandlerFunc(s.beginPasskeyRegistration)))
	mux.Handle("POST /api/auth/passkey/register/finish", s.requireSession(http.HandlerFunc(s.finishPasskeyRegistration)))
	mux.Handle("POST /security/passkeys/delete", s.requireSession(http.HandlerFunc(s.deletePasskey)))
	mux.Handle("POST /security/totp/setup", s.requireSession(http.HandlerFunc(s.beginTOTPEnrollment)))
	mux.Handle("GET /security/totp/qr", s.requireSession(http.HandlerFunc(s.totpEnrollmentQR)))
	mux.Handle("POST /security/totp/confirm", s.requireSession(http.HandlerFunc(s.confirmTOTPEnrollment)))
	mux.Handle("POST /security/totp/delete", s.requireSession(http.HandlerFunc(s.deleteTOTP)))
	mux.Handle("POST /security/recovery-codes/rotate", s.requireSession(http.HandlerFunc(s.rotateRecoveryCodes)))
	mux.Handle("POST /security/sessions/revoke-others", s.requireSession(http.HandlerFunc(s.revokeOtherSessions)))
	mux.Handle("POST /security/sessions/revoke", s.requireSession(http.HandlerFunc(s.revokeSession)))
	mux.Handle("GET /security/password", s.requireSession(http.HandlerFunc(s.passwordPage)))
	mux.Handle("POST /security/password", s.requireSession(http.HandlerFunc(s.changePassword)))
	mux.Handle("GET /settings/users", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.usersPage))))
	mux.Handle("POST /settings/users/create-setup", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.createUserWithSetup))))
	mux.Handle("POST /settings/users/create-password", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.createUserWithPassword))))
	mux.Handle("POST /settings/users/role", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.changeUserRole))))
	mux.Handle("POST /settings/users/status", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.changeUserStatus))))
	mux.Handle("POST /settings/users/setup-link", s.requireSession(s.requireSuperuser(http.HandlerFunc(s.replaceUserSetupLink))))
	mux.HandleFunc("GET /{slug}", s.resolveShortLink)
	return s.securityBoundary(mux)
}

func (s *Server) assets() http.Handler {
	assets, err := fs.Sub(files, "assets")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/assets/", http.FileServer(http.FS(assets)))
}

func (s *Server) securityBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if !s.config.Development {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !equalHost(r.Host, s.config.AppOrigin.Host) {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func equalHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if session, ok := s.sessionFromRequest(r); ok {
		if _, err := s.auth.Authenticate(r.Context(), session); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	s.render(w, http.StatusOK, "login.html", loginView{})
}

type loginView struct {
	Username string
	Error    string
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	username := auth.NormalizeUsername(r.PostForm.Get("username"))
	clientIP := s.clientAddress(r)
	usernameKey := fmt.Sprintf("%x", sha256.Sum256([]byte(username)))
	if !s.limiter.Allow(usernameKey, clientIP) {
		s.render(w, http.StatusTooManyRequests, "login.html", loginView{
			Username: username,
			Error:    "Unable to sign in. Try again later.",
		})
		return
	}
	user, err := s.auth.VerifyCredentials(r.Context(), username, r.PostForm.Get("password"), clientIP)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		s.render(w, http.StatusUnauthorized, "login.html", loginView{
			Username: username,
			Error:    "Invalid username or password.",
		})
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "login failed internally", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	token, session, factorRequired, err := s.passkeys.AfterPassword(
		r.Context(), user, clientIP, r.UserAgent(),
	)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "prepare second-factor login", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if factorRequired {
		s.setOpaqueCookie(w, s.loginCookieName, token)
		http.Redirect(w, r, "/login/passkey", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, token)
	if session.Assurance == auth.AssurancePassword {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if session.Assurance != auth.AssuranceMFA && session.Assurance != auth.AssurancePassword {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	s.renderDashboard(w, r, http.StatusOK, shortLinkForm{})
}

type shortLinkForm struct {
	Slug      string
	TargetURL string
	Error     string
}

type shortLinkView struct {
	ID            string
	OwnerUsername string
	Slug          string
	TargetURL     string
	PublicURL     string
	Enabled       bool
	VisitCount    int64
	CreatedAt     string
	LastVisitedAt string
}

type dashboardView struct {
	Username   string
	CSRFToken  string
	Assurance  auth.Assurance
	Role       auth.Role
	ShowOwners bool
	Create     shortLinkForm
	Links      []shortLinkView
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, status int, form shortLinkForm) {
	session := sessionFromContext(r.Context())
	links, err := s.links.List(r.Context(), shortLinkActor(session))
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list short links", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	views := make([]shortLinkView, 0, len(links))
	for _, link := range links {
		lastVisited := "Never"
		if !link.LastVisitedAt.IsZero() {
			lastVisited = link.LastVisitedAt.Format("2006-01-02 15:04 UTC")
		}
		views = append(views, shortLinkView{
			ID: link.ID, OwnerUsername: link.OwnerUsername, Slug: link.Slug,
			TargetURL: link.TargetURL, PublicURL: s.shortLinkURL(link.Slug),
			Enabled: link.Enabled, VisitCount: link.VisitCount,
			CreatedAt: link.CreatedAt.Format("2006-01-02 15:04 UTC"), LastVisitedAt: lastVisited,
		})
	}
	s.render(w, status, "dashboard.html", dashboardView{
		Username: session.User.Username, CSRFToken: session.CSRFToken,
		Assurance: session.Assurance, Role: session.User.Role,
		ShowOwners: session.User.Role == auth.RoleSuperuser,
		Create:     form, Links: views,
	})
}

func (s *Server) createShortLink(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validShortLinkForm(w, r)
	if !ok {
		return
	}
	form := shortLinkForm{Slug: r.PostForm.Get("slug"), TargetURL: r.PostForm.Get("target_url")}
	_, err := s.links.Create(r.Context(), shortLinkActor(session), form.Slug, form.TargetURL)
	if err != nil {
		if errors.Is(err, shortlink.ErrForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if message, known := shortLinkErrorMessage(err); known {
			form.Error = message
			status := http.StatusBadRequest
			if errors.Is(err, shortlink.ErrSlugUnavailable) {
				status = http.StatusConflict
			}
			s.renderDashboard(w, r, status, form)
			return
		}
		s.config.Logger.ErrorContext(r.Context(), "create short link", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) updateShortLinkTarget(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validShortLinkForm(w, r)
	if !ok {
		return
	}
	err := s.links.UpdateTarget(
		r.Context(), shortLinkActor(session), r.PostForm.Get("link_id"), r.PostForm.Get("target_url"),
	)
	if err != nil {
		s.renderShortLinkError(w, r, err, "Destination not changed")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setShortLinkState(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validShortLinkForm(w, r)
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
	if err := s.links.SetEnabled(r.Context(), shortLinkActor(session), r.PostForm.Get("link_id"), enabled); err != nil {
		s.renderShortLinkError(w, r, err, "Link state not changed")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) retireShortLink(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validShortLinkForm(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		http.Error(w, "retirement must be confirmed", http.StatusBadRequest)
		return
	}
	if err := s.links.Retire(r.Context(), shortLinkActor(session), r.PostForm.Get("link_id")); err != nil {
		s.renderShortLinkError(w, r, err, "Link not retired")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) validShortLinkForm(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return auth.Session{}, false
	}
	return session, true
}

func (s *Server) renderShortLinkError(w http.ResponseWriter, r *http.Request, err error, title string) {
	message, known := shortLinkErrorMessage(err)
	status := http.StatusBadRequest
	if errors.Is(err, shortlink.ErrNotFound) || errors.Is(err, shortlink.ErrForbidden) {
		message = "That short link does not exist or you are not allowed to manage it."
		known = true
		status = http.StatusNotFound
	}
	if !known {
		s.config.Logger.ErrorContext(r.Context(), "manage short link", "title", title, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.render(w, status, "shortlink_message.html", struct {
		Title   string
		Message string
	}{Title: title, Message: message})
}

func shortLinkErrorMessage(err error) (string, bool) {
	for _, known := range []error{
		shortlink.ErrInvalidSlug, shortlink.ErrReservedSlug, shortlink.ErrSlugUnavailable,
		shortlink.ErrInvalidTarget, shortlink.ErrTargetTooLong,
	} {
		if errors.Is(err, known) {
			return known.Error(), true
		}
	}
	return "", false
}

func (s *Server) resolveShortLink(w http.ResponseWriter, r *http.Request) {
	link, err := s.links.Resolve(r.Context(), r.PathValue("slug"))
	if errors.Is(err, shortlink.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "resolve short link", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, link.TargetURL, http.StatusFound)
}

func shortLinkActor(session auth.Session) shortlink.Actor {
	return shortlink.Actor{
		UserID: session.User.ID, Superuser: session.User.Role == auth.RoleSuperuser,
	}
}

func (s *Server) shortLinkURL(slug string) string {
	u := *s.config.AppOrigin
	u.Path = "/" + slug
	return u.String()
}

type userSetupView struct {
	Token    string
	Username string
	Error    string
}

func (s *Server) userSetupPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := r.URL.Query().Get("token")
	setup, err := s.auth.UserSetup(r.Context(), token)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidSetupToken) {
			s.config.Logger.ErrorContext(r.Context(), "load user setup", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.render(w, http.StatusGone, "message.html", struct {
			Title   string
			Message string
		}{"Setup link unavailable", "This account setup link is invalid or has expired."})
		return
	}
	s.render(w, http.StatusOK, "user_setup.html", userSetupView{
		Token: token, Username: setup.Username,
	})
}

func (s *Server) completeUserSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.validBrowserOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	setupKey := fmt.Sprintf("user-setup:%x", sha256.Sum256([]byte(token)))
	if !s.limiter.Allow(setupKey, s.clientAddress(r)) {
		s.render(w, http.StatusTooManyRequests, "message.html", struct {
			Title   string
			Message string
		}{"Too many setup attempts", "Wait a minute before trying this setup link again."})
		return
	}
	setup, err := s.auth.UserSetup(r.Context(), token)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidSetupToken) {
			s.config.Logger.ErrorContext(r.Context(), "load user setup", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.render(w, http.StatusGone, "message.html", struct {
			Title   string
			Message string
		}{"Setup link unavailable", "This account setup link is invalid or has expired."})
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm_password") {
		s.render(w, http.StatusBadRequest, "user_setup.html", userSetupView{
			Token: token, Username: setup.Username, Error: "Passwords do not match.",
		})
		return
	}
	_, err = s.auth.CompleteUserSetup(
		r.Context(), token, password, s.passwordChecker,
		auth.PasswordContext{
			Service: "wispdeck", Domain: s.config.AppOrigin.Hostname(),
		},
		s.clientAddress(r),
	)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidSetupToken) &&
			!errors.Is(err, auth.ErrCompromisedPassword) &&
			!errors.Is(err, auth.ErrPasswordCheckFailed) &&
			!errors.Is(err, auth.ErrPasswordTooShort) &&
			!errors.Is(err, auth.ErrPasswordTooLong) &&
			!errors.Is(err, auth.ErrPasswordInvalid) {
			s.config.Logger.ErrorContext(r.Context(), "complete user setup", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		message := passwordErrorMessage(err, "Password could not be set.")
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrInvalidSetupToken) {
			status = http.StatusGone
			message = "This account setup link is invalid or has expired."
		}
		s.render(w, status, "user_setup.html", userSetupView{
			Token: token, Username: setup.Username, Error: message,
		})
		return
	}
	s.render(w, http.StatusOK, "message.html", struct {
		Title   string
		Message string
	}{"Account ready", "Your password has been set. You can now sign in."})
}

type usersView struct {
	Users      []auth.UserSummary
	CurrentID  string
	CSRFToken  string
	SetupHours int
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	users, err := s.auth.ListUsers(r.Context(), session)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, http.StatusOK, "users.html", usersView{
		Users: users, CurrentID: session.User.ID, CSRFToken: session.CSRFToken,
		SetupHours: int(auth.SetupTokenLifetime.Hours()),
	})
}

func (s *Server) createUserWithSetup(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validPrivilegedForm(w, r)
	if !ok {
		return
	}
	user, token, err := s.auth.CreateUserWithSetup(
		r.Context(), session, r.PostForm.Get("username"), auth.Role(r.PostForm.Get("role")),
	)
	if err != nil {
		s.renderUserManagementError(w, r, err, "User not created")
		return
	}
	s.renderCreatedUser(w, user, s.setupURL(token))
}

func (s *Server) createUserWithPassword(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validPrivilegedForm(w, r)
	if !ok {
		return
	}
	password := r.PostForm.Get("password")
	if password != r.PostForm.Get("confirm_password") {
		s.renderManagementMessage(w, http.StatusBadRequest, "Passwords do not match", "Enter the same password twice.")
		return
	}
	user, err := s.auth.CreateUserWithPassword(
		r.Context(), session, r.PostForm.Get("username"), password,
		auth.Role(r.PostForm.Get("role")), s.passwordChecker,
		auth.PasswordContext{Service: "wispdeck", Domain: s.config.AppOrigin.Hostname()},
	)
	if err != nil {
		s.renderUserManagementError(w, r, err, "User not created")
		return
	}
	s.renderCreatedUser(w, user, "")
}

func (s *Server) changeUserRole(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validPrivilegedForm(w, r)
	if !ok {
		return
	}
	user, err := s.auth.SetUserRole(
		r.Context(), session, r.PostForm.Get("user_id"), auth.Role(r.PostForm.Get("role")),
	)
	if err != nil {
		s.renderUserManagementError(w, r, err, "Role not changed")
		return
	}
	if user.ID == session.User.ID && user.Role != auth.RoleSuperuser {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

func (s *Server) changeUserStatus(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validPrivilegedForm(w, r)
	if !ok {
		return
	}
	user, err := s.auth.SetUserStatus(
		r.Context(), session, r.PostForm.Get("user_id"), auth.UserStatus(r.PostForm.Get("status")),
	)
	if err != nil {
		s.renderUserManagementError(w, r, err, "Status not changed")
		return
	}
	if user.ID == session.User.ID && user.Status == auth.UserDisabled {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

func (s *Server) replaceUserSetupLink(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validPrivilegedForm(w, r)
	if !ok {
		return
	}
	token, _, err := s.auth.ReplaceUserSetupToken(r.Context(), session, r.PostForm.Get("user_id"))
	if err != nil {
		s.renderUserManagementError(w, r, err, "Setup link not replaced")
		return
	}
	s.render(w, http.StatusOK, "setup_link.html", struct {
		SetupURL string
	}{SetupURL: s.setupURL(token)})
}

func (s *Server) validPrivilegedForm(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return auth.Session{}, false
	}
	return session, true
}

func (s *Server) renderCreatedUser(w http.ResponseWriter, user auth.User, setupURL string) {
	s.render(w, http.StatusCreated, "user_created.html", struct {
		Username string
		Role     auth.Role
		SetupURL string
	}{Username: user.Username, Role: user.Role, SetupURL: setupURL})
}

func (s *Server) renderUserManagementError(w http.ResponseWriter, r *http.Request, err error, title string) {
	message := "The requested user change could not be completed."
	known := true
	if errors.Is(err, auth.ErrLastSuperuser) {
		message = "Wispdeck must retain at least one active superuser."
	} else if errors.Is(err, auth.ErrInvalidUserState) {
		message = "That user cannot make this transition."
	} else if errors.Is(err, auth.ErrUserExists) {
		message = "A user with that username already exists."
	} else if errors.Is(err, auth.ErrCompromisedPassword) {
		message = "Choose a password that has not appeared in common or breached-password lists."
	} else if errors.Is(err, auth.ErrPasswordCheckFailed) {
		message = "The breached-password check is temporarily unavailable. No user was created."
	} else if errors.Is(err, auth.ErrPasswordTooShort) || errors.Is(err, auth.ErrPasswordTooLong) {
		message = err.Error()
	} else if errors.Is(err, auth.ErrPasswordInvalid) || errors.Is(err, auth.ErrInvalidUsername) || errors.Is(err, auth.ErrInvalidRole) {
		message = err.Error()
	} else {
		known = false
	}
	if !known {
		s.config.Logger.ErrorContext(r.Context(), "manage user", "title", title, "error", err)
	}
	s.renderManagementMessage(w, http.StatusBadRequest, title, message)
}

func (s *Server) renderManagementMessage(w http.ResponseWriter, status int, title, message string) {
	s.render(w, status, "management_message.html", struct {
		Title   string
		Message string
	}{title, message})
}

func (s *Server) setupURL(token string) string {
	u := *s.config.AppOrigin
	u.Path = "/setup"
	u.RawQuery = url.Values{"token": {token}}.Encode()
	return u.String()
}

func (s *Server) skipMFA(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.passkeys.SkipMFA(r.Context(), session); err != nil {
		s.config.Logger.WarnContext(r.Context(), "reject MFA opt-out", "error", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) passkeyLoginPage(w http.ResponseWriter, r *http.Request) {
	loginToken, ok := s.opaqueCookie(r, s.loginCookieName)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderFactorLogin(w, r, http.StatusOK, loginToken, "")
}

type factorLoginView struct {
	Error      string
	HasPasskey bool
	HasTOTP    bool
}

func (s *Server) renderFactorLogin(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	loginToken, message string,
) {
	methods, err := s.passkeys.MethodsForLogin(r.Context(), loginToken)
	if err != nil {
		s.clearOpaqueCookie(w, s.loginCookieName)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, status, "passkey_login.html", factorLoginView{
		Error: message, HasPasskey: methods.Passkey, HasTOTP: methods.TOTP,
	})
}

func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	loginToken, ok := s.opaqueCookie(r, s.loginCookieName)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "login expired")
		return
	}
	options, ceremonyToken, err := s.passkeys.BeginLogin(r.Context(), loginToken)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "login expired")
		return
	}
	s.setOpaqueCookie(w, s.ceremonyCookieName, ceremonyToken)
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	loginToken, loginOK := s.opaqueCookie(r, s.loginCookieName)
	ceremonyToken, ceremonyOK := s.opaqueCookie(r, s.ceremonyCookieName)
	if !loginOK || !ceremonyOK {
		writeJSONError(w, http.StatusUnauthorized, "login expired")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	token, _, err := s.passkeys.FinishLogin(r.Context(), loginToken, ceremonyToken, r)
	if err != nil {
		s.config.Logger.WarnContext(r.Context(), "passkey login rejected", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	s.setSessionCookie(w, token)
	s.clearOpaqueCookie(w, s.loginCookieName)
	s.clearOpaqueCookie(w, s.ceremonyCookieName)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

func (s *Server) recoveryLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	loginToken, ok := s.opaqueCookie(r, s.loginCookieName)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	recoveryKey := fmt.Sprintf("recovery:%x", sha256.Sum256([]byte(loginToken)))
	if !s.limiter.Allow(recoveryKey, s.clientAddress(r)) {
		s.renderFactorLogin(w, r, http.StatusTooManyRequests, loginToken,
			"Too many recovery attempts. Try again later.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token, _, err := s.passkeys.Recover(r.Context(), loginToken, r.PostForm.Get("recovery_code"))
	if err != nil {
		s.renderFactorLogin(w, r, http.StatusUnauthorized, loginToken,
			"Invalid or already used recovery code.")
		return
	}
	s.setSessionCookie(w, token)
	s.clearOpaqueCookie(w, s.loginCookieName)
	s.clearOpaqueCookie(w, s.ceremonyCookieName)
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) totpLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validBrowserOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	loginToken, ok := s.opaqueCookie(r, s.loginCookieName)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	key := fmt.Sprintf("totp:%x", sha256.Sum256([]byte(loginToken)))
	if !s.limiter.Allow(key, s.clientAddress(r)) {
		s.renderFactorLogin(w, r, http.StatusTooManyRequests, loginToken,
			"Too many authenticator attempts. Try again later.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token, _, err := s.totp.VerifyLogin(r.Context(), loginToken, r.PostForm.Get("totp_code"))
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidTOTP) && !errors.Is(err, auth.ErrInvalidSession) {
			s.config.Logger.ErrorContext(r.Context(), "TOTP login failed internally", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.renderFactorLogin(w, r, http.StatusUnauthorized, loginToken,
			"Invalid or already used authenticator code.")
		return
	}
	s.setSessionCookie(w, token)
	s.clearOpaqueCookie(w, s.loginCookieName)
	s.clearOpaqueCookie(w, s.ceremonyCookieName)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) passkeySettings(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	records, err := s.passkeys.Passkeys(r.Context(), session.User.ID)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list passkeys", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	totpConfigured, err := s.totp.Configured(r.Context(), session.User.ID)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "inspect TOTP configuration", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	sessions, err := s.auth.Sessions(r.Context(), session)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list sessions", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	events, err := s.auth.Events(r.Context(), session, 25)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list authentication events", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.render(w, http.StatusOK, "passkeys.html", struct {
		Username       string
		Assurance      auth.Assurance
		CSRFToken      string
		Passkeys       []auth.PasskeyRecord
		TOTPConfigured bool
		Sessions       []auth.SessionSummary
		CurrentSession [32]byte
		Events         []auth.AuthEvent
	}{session.User.Username, session.Assurance, session.CSRFToken, records, totpConfigured, sessions, session.TokenHash, events})
}

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRFHeader(r, session.CSRFToken) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var input struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request")
		return
	}
	options, ceremonyToken, err := s.passkeys.BeginRegistration(r.Context(), session, input.Name)
	if errors.Is(err, auth.ErrRecentMFARequired) {
		writeJSONError(w, http.StatusForbidden, "sign in again before changing passkeys")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setOpaqueCookie(w, s.ceremonyCookieName, ceremonyToken)
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRFHeader(r, session.CSRFToken) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	ceremonyToken, ok := s.opaqueCookie(r, s.ceremonyCookieName)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "registration expired")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	codes, err := s.passkeys.FinishRegistration(r.Context(), session, ceremonyToken, r)
	if err != nil {
		s.config.Logger.WarnContext(r.Context(), "passkey registration rejected", "error", err)
		writeJSONError(w, http.StatusBadRequest, "passkey registration failed")
		return
	}
	s.clearOpaqueCookie(w, s.ceremonyCookieName)
	writeJSON(w, http.StatusOK, map[string]any{
		"redirect":       "/security/passkeys",
		"recovery_codes": codes,
	})
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.passkeys.DeletePasskey(r.Context(), session, r.PostForm.Get("name")); err != nil {
		message := "The passkey could not be deleted."
		if errors.Is(err, auth.ErrLastPasskey) {
			message = "Add another passkey or an authenticator app before deleting this one."
		} else if errors.Is(err, auth.ErrRecentMFARequired) {
			message = "Sign in again before deleting a passkey."
		}
		s.render(w, http.StatusBadRequest, "message.html", struct {
			Title   string
			Message string
		}{"Passkey not deleted", message})
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) beginTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token, secret, err := s.totp.BeginEnrollment(r.Context(), session)
	if err != nil {
		message := "Authenticator setup could not be started."
		if errors.Is(err, auth.ErrTOTPAlreadyConfigured) {
			message = "An authenticator app is already configured."
		} else if errors.Is(err, auth.ErrRecentMFARequired) {
			message = "Sign in again before changing authentication methods."
		}
		s.render(w, http.StatusBadRequest, "message.html", struct {
			Title   string
			Message string
		}{"Authenticator not added", message})
		return
	}
	s.setOpaqueCookie(w, s.totpEnrollmentCookieName, token)
	s.renderTOTPSetup(w, http.StatusOK, session, secret, "")
}

func (s *Server) totpEnrollmentQR(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	token, ok := s.opaqueCookie(r, s.totpEnrollmentCookieName)
	if !ok {
		http.Error(w, "enrollment expired", http.StatusGone)
		return
	}
	key, err := s.totp.EnrollmentKey(r.Context(), session, token)
	if err != nil {
		http.Error(w, "enrollment expired", http.StatusGone)
		return
	}
	image, err := key.Image(256, 256)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "generate TOTP QR code", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	if err := png.Encode(w, image); err != nil {
		s.config.Logger.WarnContext(r.Context(), "write TOTP QR code", "error", err)
	}
}

func (s *Server) confirmTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token, ok := s.opaqueCookie(r, s.totpEnrollmentCookieName)
	if !ok {
		http.Error(w, "enrollment expired", http.StatusGone)
		return
	}
	enrollmentKey := fmt.Sprintf("totp-enrollment:%x", sha256.Sum256([]byte(token)))
	if !s.limiter.Allow(enrollmentKey, s.clientAddress(r)) {
		key, keyErr := s.totp.EnrollmentKey(r.Context(), session, token)
		if keyErr != nil {
			http.Error(w, "enrollment expired", http.StatusGone)
			return
		}
		s.renderTOTPSetup(w, http.StatusTooManyRequests, session, key.Secret(),
			"Too many confirmation attempts. Start setup again later.")
		return
	}
	codes, err := s.totp.ConfirmEnrollment(r.Context(), session, token, r.PostForm.Get("totp_code"))
	if err != nil {
		key, keyErr := s.totp.EnrollmentKey(r.Context(), session, token)
		if keyErr != nil {
			s.clearOpaqueCookie(w, s.totpEnrollmentCookieName)
			http.Error(w, "enrollment expired", http.StatusGone)
			return
		}
		message := "Enter the current six-digit code from your authenticator app."
		if !errors.Is(err, auth.ErrInvalidTOTP) {
			s.config.Logger.ErrorContext(r.Context(), "confirm TOTP enrollment", "error", err)
			message = "Authenticator setup could not be completed. No changes were made."
		}
		s.renderTOTPSetup(w, http.StatusBadRequest, session, key.Secret(), message)
		return
	}
	s.clearOpaqueCookie(w, s.totpEnrollmentCookieName)
	if len(codes) > 0 {
		s.render(w, http.StatusOK, "recovery_codes.html", struct {
			Codes     []string
			CSRFToken string
		}{codes, session.CSRFToken})
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) renderTOTPSetup(
	w http.ResponseWriter,
	status int,
	session auth.Session,
	secret, message string,
) {
	s.render(w, status, "totp_setup.html", struct {
		Secret    string
		CSRFToken string
		Error     string
	}{secret, session.CSRFToken, message})
}

func (s *Server) deleteTOTP(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.totp.Delete(r.Context(), session); err != nil {
		message := "The authenticator app could not be removed."
		if errors.Is(err, auth.ErrLastFactor) {
			message = "Add a passkey before removing your authenticator app."
		} else if errors.Is(err, auth.ErrRecentMFARequired) {
			message = "Sign in again before removing your authenticator app."
		}
		s.render(w, http.StatusBadRequest, "message.html", struct {
			Title   string
			Message string
		}{"Authenticator not removed", message})
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) rotateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	codes, err := s.passkeys.RotateRecoveryCodes(r.Context(), session)
	if err != nil {
		s.render(w, http.StatusForbidden, "message.html", struct {
			Title   string
			Message string
		}{"Recovery codes not rotated", err.Error()})
		return
	}
	s.render(w, http.StatusOK, "recovery_codes.html", struct {
		Codes     []string
		CSRFToken string
	}{codes, session.CSRFToken})
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.auth.RevokeOtherSessions(r.Context(), session); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	encoded := r.PostForm.Get("session")
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != sha256.Size {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	var digest [32]byte
	copy(digest[:], raw)
	if err := s.auth.RevokeSession(r.Context(), session, digest); err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if digest == session.TokenHash {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if session.Assurance == auth.AssuranceRecovery {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, http.StatusOK, "password.html", struct {
		CSRFToken string
		Error     string
	}{CSRFToken: session.CSRFToken})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	current := r.PostForm.Get("current_password")
	newPassword := r.PostForm.Get("new_password")
	if newPassword != r.PostForm.Get("confirm_password") {
		s.render(w, http.StatusBadRequest, "password.html", struct {
			CSRFToken string
			Error     string
		}{session.CSRFToken, "New passwords do not match."})
		return
	}
	err := s.auth.ChangePassword(
		r.Context(), session, current, newPassword, s.passwordChecker,
		auth.PasswordContext{
			Username: session.User.Username,
			Service:  "wispdeck",
			Domain:   s.config.AppOrigin.Hostname(),
		},
	)
	if err != nil {
		message := passwordErrorMessage(err, "Password could not be changed.")
		if errors.Is(err, auth.ErrPasswordMismatch) {
			message = "Current password is incorrect."
		}
		s.render(w, http.StatusBadRequest, "password.html", struct {
			CSRFToken string
			Error     string
		}{session.CSRFToken, message})
		return
	}
	s.clearSessionCookie(w)
	s.render(w, http.StatusOK, "message.html", struct {
		Title   string
		Message string
	}{"Password changed", "Every session was revoked. Sign in again with your new password."})
}

func passwordErrorMessage(err error, fallback string) string {
	if errors.Is(err, auth.ErrCompromisedPassword) {
		return "Choose a password that has not appeared in common or breached-password lists."
	}
	if errors.Is(err, auth.ErrPasswordCheckFailed) {
		return "The breached-password check is temporarily unavailable. No change was made."
	}
	if errors.Is(err, auth.ErrPasswordTooShort) || errors.Is(err, auth.ErrPasswordTooLong) || errors.Is(err, auth.ErrPasswordInvalid) {
		return err.Error()
	}
	return fallback
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.auth.Logout(r.Context(), session, s.clientAddress(r)); err != nil {
		s.config.Logger.ErrorContext(r.Context(), "logout failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := s.sessionFromRequest(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		session, err := s.auth.Authenticate(r.Context(), token)
		if errors.Is(err, auth.ErrInvalidSession) {
			s.clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err != nil {
			s.config.Logger.ErrorContext(r.Context(), "session lookup failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireSuperuser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := sessionFromContext(r.Context())
		if session.User.Role != auth.RoleSuperuser ||
			(session.Assurance != auth.AssurancePassword && session.Assurance != auth.AssuranceMFA) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireManagedSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := sessionFromContext(r.Context())
		if session.Assurance != auth.AssurancePassword && session.Assurance != auth.AssuranceMFA {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sessionFromContext(ctx context.Context) auth.Session {
	session, ok := ctx.Value(sessionContextKey{}).(auth.Session)
	if !ok {
		panic("web: authenticated handler called without a session")
	}
	return session
}

func (s *Server) sessionFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || !auth.ValidToken(cookie.Value) {
		return "", false
	}
	return cookie.Value, true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	s.setOpaqueCookie(w, s.cookieName, token)
}

func (s *Server) setOpaqueCookie(w http.ResponseWriter, name, token string) {
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Secure:   !s.config.Development,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	s.clearOpaqueCookie(w, s.cookieName)
}

func (s *Server) clearOpaqueCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- Secure is disabled only in loopback-enforced development mode.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   !s.config.Development,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) opaqueCookie(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil || !auth.ValidToken(cookie.Value) {
		return "", false
	}
	return cookie.Value, true
}

func (s *Server) validBrowserOrigin(r *http.Request) bool {
	fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if fetchSite == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Some browsers omit Origin on same-origin HTML form submissions. The
		// Sec-Fetch-Site header is browser-controlled and cannot be supplied by
		// cross-origin JavaScript, so it is a safe fallback when no URL-bearing
		// header is available.
		if r.Referer() == "" {
			return fetchSite == "same-origin"
		}
		referer, err := url.Parse(r.Referer())
		if err != nil || referer.Scheme == "" || referer.Host == "" {
			return false
		}
		origin = referer.Scheme + "://" + referer.Host
	}
	want := s.config.AppOrigin.Scheme + "://" + s.config.AppOrigin.Host
	return subtle.ConstantTimeCompare([]byte(origin), []byte(want)) == 1
}

func validCSRF(w http.ResponseWriter, r *http.Request, expected string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		return false
	}
	actual := r.PostForm.Get("csrf_token")
	if !auth.ValidToken(actual) || !auth.ValidToken(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func validCSRFHeader(r *http.Request, expected string) bool {
	actual := r.Header.Get("X-CSRF-Token")
	if !auth.ValidToken(actual) || !auth.ValidToken(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func (s *Server) clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		remote := net.ParseIP(host)
		if remote == nil || !ipInNetworks(remote, s.trustedProxies) {
			return host
		}
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(forwarded) - 1; i >= 0; i-- {
			candidateText := strings.TrimSpace(forwarded[i])
			candidate := net.ParseIP(candidateText)
			if candidate == nil {
				return host
			}
			if !ipInNetworks(candidate, s.trustedProxies) {
				return candidate.String()
			}
		}
		return host
	}
	return r.RemoteAddr
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy CIDR %q: %w", value, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.config.Logger.Error("render template", "template", name, "error", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
