// Package web implements Wispdeck's administrative HTTP boundary.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
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
)

const productionCookieName = "__Host-wispdeck_session"

const (
	productionLoginCookieName          = "__Host-wispdeck_login"
	productionCeremonyCookieName       = "__Host-wispdeck_ceremony"
	productionTOTPEnrollmentCookieName = "__Host-wispdeck_totp_enrollment"
)

type Config struct {
	AdminOrigin       *url.URL
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
) (*Server, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if authService == nil || passkeyService == nil || totpService == nil {
		return nil, errors.New("authentication, passkey, and TOTP services are required")
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
	if config.AdminOrigin == nil {
		return errors.New("admin origin is required")
	}
	u := config.AdminOrigin
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("admin origin must contain only a scheme and host")
	}
	if u.Scheme != "https" && !(config.Development && u.Scheme == "http") {
		return errors.New("admin origin must use HTTPS outside development mode")
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", s.assets())
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /login/passkey", s.passkeyLoginPage)
	mux.HandleFunc("POST /login/recovery", s.recoveryLogin)
	mux.HandleFunc("POST /login/totp", s.totpLogin)
	mux.HandleFunc("POST /api/auth/passkey/login/begin", s.beginPasskeyLogin)
	mux.HandleFunc("POST /api/auth/passkey/login/finish", s.finishPasskeyLogin)
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.dashboard)))
	mux.Handle("POST /logout", s.requireSession(http.HandlerFunc(s.logout)))
	mux.Handle("GET /security/passkeys", s.requireSession(http.HandlerFunc(s.passkeySettings)))
	mux.Handle("POST /api/auth/passkey/register/begin", s.requireSession(http.HandlerFunc(s.beginPasskeyRegistration)))
	mux.Handle("POST /api/auth/passkey/register/finish", s.requireSession(http.HandlerFunc(s.finishPasskeyRegistration)))
	mux.Handle("POST /security/passkeys/delete", s.requireSession(http.HandlerFunc(s.deletePasskey)))
	mux.Handle("POST /security/totp/setup", s.requireSession(http.HandlerFunc(s.beginTOTPEnrollment)))
	mux.Handle("GET /security/totp/qr", s.requireSession(http.HandlerFunc(s.totpEnrollmentQR)))
	mux.Handle("POST /security/totp/confirm", s.requireSession(http.HandlerFunc(s.confirmTOTPEnrollment)))
	mux.Handle("POST /security/totp/delete", s.requireSession(http.HandlerFunc(s.deleteTOTP)))
	mux.Handle("POST /security/recovery-codes/rotate", s.requireSession(http.HandlerFunc(s.rotateRecoveryCodes)))
	mux.Handle("POST /security/sessions/revoke-others", s.requireSession(http.HandlerFunc(s.revokeOtherSessions)))
	mux.Handle("GET /security/password", s.requireSession(http.HandlerFunc(s.passwordPage)))
	mux.Handle("POST /security/password", s.requireSession(http.HandlerFunc(s.changePassword)))
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
		if !equalHost(r.Host, s.config.AdminOrigin.Host) {
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
	token, _, passkeyRequired, err := s.passkeys.AfterPassword(
		r.Context(), user, clientIP, r.UserAgent(),
	)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "prepare second-factor login", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if passkeyRequired {
		s.setOpaqueCookie(w, s.loginCookieName, token)
		http.Redirect(w, r, "/login/passkey", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, token)
	http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if session.Assurance != auth.AssuranceMFA {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "dashboard.html", struct {
		Username  string
		CSRFToken string
	}{Username: session.User.Username, CSRFToken: session.CSRFToken})
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

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if session.Assurance != auth.AssuranceMFA {
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
			Domain:   s.config.AdminOrigin.Hostname(),
		},
	)
	if err != nil {
		message := "Password could not be changed."
		if errors.Is(err, auth.ErrPasswordMismatch) {
			message = "Current password is incorrect."
		} else if errors.Is(err, auth.ErrCompromisedPassword) {
			message = "Choose a password that has not appeared in common or breached-password lists."
		} else if errors.Is(err, auth.ErrPasswordCheckFailed) {
			message = "The breached-password check is temporarily unavailable. No change was made."
		} else if errors.Is(err, auth.ErrRecentMFARequired) {
			message = "Sign in again before changing your password."
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
	want := s.config.AdminOrigin.Scheme + "://" + s.config.AdminOrigin.Host
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
