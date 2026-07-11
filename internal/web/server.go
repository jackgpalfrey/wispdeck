// Package web implements Wispdeck's administrative HTTP boundary.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
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

type Config struct {
	AdminOrigin *url.URL
	Development bool
	Logger      *slog.Logger
}

type Server struct {
	config     Config
	auth       *auth.Service
	limiter    *limit.LoginLimiter
	templates  *template.Template
	handler    http.Handler
	cookieName string
}

type sessionContextKey struct{}

//go:embed templates/*.html assets/*
var files embed.FS

func New(config Config, authService *auth.Service) (*Server, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if authService == nil {
		return nil, errors.New("authentication service is required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	templates, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s := &Server{
		config:     config,
		auth:       authService,
		limiter:    limit.NewLoginLimiter(),
		templates:  templates,
		cookieName: productionCookieName,
	}
	if config.Development {
		s.cookieName = "wispdeck_session"
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
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.dashboard)))
	mux.Handle("POST /logout", s.requireSession(http.HandlerFunc(s.logout)))
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
		w.Header().Set("Referrer-Policy", "no-referrer")
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
	clientIP := clientAddress(r.RemoteAddr)
	usernameKey := fmt.Sprintf("%x", sha256.Sum256([]byte(username)))
	if !s.limiter.Allow(usernameKey, clientIP) {
		s.render(w, http.StatusTooManyRequests, "login.html", loginView{
			Username: username,
			Error:    "Unable to sign in. Try again later.",
		})
		return
	}
	token, _, err := s.auth.Login(r.Context(), username, r.PostForm.Get("password"), clientIP)
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
	s.setSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	s.render(w, http.StatusOK, "dashboard.html", struct {
		Username  string
		CSRFToken string
	}{Username: session.User.Username, CSRFToken: session.CSRFToken})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.auth.Logout(r.Context(), session, clientAddress(r.RemoteAddr)); err != nil {
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
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Secure:   !s.config.Development,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   !s.config.Development,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) validBrowserOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
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

func clientAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.config.Logger.Error("render template", "template", name, "error", err)
	}
}
