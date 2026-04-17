package appserver

import (
	"html"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mudrii/openclaw-dashboard/internal/appauth"
	appconfig "github.com/mudrii/openclaw-dashboard/internal/appconfig"
)

func (s *Server) isAuthenticated(r *http.Request) bool {
	if s.cfg.Auth.SessionSecret == "" {
		return false
	}
	cookie, err := r.Cookie(appauth.CookieName)
	if err != nil {
		return false
	}
	_, err = appauth.ValidateCookie(cookie.Value, s.cfg.Auth.SessionSecret)
	return err == nil
}

func (s *Server) authEnabled() bool {
	return len(s.cfg.Auth.Users) > 0 || s.cfg.Auth.SessionSecret != ""
}

func (s *Server) renderLogin(w http.ResponseWriter, statusCode int, errorMsg string) {
	page := s.loginHTMLRaw
	if errorMsg != "" {
		page = strings.Replace(page, "{{ERROR_CLASS}}", "visible", 1)
		page = strings.Replace(page, "{{ERROR_MESSAGE}}", html.EscapeString(errorMsg), 1)
	} else {
		page = strings.Replace(page, "{{ERROR_CLASS}}", "", 1)
		page = strings.Replace(page, "{{ERROR_MESSAGE}}", "", 1)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(page))
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if len(s.cfg.Auth.Users) == 0 {
		s.renderLogin(w, http.StatusOK, "Keine Benutzer konfiguriert. Bitte auth.users in config.json anlegen.")
		return
	}
	s.renderLogin(w, http.StatusOK, "")
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		ip = fwd
	}

	if !s.loginRateLimiter.Allow(ip) {
		s.renderLogin(w, http.StatusTooManyRequests, "Zu viele Anmeldeversuche. Bitte später erneut versuchen.")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, http.StatusBadRequest, "Ungültige Anfrage.")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user := s.findUser(username)
	if user == nil {
		appauth.VerifyPassword(password, appauth.DummyHash)
		slog.Warn("[dashboard] login failed: unknown user", "username", username, "ip", ip)
		s.renderLogin(w, http.StatusOK, "Benutzername oder Passwort ungültig.")
		return
	}

	if !appauth.VerifyPassword(password, user.PasswordHash) {
		slog.Warn("[dashboard] login failed: wrong password", "username", username, "ip", ip)
		s.renderLogin(w, http.StatusOK, "Benutzername oder Passwort ungültig.")
		return
	}

	cookie := appauth.SignCookie(username, s.cfg.Auth.SessionSecret, s.cfg.Auth.SessionMaxAge)
	http.SetCookie(w, cookie)
	slog.Info("[dashboard] login successful", "username", username, "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, appauth.ClearCookie())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) findUser(username string) *appconfig.AuthUser {
	for i := range s.cfg.Auth.Users {
		if s.cfg.Auth.Users[i].Username == username {
			return &s.cfg.Auth.Users[i]
		}
	}
	return nil
}
