package appserver

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/mudrii/openclaw-dashboard/internal/appauth"
	"github.com/mudrii/openclaw-dashboard/internal/appsecrets"
)

//go:embed web/secrets.html
var secretsHTMLRaw []byte

var secretsTmpl = template.Must(template.New("secrets").Parse(string(secretsHTMLRaw)))

type secretsPageData struct {
	Keys      []string
	FlashKind string
	FlashText string
}

// WithSecrets injects the secrets service. Returns the server for chaining.
func (s *Server) WithSecrets(svc *appsecrets.Service) *Server {
	s.secrets = svc
	return s
}

func (s *Server) currentUser(r *http.Request) string {
	if !s.authEnabled() {
		return "dev"
	}
	cookie, err := r.Cookie(appauth.CookieName)
	if err != nil {
		return "unknown"
	}
	user, err := appauth.ValidateCookie(cookie.Value, s.cfg.Auth.SessionSecret)
	if err != nil {
		return "unknown"
	}
	return user
}

func (s *Server) handleSecretsPage(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, "secrets disabled", http.StatusNotFound)
		return
	}
	keys, err := s.secrets.List()
	if err != nil {
		slog.Error("[dashboard] secrets list failed", "error", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	data := secretsPageData{Keys: keys}
	if flash := r.URL.Query().Get("flash"); flash != "" {
		data.FlashKind, data.FlashText = decodeFlash(flash)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_ = secretsTmpl.Execute(w, data)
}

func (s *Server) handleSecretsSet(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, "secrets disabled", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/secrets?flash=error:bad_form", http.StatusSeeOther)
		return
	}
	key := r.PostFormValue("key")
	value := r.PostFormValue("value")
	user := s.currentUser(r)
	if err := s.secrets.Set(r.Context(), key, value, user); err != nil {
		slog.Info("[dashboard] secrets set failed", "key", key, "user", user, "error", err.Error())
		if strings.HasPrefix(err.Error(), "reload_failed") {
			http.Redirect(w, r, "/secrets?flash=set_reload_failed:"+url.QueryEscape(key), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/secrets?flash=error:"+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	slog.Info("[dashboard] secrets set", "key", key, "user", user)
	http.Redirect(w, r, "/secrets?flash=set:"+url.QueryEscape(key), http.StatusSeeOther)
}

func (s *Server) handleSecretsDelete(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		http.Error(w, "secrets disabled", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/secrets?flash=error:bad_form", http.StatusSeeOther)
		return
	}
	key := r.PostFormValue("key")
	user := s.currentUser(r)
	if err := s.secrets.Delete(r.Context(), key, user); err != nil {
		slog.Info("[dashboard] secrets delete failed", "key", key, "user", user, "error", err.Error())
		if strings.HasPrefix(err.Error(), "reload_failed") {
			http.Redirect(w, r, "/secrets?flash=delete_reload_failed:"+url.QueryEscape(key), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/secrets?flash=error:"+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	slog.Info("[dashboard] secrets delete", "key", key, "user", user)
	http.Redirect(w, r, "/secrets?flash=deleted:"+url.QueryEscape(key), http.StatusSeeOther)
}

func decodeFlash(flash string) (kind, text string) {
	colon := strings.IndexByte(flash, ':')
	var tag, arg string
	if colon < 0 {
		tag = flash
	} else {
		tag = flash[:colon]
		arg = flash[colon+1:]
	}
	switch tag {
	case "set":
		return "success", "✓ " + arg + " gesetzt, Reload OK"
	case "deleted":
		return "success", "✓ " + arg + " gelöscht, Reload OK"
	case "set_reload_failed":
		return "warn", "✓ " + arg + " geschrieben, aber secrets reload fehlgeschlagen — manuell prüfen"
	case "delete_reload_failed":
		return "warn", "✓ " + arg + " gelöscht, aber secrets reload fehlgeschlagen — manuell prüfen"
	case "error":
		return "error", "✗ " + arg
	}
	return "", ""
}
