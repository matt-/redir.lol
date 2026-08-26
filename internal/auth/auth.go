package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mattaustin/redir/internal/mailer"
	"github.com/mattaustin/redir/internal/store"
)

// VerifyConfig controls whether/how new signups must verify their email
// before logging in. If Mailer is nil, verification is disabled and new
// accounts are created already-verified (e.g. local dev without Cloudflare
// Email Sending configured).
type VerifyConfig struct {
	Mailer    mailer.Mailer
	FromEmail string
}

func (v VerifyConfig) enabled() bool {
	return v.Mailer != nil && v.FromEmail != ""
}

type contextKey string

const UserIDKey contextKey = "user_id"

const sessionCookie = "redir_session"

// UserIDFromCtx extracts the authenticated user ID from the request context.
func UserIDFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(UserIDKey).(string)
	return v
}

// Middleware validates the session cookie and injects the user ID into context.
// Returns 401 if the session is missing or expired.
func Middleware(s *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := sessionToken(r)
			if token == "" {
				jsonError(w, "authentication required", http.StatusUnauthorized)
				return
			}
			sess, err := s.GetSession(token)
			if err != nil || sess == nil || time.Now().After(sess.ExpiresAt) {
				clearCookie(w)
				jsonError(w, "session expired", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), UserIDKey, sess.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RegisterHandler handles POST /api/auth/register
func RegisterHandler(s *store.Store, vcfg VerifyConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Email = strings.TrimSpace(strings.ToLower(body.Email))
		if body.Email == "" || body.Password == "" {
			jsonError(w, "email and password are required", http.StatusBadRequest)
			return
		}
		if len(body.Password) < 8 {
			jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}

		u := &store.User{
			Email:         body.Email,
			PasswordHash:  string(hash),
			EmailVerified: !vcfg.enabled(),
		}
		if err := s.CreateUser(u); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				jsonError(w, "email or username already in use", http.StatusConflict)
				return
			}
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}

		if vcfg.enabled() {
			if err := sendVerificationEmail(s, vcfg, r, u); err != nil {
				log.Printf("[auth] failed to send verification email to %s: %v", u.Email, err)
			}
			w.WriteHeader(http.StatusCreated)
			jsonOK(w, map[string]interface{}{
				"email":               u.Email,
				"pending_verification": true,
			})
			return
		}

		sess, err := s.CreateSession(u.ID)
		if err != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}

		setCookie(w, sess.Token, sess.ExpiresAt)
		w.WriteHeader(http.StatusCreated)
		jsonOK(w, map[string]interface{}{
			"id":    u.ID,
			"email": u.Email,
		})
	}
}

// sendVerificationEmail issues a fresh verification token for u and emails
// the confirmation link.
func sendVerificationEmail(s *store.Store, vcfg VerifyConfig, r *http.Request, u *store.User) error {
	token, err := newVerifyToken()
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	if err := s.SetVerifyToken(u.ID, token, expires); err != nil {
		return err
	}

	link := baseURL(r) + "/api/auth/verify?token=" + url.QueryEscape(token)
	subject := "Verify your redir account"
	text := fmt.Sprintf("Confirm your email address to finish setting up your redir account:\n\n%s\n\nThis link expires in 24 hours.", link)
	html := fmt.Sprintf(`<p>Confirm your email address to finish setting up your redir account:</p><p><a href="%s">%s</a></p><p>This link expires in 24 hours.</p>`, link, link)
	return vcfg.Mailer.Send(u.Email, subject, html, text)
}

// VerifyHandler handles GET /api/auth/verify?token=... — clicked from the
// verification email. On success it marks the account verified, logs the
// user in, and redirects to the app; on failure it redirects with an error flag.
func VerifyHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		u, err := s.GetUserByVerifyToken(token)
		if err != nil || u == nil || token == "" {
			http.Redirect(w, r, "/?verify_error=1", http.StatusFound)
			return
		}
		if err := s.MarkEmailVerified(u.ID); err != nil {
			http.Redirect(w, r, "/?verify_error=1", http.StatusFound)
			return
		}

		sess, err := s.CreateSession(u.ID)
		if err != nil {
			http.Redirect(w, r, "/?verify_error=1", http.StatusFound)
			return
		}
		setCookie(w, sess.Token, sess.ExpiresAt)
		http.Redirect(w, r, "/?verified=1", http.StatusFound)
	}
}

// ResendVerificationHandler handles POST /api/auth/resend. It always returns
// a generic success response regardless of whether the email exists or is
// already verified, to avoid leaking account existence.
func ResendVerificationHandler(s *store.Store, vcfg VerifyConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Email string `json:"email"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		body.Email = strings.TrimSpace(strings.ToLower(body.Email))

		if vcfg.enabled() && body.Email != "" {
			if u, err := s.GetUserByEmail(body.Email); err == nil && u != nil && !u.EmailVerified {
				if err := sendVerificationEmail(s, vcfg, r, u); err != nil {
					log.Printf("[auth] failed to resend verification email to %s: %v", u.Email, err)
				}
			}
		}
		jsonOK(w, map[string]string{"message": "if that email exists and is unverified, a new verification link has been sent"})
	}
}

func newVerifyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// baseURL derives the scheme+host to build absolute links from, honoring
// the X-Forwarded-Proto header Cloudflare sets on proxied requests.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// LoginHandler handles POST /api/auth/login
func LoginHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Email = strings.TrimSpace(strings.ToLower(body.Email))

		u, err := s.GetUserByEmail(body.Email)
		if err != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		// use a constant-time comparison to avoid timing attacks
		if u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
			jsonError(w, "invalid email or password", http.StatusUnauthorized)
			return
		}

		if !u.EmailVerified {
			jsonErrorFields(w, "please verify your email before logging in", http.StatusForbidden, map[string]interface{}{"unverified": true})
			return
		}

		sess, err := s.CreateSession(u.ID)
		if err != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}

		setCookie(w, sess.Token, sess.ExpiresAt)
		jsonOK(w, map[string]interface{}{
			"id":    u.ID,
			"email": u.Email,
		})
	}
}

// LogoutHandler handles POST /api/auth/logout
func LogoutHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := sessionToken(r)
		if token != "" {
			s.DeleteSession(token)
		}
		clearCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// MeHandler handles GET /api/auth/me — returns current user or 401
func MeHandler(s *store.Store, adminEmails []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := UserIDFromCtx(r)
		u, err := s.GetUserByID(userID)
		if err != nil || u == nil {
			jsonError(w, "not found", http.StatusUnauthorized)
			return
		}
		isAdmin := false
		for _, e := range adminEmails {
			if e == u.Email {
				isAdmin = true
				break
			}
		}
		jsonOK(w, map[string]interface{}{
			"id":       u.ID,
			"email":    u.Email,
			"is_admin": isAdmin,
		})
	}
}

// --- helpers ---

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonErrorFields(w http.ResponseWriter, msg string, code int, extra map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body := map[string]interface{}{"error": msg}
	maps.Copy(body, extra)
	json.NewEncoder(w).Encode(body)
}
