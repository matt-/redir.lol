package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mattaustin/redir/internal/store"
)

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
func RegisterHandler(s *store.Store) http.HandlerFunc {
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
			Email:        body.Email,
			PasswordHash: string(hash),
		}
		if err := s.CreateUser(u); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				jsonError(w, "email or username already in use", http.StatusConflict)
				return
			}
			jsonError(w, "internal error", http.StatusInternalServerError)
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
func MeHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := UserIDFromCtx(r)
		u, err := s.GetUserByID(userID)
		if err != nil || u == nil {
			jsonError(w, "not found", http.StatusUnauthorized)
			return
		}
		jsonOK(w, map[string]interface{}{
			"id":    u.ID,
			"email": u.Email,
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
