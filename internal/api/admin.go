package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/mattaustin/redir/internal/auth"
	"github.com/mattaustin/redir/internal/store"
)

// requireAdmin returns a middleware that allows only users whose email is in adminEmails.
func requireAdmin(adminEmails []string, s *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := auth.UserIDFromCtx(r)
			u, err := s.GetUserByID(userID)
			if err != nil || u == nil {
				jsonError(w, "forbidden", http.StatusForbidden)
				return
			}
			for _, e := range adminEmails {
				if e == u.Email {
					next.ServeHTTP(w, r)
					return
				}
			}
			jsonError(w, "forbidden", http.StatusForbidden)
		})
	}
}

func (h *Handler) adminListRules(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 25
	}

	rules, total, err := h.store.ListAllRules(page, perPage)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if rules == nil {
		rules = []*store.AdminRule{}
	}
	jsonOK(w, map[string]interface{}{
		"rules":    rules,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

func (h *Handler) adminDeleteRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/rules/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := h.store.DeleteRuleByID(id); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) adminListRebind(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 25
	}

	rules, total, err := h.store.ListAllRebindRules(page, perPage)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if rules == nil {
		rules = []*store.AdminRebindRule{}
	}
	jsonOK(w, map[string]interface{}{
		"rules":    rules,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

func (h *Handler) adminListHits(w http.ResponseWriter, r *http.Request) {
	hits, err := h.store.ListAllHits(200)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if hits == nil {
		hits = []*store.Hit{}
	}
	jsonOK(w, hits)
}

func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if users == nil {
		users = []*store.User{}
	}
	jsonOK(w, users)
}

func (h *Handler) adminUserByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}

	// prevent admin from editing/deleting their own account via this endpoint
	callerID := auth.UserIDFromCtx(r)

	switch r.Method {
	case http.MethodPut:
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Email != "" {
			body.Email = strings.TrimSpace(strings.ToLower(body.Email))
			if err := h.store.UpdateUserEmail(id, body.Email); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					jsonError(w, "email already in use", http.StatusConflict)
					return
				}
				jsonError(w, err.Error(), 500)
				return
			}
		}
		if body.Password != "" {
			if len(body.Password) < 8 {
				jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
				return
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
			if err != nil {
				jsonError(w, "internal error", http.StatusInternalServerError)
				return
			}
			if err := h.store.UpdateUserPassword(id, string(hash)); err != nil {
				jsonError(w, err.Error(), 500)
				return
			}
		}
		u, _ := h.store.GetUserByID(id)
		jsonOK(w, u)

	case http.MethodDelete:
		if id == callerID {
			jsonError(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}
		if err := h.store.DeleteUser(id); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) adminDeleteRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/rebind/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := h.store.DeleteRebindRuleByID(id); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
