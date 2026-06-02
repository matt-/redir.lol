package api

import (
	"net/http"
	"strconv"
	"strings"

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
