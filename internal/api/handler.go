package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/mattaustin/redir/internal/auth"
	"github.com/mattaustin/redir/internal/store"
)

type Config struct {
	HTTPPort    int    `json:"http_port"`
	DNSPort     int    `json:"dns_port"`
	Domain      string `json:"domain"`
	ProxyDomain string `json:"proxy_domain"`
	PublicIP    string `json:"public_ip"`
	BindAddr    string `json:"bind_addr"`
	IptablesCmd string `json:"iptables_cmd"`
	PfCmd       string `json:"pf_cmd"`
	BuildCommit string `json:"build_commit"`
}

type Preset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var presets = []Preset{
	{Name: "AWS metadata", URL: "http://169.254.169.254/latest/meta-data/"},
	{Name: "AWS metadata v2 (token)", URL: "http://169.254.169.254/latest/api/token"},
	{Name: "GCP metadata", URL: "http://metadata.google.internal/computeMetadata/v1/"},
	{Name: "Azure IMDS", URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
	{Name: "Azure IMDS token", URL: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"},
	{Name: "localhost HTTP", URL: "http://127.0.0.1/"},
	{Name: "localhost HTTPS", URL: "https://127.0.0.1/"},
	{Name: "localhost :8080", URL: "http://127.0.0.1:8080/"},
	{Name: "Kubernetes API", URL: "https://kubernetes.default.svc/"},
	{Name: "Docker daemon", URL: "http://172.17.0.1:2375/"},
}

type Handler struct {
	store  *store.Store
	config Config
}

func New(s *store.Store, cfg Config) *Handler {
	return &Handler{store: s, config: cfg}
}

// Register wires all API routes onto mux. Protected routes are wrapped with
// the provided middleware function.
func (h *Handler) Register(mux *http.ServeMux, protect func(http.Handler) http.Handler) {
	mux.Handle("/api/rules", protect(http.HandlerFunc(h.rules)))
	mux.Handle("/api/rules/", protect(http.HandlerFunc(h.ruleByID)))
	mux.Handle("/api/rebind", protect(http.HandlerFunc(h.rebind)))
	mux.Handle("/api/rebind/", protect(http.HandlerFunc(h.rebindByID)))
	mux.Handle("/api/hits", protect(http.HandlerFunc(h.getHits)))
	mux.Handle("/api/rebind-events", protect(http.HandlerFunc(h.getRebindEvents)))
	mux.Handle("/api/presets", protect(http.HandlerFunc(h.getPresets)))
	mux.Handle("/api/info", protect(http.HandlerFunc(h.getInfo)))

	admin := requireAdmin(h.store)
	mux.Handle("/api/config", protect(admin(http.HandlerFunc(h.getConfig))))
	mux.Handle("/api/admin/rules", protect(admin(http.HandlerFunc(h.adminListRules))))
	mux.Handle("/api/admin/rules/", protect(admin(http.HandlerFunc(h.adminDeleteRule))))
	mux.Handle("/api/admin/rebind", protect(admin(http.HandlerFunc(h.adminListRebind))))
	mux.Handle("/api/admin/rebind/", protect(admin(http.HandlerFunc(h.adminDeleteRebind))))
	mux.Handle("/api/admin/users", protect(admin(http.HandlerFunc(h.adminListUsers))))
	mux.Handle("/api/admin/users/", protect(admin(http.HandlerFunc(h.adminUserByID))))
	mux.Handle("/api/admin/hits", protect(admin(http.HandlerFunc(h.adminListHits))))
}

// --- Rules ---

func (h *Handler) rules(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromCtx(r)
	switch r.Method {
	case http.MethodGet:
		rules, err := h.store.ListRules(userID)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		if rules == nil {
			rules = []*store.Rule{}
		}
		jsonOK(w, rules)
	case http.MethodPost:
		var rule store.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), 400)
			return
		}
		if rule.TargetURL == "" {
			jsonError(w, "target_url required", 400)
			return
		}
		if rule.Type == "" {
			rule.Type = store.RedirectHTTP
		}
		rule.UserID = userID
		if err := h.store.CreateRule(&rule); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: rules.label") {
				jsonError(w, "label already taken", 409)
			} else {
				jsonError(w, err.Error(), 500)
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonOK(w, rule)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (h *Handler) ruleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		h.rules(w, r)
		return
	}
	userID := auth.UserIDFromCtx(r)

	switch r.Method {
	case http.MethodGet:
		rule, err := h.store.GetRule(id)
		if err != nil || rule == nil || rule.UserID != userID {
			jsonError(w, "not found", 404)
			return
		}
		jsonOK(w, rule)
	case http.MethodPut:
		rule, err := h.store.GetRule(id)
		if err != nil || rule == nil || rule.UserID != userID {
			jsonError(w, "not found", 404)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(rule); err != nil {
			jsonError(w, "invalid JSON", 400)
			return
		}
		rule.ID = id
		rule.UserID = userID // prevent ownership change
		if err := h.store.UpdateRule(rule); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		jsonOK(w, rule)
	case http.MethodDelete:
		if err := h.store.DeleteRule(id, userID); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// --- Rebind ---

func (h *Handler) rebind(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromCtx(r)
	switch r.Method {
	case http.MethodGet:
		rules, err := h.store.ListRebindRules(userID)
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		if rules == nil {
			rules = []*store.RebindRule{}
		}
		type rebindWithCount struct {
			*store.RebindRule
			QueryCount int64 `json:"query_count"`
			Flipped    bool  `json:"flipped"`
		}
		out := make([]rebindWithCount, len(rules))
		for i, rr := range rules {
			qc := h.store.GetQueryCount(rr.ID)
			out[i] = rebindWithCount{
				RebindRule: rr,
				QueryCount: qc,
				Flipped:    store.IsFlipped(qc, int64(rr.Threshold), rr.FlipFlop),
			}
		}
		jsonOK(w, out)
	case http.MethodPost:
		var rr store.RebindRule
		if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), 400)
			return
		}
		if rr.FirstIP == "" || rr.SecondIP == "" {
			jsonError(w, "first_ip and second_ip required", 400)
			return
		}
		if !isIPv4(rr.FirstIP) || !isIPv4(rr.SecondIP) {
			jsonError(w, "first_ip and second_ip must be valid IPv4 addresses", 400)
			return
		}
		rr.UserID = userID
		if err := h.store.CreateRebindRule(&rr); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		if rr.Hostname == "" {
			slug := rr.ID
			if rr.Label != "" {
				slug = rr.Label
			}
			rr.Hostname = slug + "." + h.config.Domain
			h.store.UpdateRebindHostname(rr.ID, rr.Hostname)
		}
		w.WriteHeader(http.StatusCreated)
		jsonOK(w, rr)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (h *Handler) rebindByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/rebind/")
	parts := strings.SplitN(strings.TrimSuffix(path, "/"), "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	if id == "" {
		h.rebind(w, r)
		return
	}

	userID := auth.UserIDFromCtx(r)

	if action == "reset" && r.Method == http.MethodPost {
		// verify ownership before reset
		rr, err := h.store.GetRebindRule(id)
		if err != nil || rr == nil || rr.UserID != userID {
			jsonError(w, "not found", 404)
			return
		}
		h.store.ResetQueryCount(id)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if err := h.store.DeleteRebindRule(id, userID); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// --- Presets, Config, Hits ---

func (h *Handler) getPresets(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, presets)
}

func (h *Handler) getConfig(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, h.config)
}

func (h *Handler) getInfo(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, struct {
		ProxyDomain string `json:"proxy_domain"`
		PublicIP    string `json:"public_ip"`
		BuildCommit string `json:"build_commit"`
	}{
		ProxyDomain: h.config.ProxyDomain,
		PublicIP:    h.config.PublicIP,
		BuildCommit: h.config.BuildCommit,
	})
}

func (h *Handler) getHits(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromCtx(r)
	hits, err := h.store.ListHits(100, userID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if hits == nil {
		hits = []*store.Hit{}
	}
	jsonOK(w, hits)
}

func (h *Handler) getRebindEvents(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromCtx(r)
	events := h.store.ListRebindEvents(userID, 200)
	if events == nil {
		events = []store.RebindEvent{}
	}
	jsonOK(w, events)
}

// --- helpers ---

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}
