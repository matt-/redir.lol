package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mattaustin/redir/internal/store"
)

type Config struct {
	HTTPPort    int    `json:"http_port"`
	DNSPort     int    `json:"dns_port"`
	Domain      string `json:"domain"`
	PublicIP    string `json:"public_ip"`
	BindAddr    string `json:"bind_addr"`
	IptablesCmd string `json:"iptables_cmd"`
	PfCmd       string `json:"pf_cmd"`
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

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/rules", h.rules)
	mux.HandleFunc("/api/rules/", h.ruleByID)
	mux.HandleFunc("/api/rebind", h.rebind)
	mux.HandleFunc("/api/rebind/", h.rebindByID)
	mux.HandleFunc("/api/presets", h.getPresets)
	mux.HandleFunc("/api/config", h.getConfig)
	mux.HandleFunc("/api/hits", h.getHits)
}

// --- Rules ---

func (h *Handler) rules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := h.store.ListRules()
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
		if err := h.store.CreateRule(&rule); err != nil {
			jsonError(w, err.Error(), 500)
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
	switch r.Method {
	case http.MethodGet:
		rule, err := h.store.GetRule(id)
		if err != nil || rule == nil {
			jsonError(w, "not found", 404)
			return
		}
		jsonOK(w, rule)
	case http.MethodPut:
		rule, err := h.store.GetRule(id)
		if err != nil || rule == nil {
			jsonError(w, "not found", 404)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(rule); err != nil {
			jsonError(w, "invalid JSON", 400)
			return
		}
		rule.ID = id // prevent ID change
		if err := h.store.UpdateRule(rule); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		jsonOK(w, rule)
	case http.MethodDelete:
		if err := h.store.DeleteRule(id); err != nil {
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
	switch r.Method {
	case http.MethodGet:
		rules, err := h.store.ListRebindRules()
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		if rules == nil {
			rules = []*store.RebindRule{}
		}
		// annotate with live query counts
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
				Flipped:    qc > int64(rr.Threshold),
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
		// auto-generate hostname from ID after creation
		if err := h.store.CreateRebindRule(&rr); err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		if rr.Hostname == "" {
			rr.Hostname = "rebind-" + rr.ID + "." + h.config.Domain
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

	if action == "reset" && r.Method == http.MethodPost {
		h.store.ResetQueryCount(id)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if err := h.store.DeleteRebindRule(id); err != nil {
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

func (h *Handler) getHits(w http.ResponseWriter, r *http.Request) {
	hits, err := h.store.ListHits(100)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if hits == nil {
		hits = []*store.Hit{}
	}
	jsonOK(w, hits)
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
