package redirect

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mattaustin/redir/internal/proxy"
	"github.com/mattaustin/redir/internal/store"
)

const metaTemplate = `<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0;url=%s">
<title>Redirecting...</title>
</head><body>
<p>Redirecting to <a href="%s">%s</a></p>
</body></html>`

const jsTemplate = `<!DOCTYPE html>
<html><head><title>Redirecting...</title></head><body>
<script>window.location.href=%q;</script>
<noscript><p>JavaScript required. <a href="%s">Click here</a>.</p></noscript>
</body></html>`

type Handler struct {
	store       *store.Store
	proxyDomain string // if set, proxy rules redirect to this domain instead of serving inline
}

func New(s *store.Store, proxyDomain string) *Handler {
	return &Handler{store: s, proxyDomain: proxyDomain}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// strip leading /r/
	key := strings.TrimPrefix(r.URL.Path, "/r/")
	key = strings.TrimSuffix(key, "/")
	if key == "" {
		http.NotFound(w, r)
		return
	}

	rule, err := h.store.GetRule(key)
	if err != nil || rule == nil {
		http.NotFound(w, r)
		return
	}

	// record hit asynchronously
	go func() {
		h.store.IncrementHitCount(rule.ID)
		h.store.RecordHit(&store.Hit{
			RuleID:    rule.ID,
			RemoteIP:  remoteIP(r),
			UserAgent: r.UserAgent(),
		})
	}()

	target := rule.TargetURL

	switch rule.Type {
	case store.RedirectHTTP:
		code := rule.StatusCode
		if code == 0 {
			code = 302
		}
		http.Redirect(w, r, target, code)

	case store.RedirectMeta:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, metaTemplate, target, target, target)

	case store.RedirectJS:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, jsTemplate, target, target)

	case store.RedirectProxy:
		if h.proxyDomain != "" {
			scheme := "https"
			if r.TLS == nil {
				scheme = "http"
			}
			http.Redirect(w, r, scheme+"://"+h.proxyDomain+"/r/"+key, http.StatusFound)
			return
		}
		// no proxy domain configured — serve inline (XSS risk, local/dev only)
		r2 := r.WithContext(r.Context())
		r2.Header.Set("X-Redir-Target", target)
		proxy.Handler(w, r2)

	default:
		http.Redirect(w, r, target, http.StatusFound)
	}
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.SplitN(xff, ",", 2)[0]
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		ip = ip[:i]
	}
	return ip
}
