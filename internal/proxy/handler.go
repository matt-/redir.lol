package proxy

import (
	"io"
	"net/http"
	"strings"
	"time"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	},
	Transport: &http.Transport{
		DisableKeepAlives: true,
	},
}

// hopByHop headers that must not be forwarded
var hopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Handler fetches target on behalf of the caller and pipes the response back.
// The target URL is set by the redirect handler via X-Redir-Target header, or
// passed directly in the ?url= query param for direct API use.
func Handler(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Redir-Target")
	if target == "" {
		target = r.URL.Query().Get("url")
	}
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "invalid target URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	// forward safe request headers
	for k, vv := range r.Header {
		if hopHeaders[strings.ToLower(k)] || strings.ToLower(k) == "x-redir-target" {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// copy response headers
	for k, vv := range resp.Header {
		if hopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
