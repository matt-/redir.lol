package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/mattaustin/redir/internal/store"
)

type Server struct {
	srv    *dns.Server
	domain string
}

func New(s *store.Store, domain string, port int) *Server {
	domain = strings.TrimSuffix(domain, ".") + "."

	mux := dns.NewServeMux()
	mux.HandleFunc(domain, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.RecursionAvailable = false

		remoteAddr := w.RemoteAddr().String()
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				if !resolveRebind(s, domain, q.Name, remoteAddr, m) {
					// NXDOMAIN for unknown subdomains
					m.Rcode = dns.RcodeNameError
					appendSOA(domain, m)
				}
			case dns.TypeSOA:
				appendSOA(domain, m)
			case dns.TypeNS:
				appendNS(domain, m)
			default:
				m.Rcode = dns.RcodeNameError
			}
		}
		w.WriteMsg(m)
	})

	srv := &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Net:     "udp",
		Handler: mux,
	}

	return &Server{srv: srv, domain: domain}
}

func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.ShutdownContext(ctx)
}

func appendSOA(domain string, m *dns.Msg) {
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns1." + domain,
		Mbox:    "hostmaster." + domain,
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   900,
		Expire:  86400,
		Minttl:  1,
	}
	m.Ns = append(m.Ns, soa)
}

func appendNS(domain string, m *dns.Msg) {
	m.Answer = append(m.Answer, &dns.NS{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1." + domain,
	})
	// ns1 A record pointing to ourselves — caller must set a sensible IP
	// We use a wildcard 0.0.0.0 here; the real NS glue is set at the registrar
	m.Extra = append(m.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "ns1." + domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("0.0.0.0"),
	})
}
