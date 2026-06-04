package dns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/mattaustin/redir/internal/store"
)

// resolveRebind handles an A query for a {id}.{domain} hostname.
// Returns true if it handled the query (appended to m.Answer).
func resolveRebind(s *store.Store, baseDomain, qname string, m *dns.Msg) bool {
	// strip trailing dot and domain suffix
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	suffix := "." + strings.ToLower(strings.TrimSuffix(baseDomain, "."))

	if !strings.HasSuffix(name, suffix) {
		return false
	}

	id := strings.TrimSuffix(name, suffix)
	rule, err := s.GetRebindRule(id)
	if err != nil || rule == nil {
		return false
	}

	count := s.IncrementQueryCount(id)
	ip := rule.FirstIP
	if store.IsFlipped(count, int64(rule.Threshold), rule.FlipFlop) {
		ip = rule.SecondIP
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		A: parsed.To4(),
	})
	return true
}
