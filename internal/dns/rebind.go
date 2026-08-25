package dns

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mattaustin/redir/internal/store"
)

// resolveRebind handles an A query for a {id}.{domain} hostname.
// Returns true if it handled the query (appended to m.Answer).
func resolveRebind(s *store.Store, baseDomain, qname, remoteAddr string, m *dns.Msg) bool {
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

	count := s.IncrementQueryCount(rule.ID)
	flipped := store.IsFlipped(count, int64(rule.Threshold), rule.FlipFlop)
	ip := rule.FirstIP
	if flipped {
		ip = rule.SecondIP
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		log.Printf("[dns] rebind id=%s label=%s host=%s remote=%s query=%d ip=%s flipped=%t error=invalid-ip",
			rule.ID, rule.Label, name, remoteAddr, count, ip, flipped)
		return false
	}

	log.Printf("[dns] rebind id=%s label=%s host=%s remote=%s query=%d threshold=%d flip_flop=%t flipped=%t ip=%s",
		rule.ID, rule.Label, name, remoteAddr, count, rule.Threshold, rule.FlipFlop, flipped, ip)

	s.RecordRebindEvent(store.RebindEvent{
		Timestamp:  time.Now(),
		RuleID:     rule.ID,
		Label:      rule.Label,
		Hostname:   name,
		RemoteAddr: remoteAddr,
		QueryCount: count,
		Threshold:  rule.Threshold,
		FlipFlop:   rule.FlipFlop,
		Flipped:    flipped,
		IP:         ip,
		UserID:     rule.UserID,
	})

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
