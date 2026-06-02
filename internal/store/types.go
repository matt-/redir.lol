package store

import "time"

type RedirectType string

const (
	RedirectHTTP  RedirectType = "http"
	RedirectMeta  RedirectType = "meta"
	RedirectJS    RedirectType = "js"
	RedirectProxy RedirectType = "proxy"
)

// Rule.StatusCode is only used when Type == RedirectHTTP.
// Valid values: 301, 302, 303, 307, 308. Default: 302.
type Rule struct {
	ID         string       `json:"id"`
	Label      string       `json:"label"`
	TargetURL  string       `json:"target_url"`
	Type       RedirectType `json:"type"`
	StatusCode int          `json:"status_code"`
	HitCount   int64        `json:"hit_count"`
	UserID     string       `json:"user_id"`
	CreatedAt  time.Time    `json:"created_at"`
}

type RebindRule struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Hostname  string `json:"hostname"`
	FirstIP   string `json:"first_ip"`
	SecondIP  string `json:"second_ip"`
	Threshold int    `json:"threshold"`
	UserID    string `json:"user_id"`
}

type Hit struct {
	ID        int64     `json:"id"`
	RuleID    string    `json:"rule_id"`
	RuleLabel string    `json:"rule_label,omitempty"`
	RemoteIP  string    `json:"remote_ip"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
}

type AdminRule struct {
	Rule
	OwnerEmail string `json:"owner_email"`
}

type AdminRebindRule struct {
	RebindRule
	OwnerEmail string `json:"owner_email"`
	QueryCount int64  `json:"query_count"`
	Flipped    bool   `json:"flipped"`
}

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	Token     string    `json:"-"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
