package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	email         TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	created_at    DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token      TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users(id),
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
	id          TEXT PRIMARY KEY,
	label       TEXT UNIQUE,
	target_url  TEXT NOT NULL,
	type        TEXT NOT NULL,
	status_code INTEGER NOT NULL DEFAULT 302,
	hit_count   INTEGER NOT NULL DEFAULT 0,
	user_id     TEXT NOT NULL DEFAULT '',
	created_at  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS rebind_rules (
	id          TEXT PRIMARY KEY,
	label       TEXT,
	hostname    TEXT NOT NULL,
	first_ip    TEXT NOT NULL,
	second_ip   TEXT NOT NULL,
	threshold   INTEGER NOT NULL DEFAULT 1,
	flip_flop   INTEGER NOT NULL DEFAULT 0,
	user_id     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hits (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id    TEXT NOT NULL,
	remote_ip  TEXT,
	user_agent TEXT,
	timestamp  DATETIME NOT NULL
);
`


type Store struct {
	db          *sql.DB
	queryCounts sync.Map // rebind ID -> *atomic.Int64
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Migration: add flip_flop column to existing databases (ignore error if already present)
	db.Exec(`ALTER TABLE rebind_rules ADD COLUMN flip_flop INTEGER NOT NULL DEFAULT 0`)
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Redirect Rules ---

func (s *Store) CreateRule(r *Rule) error {
	if r.ID == "" {
		r.ID = newID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.Type == RedirectHTTP && r.StatusCode == 0 {
		r.StatusCode = 302
	}
	_, err := s.db.Exec(
		`INSERT INTO rules (id, label, target_url, type, status_code, hit_count, user_id, created_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		r.ID, nullableString(r.Label), r.TargetURL, r.Type, r.StatusCode, r.UserID, r.CreatedAt,
	)
	return err
}

func (s *Store) ListRules(userID string) ([]*Rule, error) {
	rows, err := s.db.Query(
		`SELECT id, COALESCE(label,''), target_url, type, status_code, hit_count, user_id, created_at
		 FROM rules WHERE user_id=? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*Rule
	for rows.Next() {
		r := &Rule{}
		if err := rows.Scan(&r.ID, &r.Label, &r.TargetURL, &r.Type, &r.StatusCode, &r.HitCount, &r.UserID, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) GetRule(idOrLabel string) (*Rule, error) {
	r := &Rule{}
	err := s.db.QueryRow(
		`SELECT id, COALESCE(label,''), target_url, type, status_code, hit_count, user_id, created_at
		 FROM rules WHERE id = ? OR label = ? LIMIT 1`,
		idOrLabel, idOrLabel,
	).Scan(&r.ID, &r.Label, &r.TargetURL, &r.Type, &r.StatusCode, &r.HitCount, &r.UserID, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (s *Store) UpdateRule(r *Rule) error {
	_, err := s.db.Exec(
		`UPDATE rules SET label=?, target_url=?, type=?, status_code=? WHERE id=? AND user_id=?`,
		nullableString(r.Label), r.TargetURL, r.Type, r.StatusCode, r.ID, r.UserID,
	)
	return err
}

func (s *Store) DeleteRule(id, userID string) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id=? AND user_id=?`, id, userID)
	return err
}

// DeleteRuleByID deletes any rule regardless of owner — admin use only.
func (s *Store) DeleteRuleByID(id string) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id=?`, id)
	return err
}

// ListAllRules returns all rules across all users, paginated, joined with owner email.
// Returns the rules, total count, and any error.
func (s *Store) ListAllRules(page, perPage int) ([]*AdminRule, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 25
	}
	offset := (page - 1) * perPage

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		`SELECT r.id, COALESCE(r.label,''), r.target_url, r.type, r.status_code, r.hit_count, r.user_id, r.created_at,
		        COALESCE(u.email,'')
		 FROM rules r LEFT JOIN users u ON r.user_id = u.id
		 ORDER BY r.created_at DESC
		 LIMIT ? OFFSET ?`,
		perPage, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []*AdminRule
	for rows.Next() {
		ar := &AdminRule{}
		if err := rows.Scan(
			&ar.ID, &ar.Label, &ar.TargetURL, &ar.Type, &ar.StatusCode,
			&ar.HitCount, &ar.UserID, &ar.CreatedAt, &ar.OwnerEmail,
		); err != nil {
			return nil, 0, err
		}
		rules = append(rules, ar)
	}
	return rules, total, rows.Err()
}

func (s *Store) IncrementHitCount(ruleID string) {
	s.db.Exec(`UPDATE rules SET hit_count = hit_count + 1 WHERE id=?`, ruleID)
}

// --- Hits ---

func (s *Store) RecordHit(h *Hit) error {
	if h.Timestamp.IsZero() {
		h.Timestamp = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO hits (rule_id, remote_ip, user_agent, timestamp) VALUES (?, ?, ?, ?)`,
		h.RuleID, h.RemoteIP, h.UserAgent, h.Timestamp,
	)
	if err != nil {
		return err
	}
	s.db.Exec(`DELETE FROM hits WHERE id NOT IN (SELECT id FROM hits ORDER BY id DESC LIMIT 1000)`)
	return nil
}

func (s *Store) ListHits(limit int, userID string) ([]*Hit, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT h.id, h.rule_id, COALESCE(r.label, h.rule_id), h.remote_ip, h.user_agent, h.timestamp
		 FROM hits h LEFT JOIN rules r ON h.rule_id = r.id
		 WHERE r.user_id=?
		 ORDER BY h.id DESC LIMIT ?`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []*Hit
	for rows.Next() {
		h := &Hit{}
		if err := rows.Scan(&h.ID, &h.RuleID, &h.RuleLabel, &h.RemoteIP, &h.UserAgent, &h.Timestamp); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

func (s *Store) ListAllHits(limit int) ([]*Hit, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT h.id, h.rule_id, COALESCE(r.label, h.rule_id), h.remote_ip, h.user_agent, h.timestamp
		 FROM hits h LEFT JOIN rules r ON h.rule_id = r.id
		 ORDER BY h.id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []*Hit
	for rows.Next() {
		h := &Hit{}
		if err := rows.Scan(&h.ID, &h.RuleID, &h.RuleLabel, &h.RemoteIP, &h.UserAgent, &h.Timestamp); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// --- Rebind Rules ---

func (s *Store) CreateRebindRule(r *RebindRule) error {
	if r.ID == "" {
		r.ID = newID()
	}
	if r.Threshold <= 0 {
		r.Threshold = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO rebind_rules (id, label, hostname, first_ip, second_ip, threshold, flip_flop, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, nullableString(r.Label), r.Hostname, r.FirstIP, r.SecondIP, r.Threshold, r.FlipFlop, r.UserID,
	)
	return err
}

func (s *Store) ListRebindRules(userID string) ([]*RebindRule, error) {
	rows, err := s.db.Query(
		`SELECT id, COALESCE(label,''), hostname, first_ip, second_ip, threshold, flip_flop, user_id
		 FROM rebind_rules WHERE user_id=?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*RebindRule
	for rows.Next() {
		r := &RebindRule{}
		if err := rows.Scan(&r.ID, &r.Label, &r.Hostname, &r.FirstIP, &r.SecondIP, &r.Threshold, &r.FlipFlop, &r.UserID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) GetRebindRule(idOrLabel string) (*RebindRule, error) {
	r := &RebindRule{}
	err := s.db.QueryRow(
		`SELECT id, COALESCE(label,''), hostname, first_ip, second_ip, threshold, flip_flop, user_id
		 FROM rebind_rules WHERE id=? OR label=? LIMIT 1`, idOrLabel, idOrLabel,
	).Scan(&r.ID, &r.Label, &r.Hostname, &r.FirstIP, &r.SecondIP, &r.Threshold, &r.FlipFlop, &r.UserID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (s *Store) UpdateRebindHostname(id, hostname string) error {
	_, err := s.db.Exec(`UPDATE rebind_rules SET hostname=? WHERE id=?`, hostname, id)
	return err
}

func (s *Store) DeleteRebindRule(id, userID string) error {
	s.queryCounts.Delete(id)
	_, err := s.db.Exec(`DELETE FROM rebind_rules WHERE id=? AND user_id=?`, id, userID)
	return err
}

// DeleteRebindRuleByID deletes any rebind rule regardless of owner — admin use only.
func (s *Store) DeleteRebindRuleByID(id string) error {
	s.queryCounts.Delete(id)
	_, err := s.db.Exec(`DELETE FROM rebind_rules WHERE id=?`, id)
	return err
}

// ListAllRebindRules returns all rebind rules across all users, paginated, joined with owner email.
func (s *Store) ListAllRebindRules(page, perPage int) ([]*AdminRebindRule, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 25
	}
	offset := (page - 1) * perPage

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rebind_rules`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		`SELECT r.id, COALESCE(r.label,''), r.hostname, r.first_ip, r.second_ip, r.threshold, r.flip_flop, r.user_id,
		        COALESCE(u.email,'')
		 FROM rebind_rules r LEFT JOIN users u ON r.user_id = u.id
		 ORDER BY r.id DESC
		 LIMIT ? OFFSET ?`,
		perPage, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rules []*AdminRebindRule
	for rows.Next() {
		ar := &AdminRebindRule{}
		if err := rows.Scan(
			&ar.ID, &ar.Label, &ar.Hostname, &ar.FirstIP, &ar.SecondIP,
			&ar.Threshold, &ar.FlipFlop, &ar.UserID, &ar.OwnerEmail,
		); err != nil {
			return nil, 0, err
		}
		ar.QueryCount = s.GetQueryCount(ar.ID)
		ar.Flipped = IsFlipped(ar.QueryCount, int64(ar.Threshold), ar.FlipFlop)
		rules = append(rules, ar)
	}
	return rules, total, rows.Err()
}

// isFlipped returns whether the current query count should resolve to the second IP.
// In flip_flop mode the result alternates every threshold queries; otherwise it latches after threshold.
func IsFlipped(count, threshold int64, flipFlop bool) bool {
	if threshold <= 0 {
		threshold = 1
	}
	if flipFlop {
		return ((count-1)/threshold)%2 == 1
	}
	return count > threshold
}

// --- DNS rebind query counters (in-memory, intentionally reset on restart) ---

func (s *Store) IncrementQueryCount(id string) int64 {
	v, _ := s.queryCounts.LoadOrStore(id, &atomic.Int64{})
	return v.(*atomic.Int64).Add(1)
}

func (s *Store) GetQueryCount(id string) int64 {
	v, ok := s.queryCounts.Load(id)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

func (s *Store) ResetQueryCount(id string) {
	v, ok := s.queryCounts.Load(id)
	if ok {
		v.(*atomic.Int64).Store(0)
	}
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
