package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Users ---

func (s *Store) CreateUser(u *User) error {
	if u.ID == "" {
		u.ID = newID()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, email, username, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Username, u.PasswordHash, u.CreatedAt,
	)
	return err
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, email, username, password_hash, created_at FROM users WHERE email=?`, email,
	).Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (s *Store) GetUserByID(id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, email, username, password_hash, created_at FROM users WHERE id=?`, id,
	).Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// --- Sessions ---

func (s *Store) CreateSession(userID string) (*Session, error) {
	sess := &Session{
		Token:     newToken(),
		UserID:    userID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.Token, sess.UserID, sess.CreatedAt, sess.ExpiresAt,
	)
	return sess, err
}

func (s *Store) GetSession(token string) (*Session, error) {
	sess := &Session{}
	err := s.db.QueryRow(
		`SELECT token, user_id, created_at, expires_at FROM sessions WHERE token=?`, token,
	).Scan(&sess.Token, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sess, err
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (s *Store) DeleteExpiredSessions() {
	s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
}
