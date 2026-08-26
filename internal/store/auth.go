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
		`INSERT INTO users (id, email, password_hash, created_at, email_verified) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.CreatedAt, u.EmailVerified,
	)
	return err
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	var verifyToken sql.NullString
	var verifyExpires sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, email, password_hash, created_at, email_verified, verify_token, verify_expires FROM users WHERE email=?`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.EmailVerified, &verifyToken, &verifyExpires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	u.VerifyToken = verifyToken.String
	u.VerifyExpires = verifyExpires.Time
	return u, err
}

func (s *Store) GetUserByID(id string) (*User, error) {
	u := &User{}
	var verifyToken sql.NullString
	var verifyExpires sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, email, password_hash, created_at, email_verified, verify_token, verify_expires FROM users WHERE id=?`, id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.EmailVerified, &verifyToken, &verifyExpires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	u.VerifyToken = verifyToken.String
	u.VerifyExpires = verifyExpires.Time
	return u, err
}

// SetVerifyToken stores a fresh email-verification token and its expiry for userID.
func (s *Store) SetVerifyToken(userID, token string, expires time.Time) error {
	_, err := s.db.Exec(
		`UPDATE users SET verify_token=?, verify_expires=? WHERE id=?`,
		token, expires, userID,
	)
	return err
}

// GetUserByVerifyToken looks up a user by an unexpired verification token.
func (s *Store) GetUserByVerifyToken(token string) (*User, error) {
	u := &User{}
	var verifyToken sql.NullString
	var verifyExpires sql.NullTime
	err := s.db.QueryRow(
		`SELECT id, email, password_hash, created_at, email_verified, verify_token, verify_expires
		 FROM users WHERE verify_token=? AND verify_expires > ?`,
		token, time.Now().UTC(),
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.EmailVerified, &verifyToken, &verifyExpires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	u.VerifyToken = verifyToken.String
	u.VerifyExpires = verifyExpires.Time
	return u, err
}

// MarkEmailVerified marks userID as verified and clears any pending token.
func (s *Store) MarkEmailVerified(userID string) error {
	_, err := s.db.Exec(
		`UPDATE users SET email_verified=1, verify_token=NULL, verify_expires=NULL WHERE id=?`,
		userID,
	)
	return err
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

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(
		`SELECT id, email, created_at, email_verified FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.EmailVerified); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) UpdateUserEmail(id, email string) error {
	_, err := s.db.Exec(`UPDATE users SET email=? WHERE id=?`, email, id)
	return err
}

func (s *Store) UpdateUserPassword(id, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, passwordHash, id)
	return err
}

func (s *Store) DeleteUser(id string) error {
	s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	s.db.Exec(`UPDATE rules SET user_id='' WHERE user_id=?`, id)
	s.db.Exec(`UPDATE rebind_rules SET user_id='' WHERE user_id=?`, id)
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}
