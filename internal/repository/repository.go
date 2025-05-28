package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aggregat4/go-baselib/migrations"
)

var mymigrations = []migrations.Migration{
	{
		SequenceId: 1,
		Sql: `
		-- Enable WAL mode on the database to allow for concurrent reads and writes
		PRAGMA journal_mode=WAL;
		PRAGMA foreign_keys = ON;

		CREATE TABLE IF NOT EXISTS users (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			last_updated INTEGER NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS codes (
			code TEXT NOT NULL PRIMARY KEY,
			username TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			created INTEGER NOT NULL,
			FOREIGN KEY (username) REFERENCES users(username)
		);
		`,
	},
	{
		SequenceId: 2,
		Sql: `
		-- Disable foreign keys temporarily for the migration
		PRAGMA foreign_keys = OFF;

		-- Rename columns in users table
		ALTER TABLE users RENAME COLUMN username TO email;

		-- Rename columns in codes table
		ALTER TABLE codes RENAME COLUMN username TO email;

		-- Re-enable foreign keys
		PRAGMA foreign_keys = ON;
		`,
	},
	{
		SequenceId: 3,
		Sql: `
		-- Add verification status to users table and create verification tokens table
		ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0;

		CREATE TABLE IF NOT EXISTS verification_tokens (
			token TEXT NOT NULL PRIMARY KEY,
			email TEXT NOT NULL,
			type TEXT NOT NULL, -- 'registration', 'password_reset', 'account_deletion'
			created INTEGER NOT NULL,
			expires INTEGER NOT NULL,
			FOREIGN KEY (email) REFERENCES users(email)
		);

		-- Index for cleanup of expired tokens
		CREATE INDEX idx_verification_tokens_expires ON verification_tokens(expires);
		`,
	},
	{
		SequenceId: 4,
		Sql: `
		-- Create tables for scopes and claims
		CREATE TABLE IF NOT EXISTS scopes (
			scope_name TEXT NOT NULL PRIMARY KEY,
			description TEXT,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS scope_claims (
			scope_name TEXT NOT NULL,
			claim_name TEXT NOT NULL,
			description TEXT,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (scope_name, claim_name),
			FOREIGN KEY (scope_name) REFERENCES scopes(scope_name)
		);

		CREATE TABLE IF NOT EXISTS user_claims (
			user_id INTEGER NOT NULL,
			claim_name TEXT NOT NULL,
			claim_value TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, claim_name),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		-- Add scopes column to codes table to store requested scopes
		ALTER TABLE codes ADD COLUMN scopes TEXT NOT NULL DEFAULT 'openid';

		-- Insert default scopes
		INSERT OR IGNORE INTO scopes (scope_name, description, created_at) VALUES
			('openid', 'OpenID Connect scope', unixepoch()),
			('profile', 'Profile information scope', unixepoch()),
			('email', 'Email information scope', unixepoch());

		-- Insert default claims for standard scopes
		INSERT OR IGNORE INTO scope_claims (scope_name, claim_name, description, created_at) VALUES
			('openid', 'sub', 'Subject identifier', unixepoch()),
			('openid', 'iss', 'Issuer identifier', unixepoch()),
			('openid', 'aud', 'Audience identifier', unixepoch()),
			('openid', 'exp', 'Expiration time', unixepoch()),
			('openid', 'iat', 'Issued at time', unixepoch()),
			('profile', 'name', 'Full name', unixepoch()),
			('profile', 'family_name', 'Family name', unixepoch()),
			('profile', 'given_name', 'Given name', unixepoch()),
			('profile', 'middle_name', 'Middle name', unixepoch()),
			('profile', 'nickname', 'Nickname', unixepoch()),
			('profile', 'preferred_username', 'Preferred username', unixepoch()),
			('profile', 'picture', 'Profile picture URL', unixepoch()),
			('profile', 'website', 'Website URL', unixepoch()),
			('profile', 'gender', 'Gender', unixepoch()),
			('profile', 'birthdate', 'Birth date', unixepoch()),
			('profile', 'zoneinfo', 'Time zone', unixepoch()),
			('profile', 'locale', 'Locale', unixepoch()),
			('profile', 'updated_at', 'Last updated timestamp', unixepoch()),
			('email', 'email', 'Email address', unixepoch()),
			('email', 'email_verified', 'Email verification status', unixepoch());
		`,
	},
	{
		SequenceId: 5,
		Sql: `
		-- Create email tracking table for rate limiting and abuse prevention
		CREATE TABLE IF NOT EXISTS email_tracking (
			email TEXT NOT NULL,
			type TEXT NOT NULL,
			first_attempt INTEGER NOT NULL,
			last_attempt INTEGER NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			blocked INTEGER NOT NULL DEFAULT 0,
			blocked_at INTEGER,
			PRIMARY KEY (email, type)
		);

		-- Create index for cleanup of expired tracking records
		CREATE INDEX idx_email_tracking_first_attempt ON email_tracking(first_attempt);
		-- Create index for cleanup of expired blocks
		CREATE INDEX idx_email_tracking_blocked_at ON email_tracking(blocked_at);
		`,
	},
}

type Store struct {
	db *sql.DB
}

type User struct {
	Id          int64
	Email       string
	Password    string
	LastUpdated int64
	Verified    bool
}

type Code struct {
	Code        string
	Email       string
	ClientId    string
	RedirectUri string
	Created     int64
	Scopes      string // Space-separated list of scopes
}

type VerificationToken struct {
	Token   string
	Email   string
	Type    string
	Created int64
	Expires int64
}

// Add new types for scopes and claims
type Scope struct {
	Name        string
	Description string
	CreatedAt   int64
}

type ScopeClaim struct {
	ScopeName   string
	ClaimName   string
	Description string
	CreatedAt   int64
}

type UserClaim struct {
	UserId    int64
	ClaimName string
	Value     string
	CreatedAt int64
}

type EmailTracking struct {
	Email        string
	Type         string
	FirstAttempt int64
	LastAttempt  int64
	Attempts     int
	Blocked      bool
	BlockedAt    int64
}

func CreateFileDbUrl(dbName string) string {
	return fmt.Sprintf("file:%s.sqlite", dbName)
}

func CreateInMemoryDbUrl() string {
	return ":memory:"
}

func (store *Store) InitAndVerifyDb(dbUrl string) error {
	var err error
	store.db, err = sql.Open("sqlite3", dbUrl)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	return migrations.MigrateSchema(store.db, mymigrations)
}

func (store *Store) CreateUser(email, hashedPassword string) error {
	rows, err := store.db.Query("SELECT password FROM users WHERE email = ?", email)
	if err != nil {
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var password string
		err = rows.Scan(&password)

		if err != nil {
			return err
		}

		if hashedPassword != password {
			return errors.New("the database already has this account but with a different password")
		}
	} else {
		_, err := store.db.Exec("INSERT INTO users (email, password, last_updated) VALUES (?, ?, ?)",
			email, hashedPassword, time.Now().Unix())
		if err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) FindCode(code string) (*Code, error) {
	rows, err := store.db.Query("SELECT email, client_id, redirect_uri, created, scopes FROM codes WHERE code = ?", code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var email string
		var clientId string
		var redirectUri string
		var created int64
		var scopes string
		err = rows.Scan(&email, &clientId, &redirectUri, &created, &scopes)
		if err != nil {
			return nil, err
		}
		return &Code{code, email, clientId, redirectUri, created, scopes}, nil
	}
	return nil, nil
}

func (store *Store) DeleteCode(code string) error {
	_, err := store.db.Exec("DELETE FROM codes WHERE code = ?", code)
	return err
}

func (store *Store) SaveCode(code Code) error {
	_, err := store.db.Exec("INSERT INTO codes (code, email, client_id, redirect_uri, created, scopes) VALUES (?, ?, ?, ?, ?, ?)", code.Code, code.Email, code.ClientId, code.RedirectUri, code.Created, code.Scopes)
	return err
}

func (store *Store) FindUser(email string) (*User, error) {
	rows, err := store.db.Query("SELECT id, email, password, last_updated, is_verified FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var id int64
		var userEmail string
		var password string
		var lastUpdated int64
		var isVerified bool
		err = rows.Scan(&id, &userEmail, &password, &lastUpdated, &isVerified)
		if err != nil {
			return nil, err
		}
		return &User{id, userEmail, password, lastUpdated, isVerified}, nil
	}
	return nil, nil
}

func (store *Store) CreateVerificationToken(token VerificationToken) error {
	_, err := store.db.Exec(
		"INSERT INTO verification_tokens (token, email, type, created, expires) VALUES (?, ?, ?, ?, ?)",
		token.Token, token.Email, token.Type, token.Created, token.Expires,
	)
	return err
}

func (store *Store) FindVerificationToken(token string) (*VerificationToken, error) {
	rows, err := store.db.Query(
		"SELECT token, email, type, created, expires FROM verification_tokens WHERE token = ?",
		token,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var vt VerificationToken
		err = rows.Scan(&vt.Token, &vt.Email, &vt.Type, &vt.Created, &vt.Expires)
		if err != nil {
			return nil, err
		}
		return &vt, nil
	}
	return nil, nil
}

func (store *Store) FindVerificationTokenByEmail(email string) ([]*VerificationToken, error) {
	rows, err := store.db.Query(
		"SELECT token, email, type, created, expires FROM verification_tokens WHERE email = ?",
		email,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*VerificationToken
	for rows.Next() {
		var vt VerificationToken
		err = rows.Scan(&vt.Token, &vt.Email, &vt.Type, &vt.Created, &vt.Expires)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, &vt)
	}
	return tokens, nil
}

func (store *Store) DeleteVerificationToken(token string) error {
	_, err := store.db.Exec("DELETE FROM verification_tokens WHERE token = ?", token)
	return err
}

func (store *Store) DeleteExpiredVerificationTokens() error {
	_, err := store.db.Exec("DELETE FROM verification_tokens WHERE expires < ?", time.Now().Unix())
	return err
}

func (store *Store) DeleteUnverifiedUsers(maxAge time.Duration) error {
	// First delete verification tokens for unverified users
	_, err := store.db.Exec(`
		DELETE FROM verification_tokens 
		WHERE email IN (
			SELECT email FROM users 
			WHERE is_verified = 0 
			AND last_updated < ?
		)`, time.Now().Add(-maxAge).Unix())
	if err != nil {
		return err
	}

	// Then delete the unverified users
	_, err = store.db.Exec(`
		DELETE FROM users 
		WHERE is_verified = 0 
		AND last_updated < ?`, time.Now().Add(-maxAge).Unix())
	return err
}

func (store *Store) VerifyUser(email string) error {
	_, err := store.db.Exec("UPDATE users SET is_verified = 1 WHERE email = ?", email)
	return err
}

func (store *Store) IsUserVerified(email string) (bool, error) {
	rows, err := store.db.Query("SELECT is_verified FROM users WHERE email = ?", email)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if rows.Next() {
		var isVerified int
		err = rows.Scan(&isVerified)
		if err != nil {
			return false, err
		}
		return isVerified == 1, nil
	}
	return false, nil
}

func (store *Store) UpdateUserPassword(email, hashedPassword string) error {
	_, err := store.db.Exec("UPDATE users SET password = ?, last_updated = ? WHERE email = ?",
		hashedPassword, time.Now().Unix(), email)
	return err
}

func (store *Store) Close() error {
	return store.db.Close()
}

// Used in tests only!
func (store *Store) UpdateLastUpdated(email string, lastUpdated int64) error {
	_, err := store.db.Exec("UPDATE users SET last_updated = ? WHERE email = ?", lastUpdated, email)
	return err
}

func (store *Store) DeleteUser(email string) error {
	// Start a transaction to ensure all related data is deleted atomically
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete verification tokens
	_, err = tx.Exec("DELETE FROM verification_tokens WHERE email = ?", email)
	if err != nil {
		return err
	}

	// Delete authorization codes
	_, err = tx.Exec("DELETE FROM codes WHERE email = ?", email)
	if err != nil {
		return err
	}

	// Delete the user
	_, err = tx.Exec("DELETE FROM users WHERE email = ?", email)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// Scope Management Methods
func (store *Store) CreateScope(scope Scope) error {
	_, err := store.db.Exec(
		"INSERT INTO scopes (scope_name, description, created_at) VALUES (?, ?, ?)",
		scope.Name, scope.Description, scope.CreatedAt,
	)
	return err
}

func (store *Store) DeleteScope(scopeName string) error {
	_, err := store.db.Exec("DELETE FROM scopes WHERE scope_name = ?", scopeName)
	return err
}

func (store *Store) ListScopes() ([]Scope, error) {
	rows, err := store.db.Query("SELECT scope_name, description, created_at FROM scopes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []Scope
	for rows.Next() {
		var scope Scope
		err = rows.Scan(&scope.Name, &scope.Description, &scope.CreatedAt)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func (store *Store) GetScope(scopeName string) (*Scope, error) {
	rows, err := store.db.Query("SELECT scope_name, description, created_at FROM scopes WHERE scope_name = ?", scopeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var scope Scope
		err = rows.Scan(&scope.Name, &scope.Description, &scope.CreatedAt)
		if err != nil {
			return nil, err
		}
		return &scope, nil
	}
	return nil, nil
}

// Scope Claims Management Methods
func (store *Store) AddClaimToScope(claim ScopeClaim) error {
	_, err := store.db.Exec(
		"INSERT INTO scope_claims (scope_name, claim_name, description, created_at) VALUES (?, ?, ?, ?)",
		claim.ScopeName, claim.ClaimName, claim.Description, claim.CreatedAt,
	)
	return err
}

func (store *Store) RemoveClaimFromScope(scopeName, claimName string) error {
	_, err := store.db.Exec("DELETE FROM scope_claims WHERE scope_name = ? AND claim_name = ?", scopeName, claimName)
	return err
}

func (store *Store) ListScopeClaims(scopeName string) ([]ScopeClaim, error) {
	rows, err := store.db.Query(
		"SELECT scope_name, claim_name, description, created_at FROM scope_claims WHERE scope_name = ?",
		scopeName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []ScopeClaim
	for rows.Next() {
		var claim ScopeClaim
		err = rows.Scan(&claim.ScopeName, &claim.ClaimName, &claim.Description, &claim.CreatedAt)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

// User Claims Management Methods
func (store *Store) SetUserClaim(claim UserClaim) error {
	_, err := store.db.Exec(
		"INSERT OR REPLACE INTO user_claims (user_id, claim_name, claim_value, created_at) VALUES (?, ?, ?, ?)",
		claim.UserId, claim.ClaimName, claim.Value, claim.CreatedAt,
	)
	return err
}

func (store *Store) RemoveUserClaim(userId int64, claimName string) error {
	_, err := store.db.Exec("DELETE FROM user_claims WHERE user_id = ? AND claim_name = ?", userId, claimName)
	return err
}

func (store *Store) GetUserClaims(userId int64) ([]UserClaim, error) {
	rows, err := store.db.Query(
		"SELECT user_id, claim_name, claim_value, created_at FROM user_claims WHERE user_id = ?",
		userId,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []UserClaim
	for rows.Next() {
		var claim UserClaim
		err = rows.Scan(&claim.UserId, &claim.ClaimName, &claim.Value, &claim.CreatedAt)
		if err != nil {
			return nil, err
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

func (store *Store) GetUserClaim(userId int64, claimName string) (*UserClaim, error) {
	rows, err := store.db.Query(
		"SELECT user_id, claim_name, claim_value, created_at FROM user_claims WHERE user_id = ? AND claim_name = ?",
		userId, claimName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var claim UserClaim
		err = rows.Scan(&claim.UserId, &claim.ClaimName, &claim.Value, &claim.CreatedAt)
		if err != nil {
			return nil, err
		}
		return &claim, nil
	}
	return nil, nil
}

// Helper method to get all claims for a user based on requested scopes
func (store *Store) GetUserClaimsForScopes(userId int64, scopes []string) ([]UserClaim, error) {
	// First get all claims associated with the requested scopes
	scopeClaims := make(map[string]bool)
	for _, scope := range scopes {
		claims, err := store.ListScopeClaims(scope)
		if err != nil {
			return nil, err
		}
		for _, claim := range claims {
			scopeClaims[claim.ClaimName] = true
		}
	}

	// Then get all user claims
	allClaims, err := store.GetUserClaims(userId)
	if err != nil {
		return nil, err
	}

	// Filter claims to only include those associated with requested scopes
	var filteredClaims []UserClaim
	for _, claim := range allClaims {
		if scopeClaims[claim.ClaimName] {
			filteredClaims = append(filteredClaims, claim)
		}
	}

	return filteredClaims, nil
}

// ScopeExists checks if a scope exists in the database
func (store *Store) ScopeExists(scopeName string) (bool, error) {
	var count int
	err := store.db.QueryRow("SELECT COUNT(*) FROM scopes WHERE scope_name = ?", scopeName).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (store *Store) TrackEmailAttempt(email, emailType string) error {
	now := time.Now().Unix()

	_, err := store.db.Exec(`
		INSERT INTO email_tracking (email, type, first_attempt, last_attempt, attempts)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(email, type) DO UPDATE SET
			last_attempt = ?,
			attempts = attempts + 1
	`, email, emailType, now, now, now)
	return err
}

func (store *Store) GetEmailTracking(email, emailType string) (*EmailTracking, error) {
	rows, err := store.db.Query(`
		SELECT email, type, first_attempt, last_attempt, attempts, blocked, blocked_at
		FROM email_tracking
		WHERE email = ? AND type = ?
	`, email, emailType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var et EmailTracking
		var blocked int
		err = rows.Scan(&et.Email, &et.Type, &et.FirstAttempt, &et.LastAttempt, &et.Attempts, &blocked, &et.BlockedAt)
		if err != nil {
			return nil, err
		}
		et.Blocked = blocked == 1
		return &et, nil
	}
	return nil, nil
}

func (store *Store) BlockEmailAddress(email, emailType string, blockUntil time.Time) error {
	_, err := store.db.Exec(`
		UPDATE email_tracking
		SET blocked = 1, blocked_at = ?
		WHERE email = ? AND type = ?
	`, time.Now().Unix(), email, emailType)
	return err
}

func (store *Store) GetEmailCounts(since time.Time) (map[string]int, error) {
	counts := make(map[string]int)
	sinceUnix := since.Unix()

	// Get count per email address
	rows, err := store.db.Query(`
		SELECT email, attempts
		FROM email_tracking
		WHERE first_attempt >= ?
	`, sinceUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var count int
		err = rows.Scan(&email, &count)
		if err != nil {
			return nil, err
		}
		counts[email] = count
	}

	return counts, nil
}

func (store *Store) CleanupExpiredEmailTracking() error {
	// First unblock addresses where the block period has expired
	_, err := store.db.Exec(`
		UPDATE email_tracking
		SET blocked = 0, blocked_at = NULL
		WHERE blocked = 1 AND blocked_at < ?
	`, time.Now().Unix())
	if err != nil {
		return err
	}

	// Then delete tracking records that are older than 24 hours AND are not blocked
	_, err = store.db.Exec(`
		DELETE FROM email_tracking
		WHERE first_attempt < ? AND blocked = 0
	`, time.Now().Add(-24*time.Hour).Unix())
	return err
}
