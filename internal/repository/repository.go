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
}

type VerificationToken struct {
	Token   string
	Email   string
	Type    string
	Created int64
	Expires int64
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
		return err
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
	rows, err := store.db.Query("SELECT email, client_id, redirect_uri, created FROM codes WHERE code = ?", code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var email string
		var clientId string
		var redirectUri string
		var created int64
		err = rows.Scan(&email, &clientId, &redirectUri, &created)
		if err != nil {
			return nil, err
		}
		return &Code{code, email, clientId, redirectUri, created}, nil
	}
	return nil, nil
}

func (store *Store) DeleteCode(code string) error {
	_, err := store.db.Exec("DELETE FROM codes WHERE code = ?", code)
	return err
}

func (store *Store) SaveCode(code Code) error {
	_, err := store.db.Exec("INSERT INTO codes (code, email, client_id, redirect_uri, created) VALUES (?, ?, ?, ?, ?)", code.Code, code.Email, code.ClientId, code.RedirectUri, code.Created)
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

func (store *Store) DeleteVerificationToken(token string) error {
	_, err := store.db.Exec("DELETE FROM verification_tokens WHERE token = ?", token)
	return err
}

func (store *Store) DeleteExpiredVerificationTokens() error {
	_, err := store.db.Exec("DELETE FROM verification_tokens WHERE expires < ?", time.Now().Unix())
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

func (store *Store) Close() error {
	return store.db.Close()
}
