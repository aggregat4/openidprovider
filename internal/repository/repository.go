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
}

type Store struct {
	db *sql.DB
}

type User struct {
	Id          int64
	Email       string
	Password    string
	LastUpdated int64
}

type Code struct {
	Code        string
	Email       string
	ClientId    string
	RedirectUri string
	Created     int64
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
	rows, err := store.db.Query("SELECT id, email, password, last_updated FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var id int64
		var userEmail string
		var password string
		var lastUpdated int64
		err = rows.Scan(&id, &userEmail, &password, &lastUpdated)
		if err != nil {
			return nil, err
		}
		return &User{id, email, password, lastUpdated}, nil
	}
	return nil, nil
}

func (store *Store) Close() error {
	return store.db.Close()
}
