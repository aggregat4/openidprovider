package repository

import (
	"aggregat4/openidprovider/pkg/migrations"
	"database/sql"
	"errors"
	"fmt"
	"time"
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
}

type Store struct {
	db *sql.DB
}

type User struct {
	Id          int64
	Username    string
	Password    string
	LastUpdated int64
}

type Code struct {
	Code        string
	UserName    string
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

func MigrateSchema(dB *sql.DB) {
	panic("unimplemented")
}

func (store *Store) CreateUser(username, hashedPassword string) error {
	rows, err := store.db.Query("SELECT password FROM users WHERE username = ?", username)
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
		_, err := store.db.Exec("INSERT INTO users (username, password, last_updated) VALUES (?, ?, ?)",
			username, hashedPassword, time.Now().Unix())
		if err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) FindCode(code string) (*Code, error) {
	rows, err := store.db.Query("SELECT username, client_id, redirect_uri, created FROM codes WHERE code = ?", code)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var userName string
		var clientId string
		var redirectUri string
		var created int64
		err = rows.Scan(&userName, &clientId, &redirectUri, &created)
		if err != nil {
			return nil, err
		}
		return &Code{code, userName, clientId, redirectUri, created}, nil
	}
	return nil, nil
}

func (store *Store) DeleteCode(code string) error {
	_, err := store.db.Exec("DELETE FROM codes WHERE code = ?", code)
	return err
}

func (store *Store) SaveCode(code Code) error {
	_, err := store.db.Exec("INSERT INTO codes (code, username, client_id, redirect_uri, created) VALUES (?, ?, ?, ?, ?)", code.Code, code.UserName, code.ClientId, code.RedirectUri, code.Created)
	return err
}

func (store *Store) FindUser(username string) (*User, error) {
	rows, err := store.db.Query("SELECT id, username, password, last_updated FROM users WHERE username = ?", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var id int64
		var userName string
		var password string
		var lastUpdated int64
		err = rows.Scan(&id, &userName, &password, &lastUpdated)
		if err != nil {
			return nil, err
		}
		return &User{id, username, password, lastUpdated}, nil
	}
	return nil, nil
}

func (store *Store) Close() error {
	return store.db.Close()
}
