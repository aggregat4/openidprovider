package schema

import (
	"database/sql"
	"errors"
	"fmt"
)

func createDbUrl(dbName string) string {
	return fmt.Sprintf("file:%s.sqlite?_foreign_keys=on", dbName)
}

func InitAndVerifyDb(dbName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", createDbUrl(dbName))
	if err != nil {
		return nil, err
	}

	err = MigrateSchema(db)

	return db, err
}

func InitDatabaseWithUser(dbName string, initdbUsername, initdbPassword string) error {
	db, err := sql.Open("sqlite3", createDbUrl(dbName))
	if err != nil {
		return err
	}

	defer db.Close()

	MigrateSchema(db)

	rows, err := db.Query("SELECT password FROM users WHERE id = 1 AND username = ?", initdbUsername)
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

		if initdbPassword != password {
			return errors.New("the database already has this account but with a different password")
		}
	} else {
		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", initdbUsername, initdbPassword)
		if err != nil {
			return err
		}
	}
	return nil
}

func initMigrationTable(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS migrations (sequence_id INTEGER NOT NULL PRIMARY KEY)")
	return err
}

func existsMigrationTable(db *sql.DB) (bool, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='migrations'")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

func getAppliedMigrations(db *sql.DB) ([]int, error) {
	rows, err := db.Query("SELECT sequence_id FROM migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var migrations []int
	for rows.Next() {
		var sequenceId int
		err = rows.Scan(&sequenceId)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, sequenceId)
	}
	return migrations, nil
}

type Migration struct {
	SequenceId int
	Sql        string
}

var migrations = []Migration{
	{1,
		`
		-- Enable WAL mode on the database to allow for concurrent reads and writes
		PRAGMA journal_mode=WAL;

		CREATE TABLE IF NOT EXISTS users (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			last_update INTEGER NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS codes (
			id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			code TEXT NOT NULL,
			username TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			created INTEGER NOT NULL
		);
		`,
	},
}

func MigrateSchema(db *sql.DB) error {
	println("Migrating schema")
	exists, err := existsMigrationTable(db)
	if err != nil {
		return err
	}
	if !exists {
		err = initMigrationTable(db)
		if err != nil {
			return err
		}
	}
	appliedMigrations, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		if !contains(appliedMigrations, migration.SequenceId) {
			println("Executing migration ", migration.SequenceId)
			_, err = db.Exec(migration.Sql)
			if err != nil {
				return err
			}
			_, err = db.Exec("INSERT INTO migrations (sequence_id) VALUES (?)", migration.SequenceId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func contains(list []int, item int) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}
