package migrations

import "database/sql"

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

func MigrateSchema(db *sql.DB, migrations []Migration) error {
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
