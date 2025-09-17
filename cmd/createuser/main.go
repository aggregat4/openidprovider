package main

import (
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"flag"

	"github.com/aggregat4/go-baselib/crypto"

	_ "github.com/mattn/go-sqlite3"
)

var logger = logging.ForComponent("cmd.createuser")

func main() {
	var dbName string
	flag.StringVar(&dbName, "db", "", "Database name (required)")
	var initdbPassword string
	flag.StringVar(&initdbPassword, "password", "", "Initializes the database with a user with this password")
	var initdbUsername string
	flag.StringVar(&initdbUsername, "username", "", "Initializes the database with a user with this username")
	flag.Parse()

	if dbName == "" {
		logging.Fatal(logger, "Database name is required. Use -db flag to specify it")
	}

	if initdbPassword != "" && initdbUsername != "" {
		var store repository.Store
		err := store.InitAndVerifyDb(repository.CreateFileDbUrl(dbName))
		if err != nil {
			logging.Fatal(logger, "Error initializing database: {Error}", err)
		}
		defer store.Close()
		hashedPassword, err := crypto.HashPassword(initdbPassword)
		if err != nil {
			logging.Fatal(logger, "Error hashing password: {Error}", err)
		}
		err = store.CreateUser(initdbUsername, hashedPassword)
		if err != nil {
			logging.Fatal(logger, "Error initializing database: {Error}", err)
		}
		err = store.VerifyUser(initdbUsername)
		if err != nil {
			logging.Fatal(logger, "Error verifying user: {Error}", err)
		}
	} else {
		logging.Fatal(logger, "Require a username and password to initialize a database with a valid user")
	}
}
