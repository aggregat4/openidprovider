package main

import (
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/pkg/crypto"
	"flag"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	const dbName = "openidprovider"

	var initdbPassword string
	flag.StringVar(&initdbPassword, "password", "", "Initializes the database with a user with this password")
	var initdbUsername string
	flag.StringVar(&initdbUsername, "username", "", "Initializes the database with a user with this username")
	flag.Parse()

	if initdbPassword != "" && initdbUsername != "" {
		var store repository.Store
		err := store.InitAndVerifyDb(repository.CreateFileDbUrl(dbName))
		if err != nil {
			log.Fatalf("Error initializing database: %s", err)
		}
		defer store.Close()
		hashedPassword, err := crypto.HashPassword(initdbPassword)
		if err != nil {
			log.Fatalf("Error hashing password: %s", err)
		}
		err = store.CreateUser(initdbUsername, hashedPassword)
		if err != nil {
			log.Fatalf("Error initializing database: %s", err)
		}
	} else {
		log.Fatalf("Require a username and password to initialize a database with a valid user")
	}
}
