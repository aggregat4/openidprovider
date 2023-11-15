package main

import (
	"aggregat4/openidprovider/crypto"
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/schema"
	"aggregat4/openidprovider/server"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/kirsle/configdir"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func main() {
	const dbName = "openidprovider"

	var initdbPassword string
	flag.StringVar(&initdbPassword, "initdb-pass", "", "Initializes the database with a user with this password, contents must be bcrypt encoded")
	var initdbUsername string
	flag.StringVar(&initdbUsername, "initdb-username", "", "Initializes the database with a user with this username")

	var passwordToHash string
	flag.StringVar(&passwordToHash, "passwordtohash", "", "A password that should be hashed and salted and the output sent to stdout")

	flag.Parse()

	if passwordToHash != "" {
		hash, err := crypto.HashPassword(passwordToHash)
		if err != nil {
			log.Fatalf("Error hashing password: %s", err)
		}
		fmt.Println(hash)
	} else if initdbPassword != "" && initdbUsername != "" {
		err := schema.InitDatabaseWithUser(dbName, initdbUsername, initdbPassword)
		if err != nil {
			log.Fatalf("Error initializing database: %s", err)
		}
	} else {
		err := godotenv.Load()
		if err != nil {
			log.Fatalf("error loading .env file: %s", err)
		}

		registeredClients := readRegisteredClients()

		server.RunServer(dbName, domain.Configuration{
			ServerReadTimeoutSeconds:  getIntFromEnv("OPENIDPROVIDER_SERVER_READ_TIMEOUT_SECONDS", 5),
			ServerWriteTimeoutSeconds: getIntFromEnv("OPENIDPROVIDER_SERVER_WRITE_TIMEOUT_SECONDS", 10),
			ServerPort:                getIntFromEnv("OPENIDPROVIDER_SERVER_PORT", 1323),
			RegisteredClients:         registeredClients,
		})
	}
}

func readRegisteredClients() map[string][]string {
	var k = koanf.New(".")
	if err := k.Load(file.Provider(configdir.LocalConfig("openidprovider")+"/openidprovider.json"), json.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}
	configuredClients := k.Get("registeredclients")
	clients, ok := configuredClients.([]map[string]interface{})
	if !ok {
		log.Fatalf("registeredclients is not an array of objects")
	}
	registeredClients := make(map[domain.ClientId][]domain.ClientRedirectUri)
	for _, client := range clients {
		clientId, ok := client["id"].(string)
		if !ok {
			log.Fatalf("client id is not a string")
		}
		redirectUris, ok := client["redirecturis"].([]string)
		if !ok {
			log.Fatalf("redirect uris is not an array of strings")
		}
		registeredClients[domain.ClientId(clientId)] = redirectUris
	}
	return registeredClients
}

func requireStringFromEnv(s string) string {
	value := os.Getenv(s)
	if value == "" {
		panic(fmt.Errorf("env variable %s is required", s))
	}
	return value
}

func getIntFromEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Errorf("error parsing env variable %s: %s", key, err))
	}
	return intValue
}

func getStringFromEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
