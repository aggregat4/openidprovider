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

	"github.com/gurkankaymak/hocon"
	"github.com/joho/godotenv"
	"github.com/kirsle/configdir"
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
			panic(err)
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
			panic(fmt.Errorf("error loading .env file: %s", err))
		}
		conf, err := hocon.ParseResource(configdir.LocalConfig("openidprovider") + "/openidprovider.hocon")
		if err != nil {
			log.Fatal("error while parsing configuration: ", err)
		}
		configuredClients := conf.GetObject("registeredcliients")
		registeredClients := make(map[domain.ClientId][]domain.ClientRedirectUri)
		for client := range configuredClients {
			clientId := client
			redirectUris := make([]domain.ClientRedirectUri, 0, 1)
			// TODO: continue here, i do not know how to read a nested array using this library
			// maybe try koanf as a replacement?
			for redirectUri := range configuredClients[clientId]. {
				redirectUris = append(redirectUris, redirectUri.GetString())
			}
			registeredClients[domain.ClientId(clientId)] = redirectUris
		}

		server.RunServer(dbName, domain.Configuration{
			ServerReadTimeoutSeconds:  getIntFromEnv("OPENIDPROVIDER_SERVER_READ_TIMEOUT_SECONDS", 5),
			ServerWriteTimeoutSeconds: getIntFromEnv("OPENIDPROVIDER_SERVER_WRITE_TIMEOUT_SECONDS", 10),
			ServerPort:                getIntFromEnv("OPENIDPROVIDER_SERVER_PORT", 1323),
		})
	}
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
