package main

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"aggregat4/openidprovider/pkg/lang"
	"flag"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kirsle/configdir"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	const dbName = "openidprovider"

	var store repository.Store
	err := store.InitAndVerifyDb(repository.CreateFileDbUrl(dbName))
	if err != nil {
		log.Fatalf("Error initializing database: %s", err)
	}
	defer store.Close()

	var configFileLocation string
	flag.StringVar(&configFileLocation, "config", "", "The location of the configuration file if you do not want to default to the standard location")
	flag.Parse()

	defaultConfigLocation := configdir.LocalConfig("openidprovider") + "/openidprovider.json"
	server.RunServer(server.Controller{
		Store:  &store,
		Config: readConfig(lang.IfElse(configFileLocation == "", defaultConfigLocation, configFileLocation)),
	})
}

func readConfig(configFileLocation string) domain.Configuration {
	var k = koanf.New(".")
	if err := k.Load(file.Provider(configFileLocation), json.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}
	serverReadTimeoutSeconds := k.Int("serverreadtimeoutseconds")
	if serverReadTimeoutSeconds == 0 {
		serverReadTimeoutSeconds = 5
	}
	serverWriteTimeoutSeconds := k.Int("serverwritetimeoutseconds")
	if serverWriteTimeoutSeconds == 0 {
		serverWriteTimeoutSeconds = 10
	}
	serverPort := k.Int("serverport")
	if serverPort == 0 {
		serverPort = 1323
	}
	baseUrl := k.String("baseurl")
	if baseUrl == "" {
		log.Fatalf("Base URL is required in the configuration")
	}
	privateKeyPemFilename := k.String("privatekeypemfilename")
	if privateKeyPemFilename == "" {
		log.Fatalf("Private key filename is required in the configuration")
	}
	privateKeyFile, err := os.ReadFile(privateKeyPemFilename)
	if err != nil {
		log.Fatalf("Error reading private key file: %s", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		log.Fatalf("Error parsing private key: %s", err)
	}

	publicKeyPemFilename := k.String("publickeypemfilename")
	if publicKeyPemFilename == "" {
		log.Fatalf("Public key filename is required in the configuration")
	}
	publicKeyFile, err := os.ReadFile(publicKeyPemFilename)
	if err != nil {
		log.Fatalf("Error reading public key file: %s", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyFile)
	if err != nil {
		log.Fatalf("Error parsing public key: %s", err)
	}

	configuredClients := k.Get("registeredclients")
	// NOTE: I tried casting to `[]map[string]interface{}` but that did not work, even though that is the type
	// Apparently go does not have that information yet. Instead this is a generic object here and later in the
	// loop we cast the objects to a `map[string]interface{}`
	clients, ok := configuredClients.([]interface{})
	if !ok {
		log.Fatalf("registeredclients is not an array of objects")
	}
	registeredClients := make(map[domain.ClientId]domain.Client)
	for _, client := range clients {
		client, ok := client.(map[string]interface{})
		if !ok {
			log.Fatalf("client is not an object")
		}
		clientId := client["id"].(string)
		if !ok {
			log.Fatalf("client id is not a string")
		}
		// NOTE: again we can not cast to `[]string` yet, we do that later for each individual redirect uri
		redirectUris, ok := client["redirecturis"].([]interface{})
		if !ok {
			log.Fatalf("redirect uris is not an array")
		}
		redirectUrisString := make([]string, len(redirectUris))
		for i, uri := range redirectUris {
			uri, ok := uri.(string)
			if !ok {
				log.Fatalf("redirect uri is not a string")
			}
			redirectUrisString[i] = uri
		}
		basicAuthSecret, ok := client["basicauthsecret"].(string)
		if !ok {
			log.Fatalf("basic auth secret is not a string")
		}
		registeredClients[domain.ClientId(clientId)] = domain.Client{
			Id:              domain.ClientId(clientId),
			RedirectUris:    redirectUrisString,
			BasicAuthSecret: basicAuthSecret,
		}
	}
	idTokenValidityMinutes := k.MustInt("jwt.idtokenvalidityminutes")
	return domain.Configuration{
		ServerReadTimeoutSeconds:  serverReadTimeoutSeconds,
		ServerWriteTimeoutSeconds: serverWriteTimeoutSeconds,
		ServerPort:                serverPort,
		BaseUrl:                   baseUrl,
		RegisteredClients:         registeredClients,
		JwtConfig: domain.JwtConfiguration{
			Issuer:                 baseUrl,
			IdTokenValidityMinutes: int(idTokenValidityMinutes),
			PrivateKey:             privateKey,
			PublicKey:              publicKey,
		},
	}
}
