package main

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"aggregat4/openidprovider/pkg/lang"
	"flag"
	"log"

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
	server.RunServer(server.Controller{Store: &store, Config: readConfig(lang.IfElse(configFileLocation == "", defaultConfigLocation, configFileLocation))})
}

func readConfig(configFileLocation string) domain.Configuration {
	var k = koanf.New(".")
	if err := k.Load(file.Provider(configFileLocation), json.Parser()); err != nil {
		log.Fatalf("error loading config: %v", err)
	}
	serverReadTimeoutSeconds, ok := k.Get("serverreadtimeoutseconds").(int)
	if !ok {
		serverReadTimeoutSeconds = 5
	}
	serverWriteTimeoutSeconds, ok := k.Get("serverwritetimeoutseconds").(int)
	if !ok {
		serverWriteTimeoutSeconds = 10
	}
	serverPort, ok := k.Get("serverport").(int)
	if !ok {
		serverPort = 1323
	}

	configuredClients := k.Get("registeredclients")
	clients, ok := configuredClients.([]map[string]interface{})
	if !ok {
		log.Fatalf("registeredclients is not an array of objects")
	}
	registeredClients := make(map[domain.ClientId]domain.Client)
	for _, client := range clients {
		clientId, ok := client["id"].(string)
		if !ok {
			log.Fatalf("client id is not a string")
		}
		clientSecret, ok := client["secret"].(string)
		if !ok {
			log.Fatalf("client secret is not a string")
		}
		redirectUris, ok := client["redirecturis"].([]string)
		if !ok {
			log.Fatalf("redirect uris is not an array of strings")
		}
		registeredClients[domain.ClientId(clientId)] = domain.Client{
			Id:           domain.ClientId(clientId),
			RedirectUris: redirectUris,
			Secret:       clientSecret,
		}
	}
	configuredJwt := k.Get("jwt")
	jwt, ok := configuredJwt.(map[string]interface{})
	if !ok {
		log.Fatalf("jwt is not an object")
	}
	issuer, ok := jwt["issuer"].(string)
	if !ok {
		log.Fatalf("issuer is not a string")
	}
	idTokenValidityMinutes, ok := jwt["idtokenvalidityminutes"].(float64)
	if !ok {
		log.Fatalf("idtokenvalidityminutes is not a number")
	}
	jwtConfig := domain.JwtConfiguration{
		Issuer:                 issuer,
		IdTokenValidityMinutes: int(idTokenValidityMinutes),
	}
	return domain.Configuration{
		ServerReadTimeoutSeconds:  serverReadTimeoutSeconds,
		ServerWriteTimeoutSeconds: serverWriteTimeoutSeconds,
		ServerPort:                serverPort,
		RegisteredClients:         registeredClients,
		JwtConfig:                 jwtConfig,
	}
}
