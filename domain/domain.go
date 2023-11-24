package domain

type ClientId = string

type Client struct {
	Id           ClientId
	RedirectUris []string
	Secret       string
}

type JwtConfiguration struct {
	Issuer                 string
	IdTokenValidityMinutes int
}

type Configuration struct {
	ServerReadTimeoutSeconds  int
	ServerWriteTimeoutSeconds int
	ServerPort                int
	RegisteredClients         map[ClientId]Client
	JwtConfig                 JwtConfiguration
}
