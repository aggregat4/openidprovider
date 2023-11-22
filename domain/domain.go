package domain

type ClientId = string

type Client struct {
	Id           ClientId
	RedirectUris []string
	Secret       string
}

type Configuration struct {
	ServerReadTimeoutSeconds  int
	ServerWriteTimeoutSeconds int
	ServerPort                int
	RegisteredClients         map[ClientId]Client
}

// No support for "nonce", "display", "prompt", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values" yet
type OidcAuthenticationRequest struct {
	Scopes       []string
	ResponseType string
	ClientId     string
	RedirectUri  string
	State        string
}
