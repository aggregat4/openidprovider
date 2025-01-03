module aggregat4/openidprovider

go 1.23

toolchain go1.23.4

require github.com/aggregat4/go-baselib v1.4.0

//replace github.com/aggregat4/go-baselib => ../go-baselib

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/gorilla/sessions v1.4.0
	github.com/kirsle/configdir v0.0.0-20170128060238-e45d2f54772f
	github.com/knadh/koanf/parsers/json v0.1.0
	github.com/knadh/koanf/providers/file v1.1.2
	github.com/knadh/koanf/v2 v2.1.2
	github.com/labstack/echo-contrib v0.17.2
	github.com/labstack/echo/v4 v4.13.3
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
)

require (
	github.com/google/uuid v1.6.0
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
