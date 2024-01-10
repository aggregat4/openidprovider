#!/bin/bash

go build -o bin/createuser cmd/createuser/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/createuser-prod cmd/createuser/main.go

go build -o bin/server cmd/server/main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/server-prod cmd/server/main.go
