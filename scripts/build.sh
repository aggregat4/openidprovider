#!/bin/bash

go build -o bin/createuser cmd/createuser/main.go
go build -o bin/createkey cmd/createkey/main.go
go build -o bin/server cmd/server/main.go
