#!/bin/bash

set -e

echo "Running tests"
go test ./...

echo "Checking race conditions"
go test -race ./... 

echo "Creating coverage report"
go test -coverprofile=coverage.out ./...
go tool cover -func coverage.out
go tool cover -html=coverage.out -o coverage.html

echo "Tests passed"
