# Repository Guidelines

## Project Structure & Module Organization

The Go module is anchored at the repository root with dependencies tracked in `go.mod`. Runtime entrypoints live in `cmd/`, providing binaries for the OAuth server (`cmd/server`) and support tools (`cmd/createuser`, `cmd/createkey`, `cmd/cleanup`, `cmd/testemail`). Core logic resides under `internal/`: `internal/server` handles HTTP flows, `internal/domain` defines identities and tokens, `internal/repository` wraps SQLite persistence, while `internal/config` reads configuration. Shared packages that may be imported by auxiliary tools sit in `pkg/` (currently `pkg/email`). Samples and launcher scripts in `demo/` demonstrate workable configurations; `example-config.jsonc` is your template for new deployments.

## Build, Test, and Development Commands

- `./scripts/build.sh` compiles all binaries into `bin/`.
- `go run cmd/server/main.go --config example-config.jsonc` starts the provider with the sample configuration.
- `./scripts/test.sh` runs the standard unit test suite (`go test ./...`) and exits on the first failure.
- `./scripts/lint.sh` expects `golangci-lint` on `PATH` and applies the repository lint rules.

## Coding Style & Naming Conventions

Follow idiomatic Go: run `gofmt` (or `goimports`) on every change; default to tabs in Go files. Keep package names short and lowercase; exported symbols should use PascalCase. Configuration examples use JSONC—preserve trailing comments and camelCase keys. Prefer explicit contexts in new APIs and keep SQL statements centralized in `internal/repository`.

## Testing Guidelines

Unit tests belong alongside the code under test with the `_test.go` suffix. Favor table-driven tests and cover edge cases around token expiry and repository errors. Aim for the coverage level maintained by `go test ./... -cover`; uncomment the coverage lines in `scripts/test.sh` when validating larger changes. Use the SQLite demo database in `demo/` only for manual verification, not during automated tests.

## Commit & Pull Request Guidelines

Commits in this project are concise, imperative statements (e.g., `Remove spurious commands`). Group related changes together and include configuration or migration updates in the same commit. Pull requests should describe behavior changes, reference related issues, and mention how you validated the change (tests run, manual scenarios). Attach screenshots or logs when altering login or consent flows.

## Frontend Code

Try to use custom properties in css for colors and other design tokens that are reused.
Use CSS nesting when writing styles.
