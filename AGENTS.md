# Commands
- Build: `./scripts/build.sh`
- Lint: `./scripts/lint.sh`
- Test: `./scripts/test.sh`
- Single test: `go test -run TestName ./path/to/package`

# Style
- Use standard Go formatting (`gofmt`)
- Imports: stdlib → third-party → local (separated by blank lines)
- Error handling: `if err != nil { return fmt.Errorf("context: %w", err) }`
- Naming: CamelCase for exports, camelCase for internals
- Context: Always pass context as first parameter
- HTTP handlers: `func(w http.ResponseWriter, r *http.Request)`
- Tests: `TestXxx(t *testing.T)` with table-driven tests
- CSS: Use custom properties for colors, CSS nesting enabled