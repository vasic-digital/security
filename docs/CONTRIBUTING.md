# Contributing to digital.vasic.security

## Getting Started

1. Clone the repository via SSH:
   ```bash
   git clone <ssh-url>
   cd Security
   ```

2. Ensure Go 1.24+ is installed:
   ```bash
   go version
   ```

3. Run the test suite to verify the setup:
   ```bash
   go test ./... -count=1 -race
   ```

## Development Workflow

### Branch Naming

Use conventional prefixes:
- `feat/` -- New feature (e.g., `feat/add-uuid-detector`)
- `fix/` -- Bug fix (e.g., `fix/phone-regex-false-positive`)
- `refactor/` -- Code restructuring (e.g., `refactor/extract-mask-strategies`)
- `test/` -- Test improvements (e.g., `test/add-concurrent-redactor-tests`)
- `docs/` -- Documentation (e.g., `docs/update-api-reference`)
- `chore/` -- Maintenance (e.g., `chore/update-testify`)

### Commit Messages

Follow Conventional Commits:

```
<type>(<scope>): <description>

feat(pii): add UUID detector with configurable formats
fix(guardrails): handle empty pattern map without error
test(policy): add concurrent evaluator stress test
docs(scanner): document CWE field usage in findings
```

### Code Quality Checks

Run these before every commit:

```bash
go fmt ./...          # Format code
go vet ./...          # Static analysis
go test ./... -race   # Tests with race detection
go test ./... -cover  # Verify coverage
```

## Code Style

### General Rules

- Follow standard Go conventions and [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` formatting (enforced by `go fmt`)
- Line length should not exceed 100 characters for readability
- Group imports: stdlib, third-party, internal (separated by blank lines)

### Naming Conventions

- **Private identifiers**: `camelCase` (e.g., `redactValue`, `maskStr`)
- **Exported identifiers**: `PascalCase` (e.g., `NewRedactor`, `FilterResult`)
- **Constants**: `PascalCase` for typed constants (e.g., `SeverityCritical`, `StrategyMask`)
- **Acronyms**: All-caps (e.g., `PII`, `SSN`, `CWE`, `IP`)
- **Receiver names**: 1-2 letters (e.g., `e` for Engine, `r` for Redactor, `f` for Filter)

### Error Handling

- Always check errors
- Wrap errors with context: `fmt.Errorf("description: %w", err)`
- Use `defer` for cleanup

### Interfaces

- Keep interfaces small and focused (1-2 methods)
- Accept interfaces, return structs
- Define interfaces in the package that consumes them

### Testing

- Use table-driven tests with descriptive test case names
- Use `testify/assert` for assertions and `testify/require` for prerequisites
- Test naming: `Test<Type>_<Method>_<Scenario>` (e.g., `TestEngine_Check_StopOnFirstFailure`)
- Test boundary conditions, empty inputs, and error paths
- Include concurrency tests for thread-safe types

## Adding a New Package

1. Create the directory: `pkg/<name>/`
2. Create the source file: `pkg/<name>/<name>.go`
3. Create the test file: `pkg/<name>/<name>_test.go`
4. The package must be self-contained -- no imports from other `pkg/` packages
5. Define a small, focused interface as the extension point
6. Provide at least one concrete implementation
7. Write table-driven tests covering all public API surface
8. Update documentation:
   - `README.md` -- Add package to the list
   - `AGENTS.md` -- Add package responsibilities and key file
   - `docs/API_REFERENCE.md` -- Document all exported types and functions
   - `docs/USER_GUIDE.md` -- Add usage examples
   - `docs/diagrams/architecture.mmd` -- Add to the diagram

## Adding a New Implementation to an Existing Package

For example, adding a new `Detector` to the `pii` package:

1. Add the implementation in the package source file
2. Add a constructor function following the pattern `func <Name>Detector() Detector`
3. If the type needs to be configurable, add a constructor that accepts configuration
4. Write table-driven tests covering normal and edge cases
5. Update `docs/API_REFERENCE.md` with the new type and constructor
6. Update `docs/USER_GUIDE.md` with usage examples

## Dependencies

This module intentionally has minimal dependencies:

- **Production code**: Only the Go standard library. No external dependencies allowed in production code.
- **Test code**: `github.com/stretchr/testify` for assertions.

Do not add new external dependencies without discussion. The module must remain lightweight and standalone.

## Module Independence

This module must never depend on the consuming project (`dev.helix.agent`) or any other application-specific module. It is designed to be a generic, reusable library. Integration with the consuming project happens in the consuming project's codebase, not here.

## Pull Request Checklist

Before submitting a pull request, verify:

- [ ] All tests pass: `go test ./... -count=1 -race`
- [ ] Code is formatted: `go fmt ./...`
- [ ] Static analysis passes: `go vet ./...`
- [ ] New code has test coverage
- [ ] Table-driven tests are used for new test cases
- [ ] Documentation is updated (API reference, user guide, diagrams)
- [ ] Commit messages follow Conventional Commits format
- [ ] No new external dependencies introduced without justification
- [ ] No cross-package imports within `pkg/`
