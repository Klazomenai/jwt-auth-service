# Contributing to JWT Auth Service

Thank you for your interest in contributing to the JWT Auth Service! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

- Go 1.22 or later
- Redis 7+ (or use embedded Redis for development)
- Make
- Git

### Development Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/klazomenai/jwt-auth-service.git
cd jwt-auth-service
```

2. Install dependencies:
```bash
make deps
```

3. Run tests to verify setup:
```bash
make test
```

4. Run the service locally:
```bash
export JWT_ISSUER=https://localhost
export JWT_AUDIENCE=test-api
go run cmd/server/main.go
```

## Development Workflow

### Making Changes

1. Create a feature branch from `main`:
```bash
git checkout -b feat/your-feature-name
```

2. Make your changes following the code style guidelines below

3. Add tests for new functionality

4. Run the test suite:
```bash
make test
make lint
```

5. Commit your changes using conventional commits (see below)

6. Push to your fork and create a pull request

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-verbose

# Run tests with HTML coverage report
make test-coverage

# Run linters
make lint
```

### Building

```bash
# Build binary
make build

# Build Docker image
make docker-build
```

## Code Style

### Go Conventions

- Follow standard Go code style and idioms
- Run `go fmt` before committing (or use `make fmt`)
- Run `go vet` to catch common mistakes (or use `make vet`)
- Keep functions small and focused
- Write clear, descriptive variable names
- Add comments for exported functions and types

### Test Coverage

- Aim for >70% test coverage for new code
- Write table-driven tests where appropriate
- Use subtests for clarity: `t.Run("test_case_name", func(t *testing.T) {...})`
- Mock external dependencies (Redis, HTTP calls)

### File Organization

- Place business logic in `pkg/` packages
- Keep `cmd/` minimal (initialization only)
- One package per directory
- Test files alongside source: `file.go` and `file_test.go`

## Commit Message Guidelines

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automated changelog generation and semantic versioning.

### Commit Message Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes only
- `style:` - Code style changes (formatting, no logic change)
- `refactor:` - Code restructuring (no feature or bug fix)
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks (dependencies, build, etc.)
- `ci:` - CI/CD pipeline changes
- `perf:` - Performance improvements
- `revert:` - Revert a previous commit

### Scope (Optional)

The scope should indicate the affected component:
- `auth` - JWT signing/validation
- `api` - HTTP handlers
- `storage` - Redis operations
- `renewal` - Auto-renewal worker
- `deps` - Dependency updates

### Breaking Changes

For breaking changes, add `!` after the type or include `BREAKING CHANGE:` in the footer:

```
feat!: remove HS256 algorithm support

BREAKING CHANGE: Only RS256 algorithm is now supported for JWT signing
```

### Examples

```
feat(auth): add RS256 JWT signing
fix(renewal): link child tokens to parent via ParentJTI claim
docs: update installation instructions
test(api): add tests for token revocation endpoint
chore(deps): update golang.org/x/crypto to v0.14.0
refactor(storage): extract Redis connection logic
```

## Pull Request Process

### Before Submitting

1. Ensure all tests pass: `make test`
2. Ensure linters pass: `make lint`
3. Update documentation if needed
4. Add entry to CHANGELOG.md under `[Unreleased]` section
5. Rebase on latest `main` if needed

### PR Description

Include in your PR description:
- Summary of changes
- Related issue number (if applicable): `Fixes #123` or `Relates to #456`
- Type of change (feature, bugfix, docs, etc.)
- Testing performed
- Any breaking changes

### Review Process

1. At least one maintainer approval required
2. All CI checks must pass
3. No merge conflicts
4. Commit messages follow conventional commits format

### After Merge

- Delete your feature branch
- Original issue will be automatically closed if using `Fixes #123` syntax

## Reporting Bugs

Use the GitHub issue tracker to report bugs. Include:
- Go version (`go version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

Use the bug report template when creating issues.

## Suggesting Features

Feature suggestions are welcome! Use the feature request template and include:
- Use case and motivation
- Proposed solution or API design
- Alternatives considered
- Willingness to implement (if applicable)

## Security Vulnerabilities

Do NOT report security vulnerabilities through public GitHub issues. Please follow the process outlined in [SECURITY.md](SECURITY.md).

## Alpha Status Notice

This project is currently in alpha (v0.0.1-alpha). Contributions are welcome, but expect:
- API changes without notice
- Incomplete features (see known limitations in README)
- Breaking changes between releases
- Focus on core functionality over polish

See [JWT-PARENT-CHILD-TECHNICAL-GAPS.md](../JWT-PARENT-CHILD-TECHNICAL-GAPS.md) for known architectural gaps planned for beta.

## Questions?

- Check existing issues and discussions
- Create a new issue with the question label
- Reference relevant documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
