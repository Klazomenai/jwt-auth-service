# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2-alpha.0](https://github.com/Klazomenai/jwt-auth-service/compare/v0.1.1-alpha.0...v0.1.2-alpha.0) (2026-02-03)


### Added

* **csrf:** add CSRF token generation and validation endpoints ([#24](https://github.com/Klazomenai/jwt-auth-service/issues/24)) ([cef7727](https://github.com/Klazomenai/jwt-auth-service/commit/cef7727226b411f853fca1470aa2347a013f8aae))

## [0.1.1-alpha.0](https://github.com/Klazomenai/jwt-auth-service/compare/v0.1.0-alpha.0...v0.1.1-alpha.0) (2025-12-14)


### Added

* add prometheus /metrics endpoint for token lifecycle monitoring ([#12](https://github.com/Klazomenai/jwt-auth-service/issues/12)) ([3000651](https://github.com/Klazomenai/jwt-auth-service/commit/300065106968a135fd0eaff2f3b408c794272025)), closes [#1](https://github.com/Klazomenai/jwt-auth-service/issues/1)


### Fixed

* **release:** add bump-patch-for-minor-pre-major for prerelease versioning ([7b75de9](https://github.com/Klazomenai/jwt-auth-service/commit/7b75de93edc081cd9903d556706a6416bf811e54))
* **release:** use prerelease versioning strategy for alpha releases ([58b06f7](https://github.com/Klazomenai/jwt-auth-service/commit/58b06f71e5cabeba7ee7bedb1e3e03cb11a79e09))

## [0.1.0-alpha.0](https://github.com/Klazomenai/jwt-auth-service/compare/v0.0.1-alpha.0...v0.1.0-alpha.0) (2025-12-07)


### Added

* add manual build workflow for testing ([35bef98](https://github.com/Klazomenai/jwt-auth-service/commit/35bef987abbe9d387e07d5c912d6f1583a2b67ea))
* implement release-please for automated changelog and release management ([bad88af](https://github.com/Klazomenai/jwt-auth-service/commit/bad88af5fea689af29763b27b91f778fd569c198))
* implement release-please for automated changelog and release management ([3ed2fb0](https://github.com/Klazomenai/jwt-auth-service/commit/3ed2fb0abe7f42fe6b1182ccba636c2d38428e05)), closes [#2](https://github.com/Klazomenai/jwt-auth-service/issues/2)
* initial release of jwt-auth-service v0.0.1-alpha ([5264f41](https://github.com/Klazomenai/jwt-auth-service/commit/5264f411ecae7ef24f2a151962f072f049581302))

## [0.0.1-alpha.0](https://github.com/klazomenai/jwt-auth-service/releases/tag/v0.0.1-alpha.0) (2025-10-31)

### Added

* Initial alpha release extracted from helm-priv-deploy-autonity
* RS256 JWT token generation and validation
* Parent/child token architecture
  * Long-lived parent tokens (30 days default)
  * Short-lived child tokens (15 minutes default)
* Server-side auto-renewal worker
  * Configurable renewal threshold and check interval
  * Automatic child token generation before expiry
* Redis-backed revocation tracking
  * Token revocation by JTI
  * User-level revocation (all tokens)
  * Auto-renewal configuration storage
* RESTful API endpoints
  * `POST /tokens` - Create single token
  * `POST /token-pairs` - Create parent + optional child token
  * `POST /renew` - Manual child token generation
  * `GET /tokens/latest` - Poll for latest auto-renewed child token
  * `GET /tokens/stream` - SSE stream for child token updates
  * `DELETE /tokens/:tokenID` - Revoke specific token
  * `DELETE /users/:userID/tokens` - Revoke all user tokens
  * `POST /authorize` - External authorization validation
  * `GET /.well-known/jwks.json` - Public key distribution
  * `GET /health` - Health check
* Environment-agnostic configuration
  * Required: `JWT_ISSUER`, `JWT_AUDIENCE`
  * Optional: Redis connection, key paths, renewal timings
* Comprehensive test suite
  * 21 unit tests across auth, API, storage, and renewal packages
  * 28.7% overall coverage (56.9% in auth package)
  * Tests use miniredis for Redis mocking
* Docker support
  * Multi-stage Dockerfile (Go 1.22)
  * GHCR registry: ghcr.io/klazomenai/jwt-auth-service
* GitHub Actions CI/CD
  * Automated testing on push/PR
  * Docker image building on version tags
* Documentation
  * README with standalone usage instructions
  * Makefile with test, build, lint, and docker targets
  * MIT License

### Security

* Fail-fast validation for required environment variables
* RSA key generation with 2048-bit minimum
* Token expiry enforcement
* Revocation checking before token operations

### Known Limitations (Alpha)

* Single RSA key stored in emptyDir (production should use secure secret storage)
* No automated key rotation
* No rate limiting enforcement
* Child tokens created via renewal do not include `token_type` and `parent_jti` claims
* Authorization endpoint does not validate parent token status for child tokens
* In-memory auto-renewal state (Redis, not distributed)
* No payload size validation
* Single replica deployments only

### Notes

This is an alpha release intended for testing and development. Do not use in production.

For production readiness requirements, see:
* [SECURITY.md](SECURITY.md) for security considerations
* [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
