# Security Policy

## Supported Versions

Currently supported versions for security updates:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.0.x   | :white_check_mark: | Alpha  |

As this project is in alpha, we recommend using only the latest release.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure practices.

### How to Report

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report vulnerabilities using one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the repository's Security tab
   - Click "Report a vulnerability"
   - Fill out the form with vulnerability details
   - This allows private discussion and coordinated disclosure

2. **Email** (Alternative)
   - Create a private issue with the label "security"
   - Include "SECURITY" in the issue title
   - Mark the issue as private if your GitHub plan supports it

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact and attack scenarios
- Suggested fix (if available)
- Your contact information (for follow-up)
- Any proof-of-concept code (please do not exploit beyond proof-of-concept)

### Response Timeline

We aim to respond to security reports according to this timeline:

- **Initial Response**: Within 48 hours
- **Validation**: Within 7 days (confirm if it's a valid security issue)
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Next planned release
- **Disclosure**: Coordinated disclosure after fix is released

### Severity Classification

We use the following severity levels:

- **Critical**: Remote code execution, authentication bypass, data breach
- **High**: Privilege escalation, SQL injection, XSS attacks
- **Medium**: Information disclosure, denial of service
- **Low**: Minor security improvements, hardening recommendations

## Security Best Practices

When deploying this service:

### RSA Key Management

- Generate unique RSA key pairs for each environment
- Store private keys in secure secret storage (not in emptyDir)
- Rotate keys periodically (recommended: every 90 days)
- Use 2048-bit minimum key size (4096-bit recommended for production)
- Never commit private keys to version control

### Redis Security

- Use Redis authentication (REDIS_PASSWORD)
- Enable TLS for Redis connections in production
- Restrict Redis network access (firewall rules)
- Use separate Redis instances per environment

### Environment Configuration

- Set JWT_ISSUER and JWT_AUDIENCE to environment-specific values
- Use strong, unique Redis passwords
- Enable TLS for all external connections
- Set appropriate token expiry times (shorter = more secure)

### Monitoring

- Monitor for unusual token generation patterns
- Alert on high revocation rates
- Track failed authorization attempts
- Log all security-relevant events

## Known Limitations (Alpha)

The current alpha release has these known security limitations:

1. **Single RSA Key**
   - No automated key rotation
   - Key stored in emptyDir (not persistent secrets)
   - See issue for key rotation roadmap

2. **No Rate Limiting**
   - Token generation endpoints not rate-limited
   - Potential for abuse/DoS
   - Planned for beta

3. **Parent/Child Token Enforcement**
   - Child tokens not fully linked to parent in JWT claims
   - Revoking parent doesn't cascade to children
   - See [JWT-PARENT-CHILD-TECHNICAL-GAPS.md](../JWT-PARENT-CHILD-TECHNICAL-GAPS.md)
   - Critical fix planned for beta

4. **In-Memory Auto-Renewal State**
   - Auto-renewal configs in Redis (not replicated)
   - Single point of failure
   - Planned distributed cache for beta

These limitations are documented and will be addressed in future releases. Do not deploy to production until beta status.

## Security Updates

Security fixes will be released as patch versions (e.g., v0.0.2) with:
- Updated CHANGELOG.md with security notice
- GitHub Security Advisory published
- Release notes detailing the fix
- Credit to reporter (unless anonymous)

Subscribe to repository releases to receive security notifications.

## Safe Harbor

We support security research and vulnerability disclosure. Researchers who:
- Follow responsible disclosure practices
- Do not exploit beyond proof-of-concept
- Allow reasonable time for fixes
- Do not harm users or services

Will be thanked and credited (if desired) in:
- CHANGELOG.md security notices
- GitHub Security Advisories
- Release notes

## Contact

For security-related questions that are not vulnerabilities, you may:
- Open a public issue with the "security" label
- Ask in GitHub Discussions
- Reference this policy

## Dependencies

We monitor dependencies for known vulnerabilities using:
- Go's vulnerability database (govulncheck)
- GitHub Dependabot alerts
- Regular dependency updates

See `go.mod` for current dependencies.

## Compliance

This service handles JWT tokens which may contain personally identifiable information (PII). When deploying:

- Ensure compliance with relevant data protection regulations (GDPR, CCPA, etc.)
- Implement appropriate data retention policies
- Enable audit logging for compliance requirements
- Review token claim contents for PII exposure
- Implement proper access controls for Redis data

## Attribution

Security researchers who have contributed to this project:

(None yet - be the first!)

## Updates to This Policy

This security policy may be updated as the project matures. Check the commit history for changes.

Last updated: 2025-10-31
