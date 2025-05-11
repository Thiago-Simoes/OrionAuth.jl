# Changelog

## [0.2.0]
## Added
- Implementation of JWT for secure session handling.

## [0.1.1]
## Added
- Migration from current SHA256 mechanism to SHA512 with salt for improved security.

## [0.1.0] - 2025-05-03
### Added
- Initial release with core authentication features.
- User creation, sign-in, and log registration functionalities.
- Basic password hashing and model definitions.

## Upcoming
- Email confirmation with secure token-based validation.
- Password reset functionality with secure token distribution and expiry.
- Enhanced log registration and auditing features.
- Robust rate limiting to mitigate brute force and DOS attacks.
- Multi-factor authentication for additional login security.
- Integration with third-party identity providers for federated login.
- Support for OAuth and OpenID Connect standards.
- Configurable password policies and account security settings.
- Admin monitoring dashboard for real-time audit trails and analytics.
- Detailed compliance audit logs with external logging service integration.
- Implement Argon2 or bcrypt

## Security Improvements - for prod-ready
- Use constant-time comparison functions for password and JWT signature verification.
- Ensure NEBULAAUTH_ALGORITHM environment variable is validated and matches supported HMAC algorithms in code.
- Implement refresh token mechanism with unique JWT ID (jti) and blacklist support for immediate revocation.
- Add standard JWT claims: iss (issuer), aud (audience), jti (JWT ID), and nbf (not before).
- Migrate password hashing to a modern KDF (Argon2id or bcrypt) instead of iterated SHA-512.
- Enforce rate limiting and account lockout after configurable failed login attempts.
- Support multi-factor authentication (e.g., TOTP) for enhanced account security.
- Refine error handling to return controlled HTTP status codes without exposing internal stack traces.