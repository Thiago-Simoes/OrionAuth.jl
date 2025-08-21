# Changelog

## [0.5.0] - 2025-08-07
At this point, we’re at a usable stage. OrionAuth should be used with caution;
it provides only the bare minimum and is intended for small projects, internal systems, and testing

- Ensure ORIONAUTH_ALGORITHM environment variable is validated and matches supported HMAC algorithms in code.
- Implemented support for HMAC512
- Implemented algorithm check between .env and JWT alg
- Fixed compatibility following RFC
- Permissions can be added individually and directly, without role
- Email confirmation with secure token-based validation.
- Password reset functionality with secure token distribution and expiry.


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
- Implement Argon2 or bcrypt
- Admin monitoring dashboard for real-time audit trails and analytics.
- Multi-factor authentication for additional login security.
- Integration with third-party identity providers for federated login.
- Support for OAuth and OpenID Connect standards.
- Configurable password policies and account security settings.
- Detailed compliance audit logs with external logging service integration.

## Security Improvements - for prod-ready
- Use constant-time comparison functions for password and JWT signature verification.
- Implement refresh token mechanism with unique JWT ID (jti) and blacklist support for immediate revocation.
- Migrate password hashing to a modern KDF (Argon2id or bcrypt) instead of iterated SHA-512.
- Enforce rate limiting and account lockout after configurable failed login attempts.
- Support multi-factor authentication (e.g., TOTP) for enhanced account security.
- Refine error handling to return controlled HTTP status codes without exposing internal stack traces.