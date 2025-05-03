# Changelog

## [0.1.0] - 2025-05-03
### Added
- Initial release with core authentication features.
- User creation, sign-in, and log registration functionalities.
- Basic password hashing and model definitions.

## Upcoming
- Migration from the current SHA256 mechanism to SHA512 with salt for improved security.
- Implementation of JWT for secure session handling using custom, from-scratch hashing.
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
