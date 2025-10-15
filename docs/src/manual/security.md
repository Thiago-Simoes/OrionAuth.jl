# OrionAuth Security Considerations and Best Practices

This document describes OrionAuth’s built-in security features, recommended configurations, and references to industry standards. Follow these guidelines to securely integrate OrionAuth into your applications, ranging from MVPs to more sensitive deployments.

*Última atualização: 16 de Setembro de 2025*

## 1. Standards and References

OrionAuth aims to align with and support applications adhering to security best practices and standards. We recommend familiarizing yourself with the following:

* **JWT (RFC 7519):** [JSON Web Token specification](https://tools.ietf.org/html/rfc7519) for stateless, secure session handling, which is a core component of OrionAuth.
* **OWASP Top 10:** [Open Web Application Security Project's list of critical web application security risks](https://owasp.org/www-project-top-ten/). OrionAuth helps mitigate several of these, including weaknesses in Identification & Authentication and Access Control.
* **NIST SP 800-63:** [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) from the U.S. National Institute of Standards and Technology, offering comprehensive guidance on authentication assurance.
* **GDPR (General Data Protection Regulation):** If your application processes personal data of EU residents, refer to the [GDPR guidelines](https://gdpr-info.eu/) for data privacy and protection.

We encourage you to include links to these (and other relevant standards like SOC 2, ISO 27001, PCI DSS, if applicable to your specific domain) in your company's security policy and documentation.

## 2. Core Security Features of OrionAuth

### 2.1 JWT-Based Session Handling

OrionAuth uses JSON Web Tokens for managing user sessions in a stateless manner.

* **Algorithms:** Supports `HS256` and `HS512` (HMAC with SHA-256/SHA-512) for signing tokens, utilizing `Nettle.jl` as the cryptographic backend. The algorithm is configurable via `ENV["OrionAuth_ALGORITHM"]`.
* **Secret Key:** A strong, unique secret key, configured via `ENV["OrionAuth_SECRET"]`, is used for signing and verifying tokens. This key's confidentiality is critical.
* **Claims:**
    * Default claims automatically included in the JWT payload by `OrionAuth.GenerateJWT` are:
        * `sub`: Subject (User ID)
        * `name`: User's name
        * `email`: User's email
        * `uuid`: User's UUID
        * `roles`: List of roles assigned to the user (names or IDs, fetched by `GetUserRoles`)
        * `permissions`: List of permissions assigned to the user (derived from roles and direct assignments, fetched by `GetUserPermissions`)
        * `iat`: Issued At (timestamp of token generation)
        * `exp`: Expiration Time (timestamp, calculated based on `ENV["OrionAuth_JWT_EXP"]`)
    * **Custom Claims:** Additional standard claims like `iss` (issuer - `ENV["OrionAuth_ISSUER"]` is available but must be manually added to the payload), `aud` (audience), `nbf` (not before), and `jti` (JWT ID for revocability) can be incorporated by customizing the payload construction within the `GenerateJWT` function in `src/auth.jl`.
* **Token Expiration:** The JWT expiration time is configurable in minutes via `ENV["OrionAuth_JWT_EXP"]`.
* **Token Generation Example (Conceptual):**
    ```julia
    # In your application, after a user signs in:
    # user_object, token_response_json = OrionAuth.signin("user@example.com", "password123")
    # The token_response_json string contains the access_token.
    # Internally, OrionAuth.GenerateJWT(user_object) is called.
    ```
* **Refresh Tokens:** Currently, OrionAuth V1 does not have built-in support for refresh tokens or advanced token revocation (e.g., blacklisting `jti`). These are considered for future enhancements.

### 2.2 Password Security

OrionAuth prioritizes strong password protection.

* **Hashing Algorithm (Default):** Uses libsodium's Argon2id implementation via `crypto_pwhash_str`, leveraging the `OPSLIMIT_MODERATE` and `MEMLIMIT_MODERATE` cost parameters by default. The algorithm is self-contained (salt + parameters + hash) and represented in the `$argon2id$...` format.
* **Algorithm Selection:** Choose between the built-in `argon2id` (default) and legacy `sha512` implementations via `ENV["OrionAuth_PASSWORD_ALGORITHM"]` or by passing the desired algorithm object (e.g., `OrionAuth.LegacySHA512Algorithm()`) to `hash_password`.
* **Legacy Compatibility:** Existing SHA-512 hashes (`"sha512&..."`) continue to verify successfully. Applications that still need to generate SHA-512 hashes can opt-in by selecting the `:sha512` algorithm and may tune the iteration count with `ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"]`.
* **Constant-Time Verification:** Argon2id verification is delegated to libsodium, which performs constant-time checks internally. Legacy SHA-512 verification keeps the original iterative approach; high-security deployments should phase it out or wrap verification with additional mitigations if necessary.

### 2.3 Secrets Management (Application/Infrastructure Responsibility)

* The `OrionAuth_SECRET` (for JWT signing), database credentials, and any other sensitive keys used by your application should be managed પાણી.
* **Recommendation:** Store these secrets in a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Do not hardcode them or commit them to version control.
* Regularly rotate secrets and audit access logs according to your organization's security policy.

### 2.4 Transport Security (Application/Infrastructure Responsibility)

* **Recommendation:** Enforce `TLS 1.2` or higher (HTTPS) for all endpoints that handle authentication requests or transmit JWTs.
* Implement HTTP Strict Transport Security (HSTS) headers to ensure browsers only connect via HTTPS.
* A reverse proxy (e.g., NGINX, Traefik, Caddy) can be used for TLS termination, certificate management, and potentially as a first line of defense for rate limiting.

### 2.5 Data Encryption At Rest (Application/Infrastructure Responsibility - for general application data)

* OrionAuth itself does not encrypt general application data stored by your system (e.g., user profile information beyond authentication details, application-specific sensitive data).
* **Recommendation:**
    * **Field-Level Encryption:** For highly sensitive fields in your database, consider encrypting them before insertion (e.g., using AES-GCM via `Nettle.jl` or another cryptographic library).
    * **Database Encryption:** Utilize disk-level encryption provided by your database system or cloud provider (e.g., LUKS, AWS EBS encryption, Azure Disk Encryption).

### 2.6 Audit Logging (OrionAuth Feature)

OrionAuth includes basic audit logging capabilities.

* **Log Table:** Actions are logged to the `OrionAuth_Log` table.
* **Information Logged:** Includes `userId`, `action` performed (e.g., "signup", "signin", "AssignRoleToUser"), and a `timestamp`.
* **Immutability (Recommendation):** While OrionAuth inserts logs, true immutability and integrity depend on database permissions and backup strategies.
* **Database Role (Recommendation):** Create a dedicated database user for your application that has minimal necessary privileges on OrionAuth tables. For the `OrionAuth_Log` table, this user might primarily need `INSERT` and `SELECT` permissions. Example:
    ```sql
    GRANT SELECT, INSERT ON OrionAuth_Log TO 'your_app_auth_user';
    ```
* **Log Retention (Application Policy):** Log retention periods and backup strategies should be defined by your organization's policies and compliance requirements.

### 2.7 Access Controls (OrionAuth Feature)

OrionAuth provides a Role-Based Access Control (RBAC) system.

* **Models:** Defines `OrionAuth_Role`, `OrionAuth_Permission`, `OrionAuth_UserRole`, `OrionAuth_RolePermission`, and `OrionAuth_UserPermission` tables to manage fine-grained access.
* **Functionality:** Provides functions to assign roles to users (`AssignRoleToUser`), assign permissions to roles (via `SyncRolesAndPermissions` or direct table manipulation), assign direct permissions to users (`AssignPermissionToUser`), and check user permissions (`CheckPermission`, `GetUserPermissions`).
* **Database Hardening (Recommendation):** Complement OrionAuth's RBAC by configuring restrictive database grants for your application's database user, minimizing privileges on critical tables (e.g., restricting `DROP`/`DELETE` on core auth tables).

### 2.8 Rate Limiting and Brute-Force Protection (Planned / Application or Infrastructure Responsibility for V1)

* **OrionAuth Package:** Rate limiting and advanced brute-force protection (like account lockout after N failed attempts) are listed as "Upcoming Features" in the README for direct inclusion in the package.
* **For V1 / Current Implementation:** It is highly recommended to implement these protections at the application layer or using infrastructure tools (e.g., a reverse proxy, WAF). This includes limiting login attempts per IP and/or per user account.

### 2.9 Multi-Factor Authentication (MFA) (Planned)

* **OrionAuth Package:** MFA (e.g., TOTP via RFC 6238) is listed as an "Upcoming Feature" in the README.
* **Current Implementation:** For V1, if MFA is required, it would need to be integrated as a separate layer by the consuming application.

## 3. Organizational vs. Package Responsibilities

| Aspect                             | OrionAuth Package Responsibility                                  | Company / Infrastructure Responsibility                       |
| :--------------------------------- | :----------------------------------------------------------------- | :------------------------------------------------------------ |
| Security Policy Documentation      | Provides this `security.md` as a guide.                            | Formal policies, regular audits, referencing standards.       |
| JWT Algorithm & Implementation     | Provides secure JWT (HS256/HS512) generation & verification.       | Choosing a strong `OrionAuth_SECRET`.                        |
| Password Hashing                 | Default Argon2id via libsodium with optional legacy SHA-512 fallback. | Educating users on strong password creation.                |
| Secret Rotation & Management       | Uses `ENV` vars for secrets; facilitates updates by app restart.   | Implement vault, schedule rotation, manage access.            |
| Penetration Testing                | Aims for secure code; testable via its API (when used in an app).  | Conduct regular penetration tests and remediate findings.     |
| Backup & Recovery                  | Defines database models.                                           | Implement DRP, define RPO/RTO, manage backup scripts.       |
| Environment Isolation              | Configurable via `ENV` variables.                                  | Implement VPCs, IAM, network policies, secure CI/CD.        |
| Transport Layer Security (TLS)     | N/A (operates at a higher layer).                                  | Enforce HTTPS, manage certificates.                           |
| Rate Limiting / Brute-Force (V1) | Planned for future; currently N/A.                               | Implement at application or infrastructure level.             |
| Multi-Factor Authentication (V1)   | Planned for future; currently N/A.                               | Implement separately if required for V1.                      |
| Audit Log Storage & Retention    | Provides `OrionAuth_Log` table and inserts records.               | Manage DB storage, backups, retention policies, SIEM anexo. |
| RBAC Definition & Enforcement      | Provides models and functions for RBAC.                            | Define appropriate roles & permissions for the application.   |

## 4. Use Cases and Implementation Levels

This section provides guidance on which security features to prioritize based on your application's sensitivity and requirements.

| Use Case                      | Core OrionAuth Features Utilized                                    | Key Additional Concerns / Responsibilities (Company/Infra)        |
| :---------------------------- | :------------------------------------------------------------------- | :---------------------------------------------------------------- |
| **MVP / Prototyping** | JWT (HS512) + Argon2id password hashing, Basic Audit Logging (`OrionAuth_Log`). | TLS/HTTPS, strong `OrionAuth_SECRET`, basic ENV var management.  |
| **Non-Sensitive Web App** | All MVP features + robust RBAC (`GetUserPermissions`, etc.).          | Vault for secrets, basic rate limiting (app/proxy), regular dependency updates. |
| **Medium-Sensitivity App** | All above + enforce Argon2id parameters review, begin MFA rollout.  | Stricter RBAC policies, SIEM integration for logs, defined log retention, field-level encryption for sensitive app data. |
| **Fintech / Regulated App** | All above + mandatory MFA, centralized secrets, Argon2id monitoring. | Formal SOC 2/ISO 27001 controls, regular pentests, robust DRP, immutable audit pipeline, compliance reporting (PCI/GDPR as applicable), dedicated security team. |

**Note:** Always adjust configurations (e.g., JWT expiration, password hashing iterations) based on your specific threat model, performance considerations, and organizational security requirements. Regularly review and update your security practices as both your application and the threat landscape evolve.