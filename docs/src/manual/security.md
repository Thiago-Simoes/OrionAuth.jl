# NebulaAuth Security Considerations and Best Practices

This document describes NebulaAuth’s built-in security features, recommended configurations, and references to industry standards. Follow these guidelines to securely integrate NebulaAuth into your applications, ranging from MVPs to more sensitive deployments.

*Última atualização: 11 de Maio de 2025*

## 1. Standards and References

NebulaAuth aims to align with and support applications adhering to security best practices and standards. We recommend familiarizing yourself with the following:

* **JWT (RFC 7519):** [JSON Web Token specification](https://tools.ietf.org/html/rfc7519) for stateless, secure session handling, which is a core component of NebulaAuth.
* **OWASP Top 10:** [Open Web Application Security Project's list of critical web application security risks](https://owasp.org/www-project-top-ten/). NebulaAuth helps mitigate several of these, including weaknesses in Identification & Authentication and Access Control.
* **NIST SP 800-63:** [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) from the U.S. National Institute of Standards and Technology, offering comprehensive guidance on authentication assurance.
* **GDPR (General Data Protection Regulation):** If your application processes personal data of EU residents, refer to the [GDPR guidelines](https://gdpr-info.eu/) for data privacy and protection.

We encourage you to include links to these (and other relevant standards like SOC 2, ISO 27001, PCI DSS, if applicable to your specific domain) in your company's security policy and documentation.

## 2. Core Security Features of NebulaAuth

### 2.1 JWT-Based Session Handling

NebulaAuth uses JSON Web Tokens for managing user sessions in a stateless manner.

* **Algorithms:** Supports `HS256` and `HS512` (HMAC with SHA-256/SHA-512) for signing tokens, utilizing `Nettle.jl` as the cryptographic backend. The algorithm is configurable via `ENV["NEBULAAUTH_ALGORITHM"]`.
* **Secret Key:** A strong, unique secret key, configured via `ENV["NEBULAAUTH_SECRET"]`, is used for signing and verifying tokens. This key's confidentiality is critical.
* **Claims:**
    * Default claims automatically included in the JWT payload by `NebulaAuth.generateJWT` are:
        * `sub`: Subject (User ID)
        * `name`: User's name
        * `email`: User's email
        * `uuid`: User's UUID
        * `roles`: List of roles assigned to the user (names or IDs, fetched by `GetUserRoles`)
        * `permissions`: List of permissions assigned to the user (derived from roles and direct assignments, fetched by `GetUserPermissions`)
        * `iat`: Issued At (timestamp of token generation)
        * `exp`: Expiration Time (timestamp, calculated based on `ENV["NEBULAAUTH_JWT_EXP"]`)
    * **Custom Claims:** Additional standard claims like `iss` (issuer - `ENV["NEBULAAUTH_ISSUER"]` is available but must be manually added to the payload), `aud` (audience), `nbf` (not before), and `jti` (JWT ID for revocability) can be incorporated by customizing the payload construction within the `generateJWT` function in `src/auth.jl`.
* **Token Expiration:** The JWT expiration time is configurable in minutes via `ENV["NEBULAAUTH_JWT_EXP"]`.
* **Token Generation Example (Conceptual):**
    ```julia
    # In your application, after a user signs in:
    # user_object, token_response_json = NebulaAuth.signin("user@example.com", "password123")
    # The token_response_json string contains the access_token.
    # Internally, NebulaAuth.generateJWT(user_object) is called.
    ```
* **Refresh Tokens:** Currently, NebulaAuth V1 does not have built-in support for refresh tokens or advanced token revocation (e.g., blacklisting `jti`). These are considered for future enhancements.

### 2.2 Password Security

NebulaAuth prioritizes strong password protection.

* **Hashing Algorithm:** Uses `SHA512` for hashing passwords.
* **Salting:** A cryptographically strong, unique 32-byte random salt (generated using `Random.randstring(RandomDevice(), 32)`) is created for each password.
* **Iterations:** The SHA512 hashing process is iterated multiple times to increase computational cost for attackers. The minimum number of iterations is configurable via `ENV["NEBULAAUTH_MIN_PASSWORD_ITTERATIONS"]` (defaults to 25000, actual iterations randomized between min and 2*min).
* **Storage Format:** Passwords are stored in the database in the format: `"sha512&<hashed_password_hex>&<salt_string>&<iterations_count>"`.
* **Constant-Time Comparison (Recommendation):** For maximum protection against timing attacks during password verification, it is best practice to use a constant-time string/byte comparison function. While NebulaAuth's current password verification (`__NEBULA__VerifyPassword`) uses standard string comparison, applications with very high-security requirements should consider if further measures are needed at the application or library level.
* **Future Enhancements:** Support for more modern key derivation functions like Argon2id or bcrypt is listed in "Upcoming Features" in the README.

### 2.3 Secrets Management (Application/Infrastructure Responsibility)

* The `NEBULAAUTH_SECRET` (for JWT signing), database credentials, and any other sensitive keys used by your application should be managed પાણી.
* **Recommendation:** Store these secrets in a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Do not hardcode them or commit them to version control.
* Regularly rotate secrets and audit access logs according to your organization's security policy.

### 2.4 Transport Security (Application/Infrastructure Responsibility)

* **Recommendation:** Enforce `TLS 1.2` or higher (HTTPS) for all endpoints that handle authentication requests or transmit JWTs.
* Implement HTTP Strict Transport Security (HSTS) headers to ensure browsers only connect via HTTPS.
* A reverse proxy (e.g., NGINX, Traefik, Caddy) can be used for TLS termination, certificate management, and potentially as a first line of defense for rate limiting.

### 2.5 Data Encryption At Rest (Application/Infrastructure Responsibility - for general application data)

* NebulaAuth itself does not encrypt general application data stored by your system (e.g., user profile information beyond authentication details, application-specific sensitive data).
* **Recommendation:**
    * **Field-Level Encryption:** For highly sensitive fields in your database, consider encrypting them before insertion (e.g., using AES-GCM via `Nettle.jl` or another cryptographic library).
    * **Database Encryption:** Utilize disk-level encryption provided by your database system or cloud provider (e.g., LUKS, AWS EBS encryption, Azure Disk Encryption).

### 2.6 Audit Logging (NebulaAuth Feature)

NebulaAuth includes basic audit logging capabilities.

* **Log Table:** Actions are logged to the `NebulaAuth_Log` table.
* **Information Logged:** Includes `userId`, `action` performed (e.g., "signup", "signin", "AssignRoleToUser"), and a `timestamp`.
* **Immutability (Recommendation):** While NebulaAuth inserts logs, true immutability and integrity depend on database permissions and backup strategies.
* **Database Role (Recommendation):** Create a dedicated database user for your application that has minimal necessary privileges on NebulaAuth tables. For the `NebulaAuth_Log` table, this user might primarily need `INSERT` and `SELECT` permissions. Example:
    ```sql
    GRANT SELECT, INSERT ON NebulaAuth_Log TO 'your_app_auth_user';
    ```
* **Log Retention (Application Policy):** Log retention periods and backup strategies should be defined by your organization's policies and compliance requirements.

### 2.7 Access Controls (NebulaAuth Feature)

NebulaAuth provides a Role-Based Access Control (RBAC) system.

* **Models:** Defines `NebulaAuth_Role`, `NebulaAuth_Permission`, `NebulaAuth_UserRole`, `NebulaAuth_RolePermission`, and `NebulaAuth_UserPermission` tables to manage fine-grained access.
* **Functionality:** Provides functions to assign roles to users (`AssignRoleToUser`), assign permissions to roles (via `SyncRolesAndPermissions` or direct table manipulation), assign direct permissions to users (`AssignPermissionToUser`), and check user permissions (`CheckUserPermission`, `GetUserPermissions`).
* **Database Hardening (Recommendation):** Complement NebulaAuth's RBAC by configuring restrictive database grants for your application's database user, minimizing privileges on critical tables (e.g., restricting `DROP`/`DELETE` on core auth tables).

### 2.8 Rate Limiting and Brute-Force Protection (Planned / Application or Infrastructure Responsibility for V1)

* **NebulaAuth Package:** Rate limiting and advanced brute-force protection (like account lockout after N failed attempts) are listed as "Upcoming Features" in the README for direct inclusion in the package.
* **For V1 / Current Implementation:** It is highly recommended to implement these protections at the application layer or using infrastructure tools (e.g., a reverse proxy, WAF). This includes limiting login attempts per IP and/or per user account.

### 2.9 Multi-Factor Authentication (MFA) (Planned)

* **NebulaAuth Package:** MFA (e.g., TOTP via RFC 6238) is listed as an "Upcoming Feature" in the README.
* **Current Implementation:** For V1, if MFA is required, it would need to be integrated as a separate layer by the consuming application.

## 3. Organizational vs. Package Responsibilities

| Aspect                             | NebulaAuth Package Responsibility                                  | Company / Infrastructure Responsibility                       |
| :--------------------------------- | :----------------------------------------------------------------- | :------------------------------------------------------------ |
| Security Policy Documentation      | Provides this `security.md` as a guide.                            | Formal policies, regular audits, referencing standards.       |
| JWT Algorithm & Implementation     | Provides secure JWT (HS256/HS512) generation & verification.       | Choosing a strong `NEBULAAUTH_SECRET`.                        |
| Password Hashing                 | Implements SHA512 with salt & iterations.                          | Educating users on strong password creation.                |
| Secret Rotation & Management       | Uses `ENV` vars for secrets; facilitates updates by app restart.   | Implement vault, schedule rotation, manage access.            |
| Penetration Testing                | Aims for secure code; testable via its API (when used in an app).  | Conduct regular penetration tests and remediate findings.     |
| Backup & Recovery                  | Defines database models.                                           | Implement DRP, define RPO/RTO, manage backup scripts.       |
| Environment Isolation              | Configurable via `ENV` variables.                                  | Implement VPCs, IAM, network policies, secure CI/CD.        |
| Transport Layer Security (TLS)     | N/A (operates at a higher layer).                                  | Enforce HTTPS, manage certificates.                           |
| Rate Limiting / Brute-Force (V1) | Planned for future; currently N/A.                               | Implement at application or infrastructure level.             |
| Multi-Factor Authentication (V1)   | Planned for future; currently N/A.                               | Implement separately if required for V1.                      |
| Audit Log Storage & Retention    | Provides `NebulaAuth_Log` table and inserts records.               | Manage DB storage, backups, retention policies, SIEM anexo. |
| RBAC Definition & Enforcement      | Provides models and functions for RBAC.                            | Define appropriate roles & permissions for the application.   |

## 4. Use Cases and Implementation Levels

This section provides guidance on which security features to prioritize based on your application's sensitivity and requirements.

| Use Case                      | Core NebulaAuth Features Utilized                                    | Key Additional Concerns / Responsibilities (Company/Infra)        |
| :---------------------------- | :------------------------------------------------------------------- | :---------------------------------------------------------------- |
| **MVP / Prototyping** | JWT (HS512, salt, iterations), Basic Audit Logging (`NebulaAuth_Log`). | TLS/HTTPS, strong `NEBULAAUTH_SECRET`, basic ENV var management.  |
| **Non-Sensitive Web App** | All MVP features + robust RBAC (`GetUserPermissions`, etc.).          | Vault for secrets, basic rate limiting (app/proxy), regular dependency updates. |
| **Medium-Sensitivity App** | All above + consider future MFA/Argon2 from NebulaAuth.              | Stricter RBAC policies, SIEM integration for logs, defined log retention, field-level encryption for sensitive app data. |
| **Fintech / Regulated App** | All above (when future features like MFA/Argon2 are available).        | Formal SOC 2/ISO 27001 controls, regular pentests, robust DRP, immutable audit pipeline, compliance reporting (PCI/GDPR as applicable), dedicated security team. |

**Note:** Always adjust configurations (e.g., JWT expiration, password hashing iterations) based on your specific threat model, performance considerations, and organizational security requirements. Regularly review and update your security practices as both your application and the threat landscape evolve.