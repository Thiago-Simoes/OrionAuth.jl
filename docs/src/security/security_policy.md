# NebulaAuth Security Policy

## Overview

NebulaAuth.jl is designed to provide simple and robust authentication and authorization mechanisms. This document outlines the security objectives, methodologies, enforced practices, limitations, and future plans.

---

## Objectives

- Provide strong and simple authentication.
- Support robust authorization via RBAC with editable roles and permissions.
- Ensure auditability through logging and session management.
- Prevent common web application vulnerabilities related to authentication and authorization.

---

## Authentication

### Supported Methods

- Password-based authentication only.

### Password Storage

- SHA512 + Salt with thousands of iterations.
- Future plan: migrate to Argon2id for password hashing.

### Password Requirements and Checks

- No current enforcement of password strength beyond storage.
- No verification against leaked password databases (planned).
- Future plan: check passwords against common password lists and compromised datasets (e.g. SecLists).

### Protection Against Brute Force

- No rate limiting or brute force protection implemented.
- Planned for future releases.

### JWT Handling

- JWTs are always required to be signed.
- Unsigned JWTs are rejected by default.
- No need for the integrator to manually validate JWT signature.

---

## Authorization

### General Approach

- Authorization is manual and route protection is integrator's responsibility.
- No automatic access control check (Force Every Access Check - RFC2904 is **not applied**).
- Abuse cases like authorization bypass and missing checks are mitigated by enforcing best practices on the integrator side.

### Access Control Model

- RBAC is implemented.
- Roles can be assigned multiple permissions.
- Policies (e.g., `admin_edit_userData`) can be hard-coded.
- Hard-coding of roles is discouraged.
- Deny by default: roles start with no permissions.
- Least privilege is enforced by design.

### Abuse Cases Covered

- Broken Access Control (OWASP Top 10 2021 A01)
- CWE-862 (Missing Authorization)
- CWE-863 (Incorrect Authorization)
- JWT signature validation (disallows unsigned tokens)

### Abuse Cases Not Covered

- Automatic route protection (manual responsibility of integrator)

---

## Secrets Management

- Application secrets (keys, secrets, configuration) are handled via environment variables (ENV).
- Secrets should be injected via secure channels (CI/CD, deployment tools).

---

## Logging and Audit Trail

- Built-in logging of critical events:
  - Sign in
  - Sign out
  - Sign up
  - Role assignment
  - Role removal
  - Access usage

- Integrator responsible for securing logs and ensuring integrity.

---

## References and Standards

- OWASP Cheat Sheet Series:
  - Authorization Cheat Sheet
  - Logging Cheat Sheet
  - Insecure Direct Object Reference Prevention Cheat Sheet
- OWASP ASVS V4 (Access Control)
- OWASP Testing Guide (Authorization Testing)
- OWASP Top 10 2021 - A01 Broken Access Control
- CWE Top 25:
  - CWE-862 Missing Authorization
  - CWE-863 Incorrect Authorization
- OAuth 2.0 Protocol
- OAuth 2.1 Draft
- Policy Enforcement in RFC 2904 (referenced, not applied)
- NIST 800-63b (Authentication Assurance Level 1)

---

## Limitations

- Route protection is the integrator's responsibility.
- No rate limiting or brute force protections (planned).
- Password leak detection not implemented (planned).
- No MFA support yet (planned).

---

## Roadmap (Future Plans)

- Migration to Argon2id for password storage.
- Implement password leak and common password verification.
- Add Multi-Factor Authentication support.
- Add rate limiting and brute force protection mechanisms.
- Potential future automatic route protection and authorization integration.

---

## Change Log

*Initial version.*
