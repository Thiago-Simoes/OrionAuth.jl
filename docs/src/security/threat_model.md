# Threat Model

This document outlines the primary threat scenarios considered during the design of OrionAuth.jl. It explicitly defines attack vectors covered and those delegated to integrators.

---

## Threat Actors

- External attackers (unauthenticated)
- Internal attackers (authenticated users attempting privilege escalation)
- Compromised user credentials
- Malicious integrator or misconfigured integration

---

## Threat Scenarios and Mitigations

### Unauthorized Access (Broken Access Control)

**Scenario**: Bypass of access control via missing or incorrect authorization checks.

**Mitigation**:
- Deny by default on roles and permissions.
- Manual integration of access control required.
- JWT unsigned tokens are rejected by default.

**Integrator Responsibility**:
- Explicitly protect all routes requiring authorization.
- Implement logic to validate user permissions where needed.

---

### Token Forgery and Session Hijacking

**Scenario**: Forged JWTs or replayed tokens.

**Mitigation**:
- JWTs must be signed and verified.
- Unsigned JWTs are automatically rejected.

**Integrator Responsibility**:
- Implement appropriate token expiration and refresh logic.

---

### Brute Force and Credential Stuffing

**Scenario**: Attacker attempts multiple passwords or reused passwords from breaches.

**Mitigation**:
- Not currently implemented.
- Future roadmap: rate limiting, password leak detection.

**Integrator Responsibility**:
- Until implemented, integrators should deploy external protections (e.g. WAF, reverse proxies with rate limiting).

---

### Abuse of Application Secrets

**Scenario**: Compromise of ENV variables exposing secrets.

**Mitigation**:
- Secrets are injected via ENV.
- Secure deployment and CI/CD practices required.

**Integrator Responsibility**:
- Protect ENV and infrastructure secrets using best practices.

---

### Insider Threat and Excessive Privileges

**Scenario**: Authenticated user escalates privileges or abuses assigned roles.

**Mitigation**:
- Least privilege enforced via RBAC.
- Deny by default on permissions.
- Logging of role changes and access usage.

**Integrator Responsibility**:
- Monitor logs and audit sensitive actions.

---

## Out of Scope

- Automatic route protection.
- Distributed denial-of-service (DDoS) attacks.
- Side-channel attacks.
- MFA and password leak verification (planned).

---