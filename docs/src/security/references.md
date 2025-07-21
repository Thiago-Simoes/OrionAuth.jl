# Security References

This document consolidates all official standards, guidelines, and references used to design and enforce the OrionAuth.jl security model.

---

## General Security Guidelines

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
  - Authorization Cheat Sheet
  - Logging Cheat Sheet
  - Insecure Direct Object Reference Prevention Cheat Sheet

- [OWASP ASVS v4.0](https://owasp.org/www-project-application-security-verification-standard/)
  - Access Control requirements and verification levels

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
  - Authorization Testing

- [OWASP Top 10 - 2021](https://owasp.org/Top10/)
  - A01:2021 - Broken Access Control

- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_cwe_top25.html)
  - CWE-862: Missing Authorization
  - CWE-863: Incorrect Authorization

---

## Authentication and Identity

- [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
  - Digital Identity Guidelines
  - Authentication Assurance Levels (AAL), Level 1 as baseline

- [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)

- [OAuth 2.1 (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10)

---

## Access Control Models and Enforcement

- [Policy Enforcement in RFC 2904 (Policy Core Information Model - PCIM)](https://datatracker.ietf.org/doc/html/rfc2904)
  - Referenced only, not enforced. Used for access control consolidation principles.

---

## Password Security and Threat Intelligence

- [SecLists - Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
  - Top common and compromised passwords reference for future password strength validation.

---

## Secrets and Configuration Management

- Environment Variables (ENV)
  - Used for application secrets injection and management.
  - Should be handled securely in CI/CD and production environments.

---

## Logging and Audit Trail

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## Special Considerations

- Future MFA implementation aligned with NIST 800-63B AAL2/AAL3 when applicable.

---
