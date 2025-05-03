# Security Features

NebulaAuth incorporates multiple security mechanisms to safeguard your application. This document outlines key security features.

## JWT-Based Session Handling
NebulaAuth uses JSON Web Tokens (JWT) for stateless authentication.
**Based on RFC7519.**

- **Token Creation:**  
  Generate a token after user authentication:
  ```julia
  using NebulaAuth.JWT
  token = NebulaAuth.JWT.create_token(user)
  ```
- **Token Verification:**  
  Verify the authenticity of a token:
  ```julia
  valid = NebulaAuth.JWT.verify_token(token)
  println("Token is valid: ", valid)
  ```

## Password Security
- **Hashing:**  
  Passwords are securely hashed using SHA512 with salt.  
- **Verification:**  
  Use the internal function to verify password correctness during sign-in.

## Email Confirmation and Password Reset (Upcoming)
- **Email Confirmation:**  
  Planned feature for secure token-based email verification during user registration.
- **Password Reset:**  
  A secure workflow will be implemented to allow users to reset their password via a time-limited token.

## Additional Security Measures (Upcoming)
- **Rate Limiting:**  
  Prevent brute-force attacks by limiting the number of login attempts.
- **Multi-Factor Authentication:**  
  Future updates will include MFA for an extra layer of security.
- **Third-Party Integration:**  
  Support for OAuth/OpenID Connect for federated identity management.
- **Audit Trails:**  
  Detailed logging of security-related events for monitoring and compliance.

These features aim to bring NebulaAuth to production-ready security standards.
