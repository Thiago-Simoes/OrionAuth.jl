# OrionAuth Documentation

OrionAuth is a lightweight authentication package written in Julia, designed for secure, scalable applications. It offers user creation, sign-in, JWT-based session handling, secure password hashing (SHA512 with salt), extensive logging, and auditing capabilities.

## Table of Contents
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Advanced Configuration](#advanced-configuration)
- [Use Cases](#use-cases)
- [Upcoming Features](#upcoming-features)
- [Contributing](#contributing)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Thiago-Simoes/OrionAuth.jl.git
   ```
2. Change to the project directory:
   ```bash
   cd OrionAuth.jl
   ```
3. Activate and instantiate packages in Julia:
   ```julia
   import Pkg
   Pkg.activate(".")
   Pkg.instantiate()
   ```

## Configuration

Create a `.env` file in the repository root with these settings:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=pass
DB_NAME=dbname
DB_PORT=3306

NebulaORM_LOG_LEVEL=error
OrionAuth_SECRET=your_secret_key_here
OrionAuth_ALGORITHM=HS512
OrionAuth_EXPIRATION=3600
OrionAuth_ISSUER=OrionAuth
OrionAuth_DBPREFIX=OrionAuth_
OrionAuth_MIN_PASSWORD_ITTERATIONS=25000
OrionAuth_JWT_EXP=30 # in minutes
```
Customize these settings based on your production environment.

## Usage Examples

### Initializing the Package

Initialize all modules and ORM models:
```julia
using OrionAuth
OrionAuth.init!()  # Loads modules such as auth.jl and jwt.jl.
```

### Signing Up and Signing In

Create a new user with secure password hashing:
```julia
using OrionAuth
user = OrionAuth.signup("user@example.com", "John Doe", "securePassword123")
println("User created with UUID: ", user.uuid)
```

Authenticate an existing user:
```julia
using OrionAuth
user = OrionAuth.signin("user@example.com", "securePassword123")
println("User signed in successfully!")
```

### JWT Handling

Generate and verify JWT tokens for session management:
```julia
using OrionAuth.JWT  # Ensure that the JWT module is included.
token = OrionAuth.JWT.create_token(user)
verified = OrionAuth.JWT.verify_token(token)
println("JWT Verified: ", verified)
```

## Advanced Configuration

- **Email Confirmation:**  
  Set up secure token-based email verification to confirm user registration.

- **Password Reset:**  
  Implement password reset workflows with token distribution and expiry management.

- **Security Enhancements:**  
  Configure robust rate limiting, enable multi-factor authentication, and integrate with third-party identity providers (OAuth/OpenID Connect).

- **Audit and Compliance:**  
  Enable detailed audit trails and integrate external logging services to monitor security events.

- **Custom Policies:**  
  Define configurable password policies and account security settings for production readiness.

## Use Cases

- **Web Applications:**  
  Implement secure user authentication and session management using JWT.

- **API Gateways:**  
  Protect API endpoints with secure token verification and role-based access control.

- **Microservices:**  
  Manage decentralized authentication across services with federated login options.

- **Admin Dashboards:**  
  Monitor user actions with detailed logging, audit trails, and real-time analytics.

## Upcoming Features

- Email confirmation via secure token-based validation.
- Password reset functionality with token distribution and expiration.
- Enhanced logging, rate limiting, and multi-factor authentication.
- Third-party identity provider integration (OAuth/OpenID Connect).
- Support for alternative password hashing (e.g., Argon2 or bcrypt).

## Contributing

We welcome contributions! Please review our guidelines before submitting pull requests or issues. For any questions, submit an issue on GitHub.

Happy coding!
