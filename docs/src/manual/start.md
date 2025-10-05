# Quick Start

## Prerequisites
- Ensure you have Julia installed.
- Clone the repository and install dependencies:
  ```julia
  import Pkg
  Pkg.activate(".")
  Pkg.add("https://github.com/Thiago-Simoes/OrionAuth.jl")

  using OrionAuth

  ```

## Configuration
Create a `.env` file in the repository root with:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=pass
DB_NAME=dbname
DB_PORT=3306

OrionORM_LOG_LEVEL=error
OrionAuth_SECRET=your_secret_key_here
OrionAuth_ALGORITHM=HS512
OrionAuth_EXPIRATION=3600
OrionAuth_ISSUER=OrionAuth
OrionAuth_DBPREFIX=OrionAuth_
OrionAuth_MIN_PASSWORD_ITTERATIONS=25000
OrionAuth_PASSWORD_ALGORITHM=argon2id
OrionAuth_ENFORCE_EMAIL_CONFIRMATION=false
OrionAuth_EMAIL_VERIFICATION_TTL=86400
# Optional: OrionAuth_EMAIL_VERIFICATION_URL=https://yourapp.test/verify
```

## Initializing the Package
In your Julia script or REPL, load and initialize OrionAuth:
```julia
using OrionAuth
OrionAuth.init!()  # Loads all modules, including auth and JWT.
```

## User Operations
### Signing Up
Create a new user with:
```julia
user, response = OrionAuth.signup("user@example.com", "John Doe", "securePassword123")
println("User created with UUID: ", user.uuid)
println("Signup response payload: ", response)
```

### Signing In
Authenticate a user with:
```julia
user, token_payload = OrionAuth.signin("user@example.com", "securePassword123")
println("User signed in successfully! JWT payload: ", token_payload)
```

### Configuring email verification

To enforce email confirmation:

1. Set `OrionAuth_ENFORCE_EMAIL_CONFIRMATION=true` in your environment.
2. Provide an email callback and template:

```julia
using OrionAuth

set_email_sender!() do message::VerificationEmail
    # message.body already contains the rendered Mustache template
    println("Send email to ", message.to)
end

set_verification_email_template!(EmailTemplate(
    subject = "Verify your OrionAuth account",
    body = """
Hello {{name}},

Use the link {{verification_url}} to confirm your account. Token: {{token}}
""",
))
```

Consumers can trigger resends with `OrionAuth.resend_verification_token("user@example.com")` and finalize confirmation with `OrionAuth.verify_email(token)`.
