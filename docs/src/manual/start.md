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

NebulaORM_LOG_LEVEL=error
OrionAuth_SECRET=your_secret_key_here
OrionAuth_ALGORITHM=HS512
OrionAuth_EXPIRATION=3600
OrionAuth_ISSUER=OrionAuth
OrionAuth_DBPREFIX=OrionAuth_
OrionAuth_MIN_PASSWORD_ITTERATIONS=25000
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
user = OrionAuth.signup("user@example.com", "John Doe", "securePassword123")
println("User created with UUID: ", user.uuid)
```

### Signing In
Authenticate a user with:
```julia
user = OrionAuth.signin("user@example.com", "securePassword123")
println("User signed in successfully!")
```
