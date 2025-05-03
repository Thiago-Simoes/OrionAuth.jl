# Quick Start

## Prerequisites
- Ensure you have Julia installed.
- Clone the repository and install dependencies:
  ```julia
  import Pkg
  Pkg.activate(".")
  Pkg.add("https://github.com/Thiago-Simoes/NebulaAuth.jl")

  using NebulaAuth

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
NEBULAAUTH_SECRET=your_secret_key_here
NEBULAAUTH_ALGORITHM=HS512
NEBULAAUTH_EXPIRATION=3600
NEBULAAUTH_ISSUER=NebulaAuth
NEBULAAUTH_DBPREFIX=NebulaAuth_
NEBULAAUTH_MIN_PASSWORD_ITTERATIONS=25000
```

## Initializing the Package
In your Julia script or REPL, load and initialize NebulaAuth:
```julia
using NebulaAuth
NebulaAuth.init!()  # Loads all modules, including auth and JWT.
```

## User Operations
### Signing Up
Create a new user with:
```julia
user = NebulaAuth.signup("user@example.com", "John Doe", "securePassword123")
println("User created with UUID: ", user.uuid)
```

### Signing In
Authenticate a user with:
```julia
user = NebulaAuth.signin("user@example.com", "securePassword123")
println("User signed in successfully!")
```
