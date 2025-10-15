# OrionAuth.jl

## Objective

This project aims to provide a modern, complete, and robust Web Authentication package for Julia that is **framework-agnostic**.

OrionAuth.jl now supports multiple web frameworks including:
- **Genie.jl** - Full-featured MVC web framework
- **Oxygen.jl** - Lightweight web framework  
- **HTTP.jl** - Direct HTTP server usage
- **Generic** - Any framework with custom request context

**Security note:** While production-ready features are being added, please review security considerations for your use case.

## Features

- 🔐 **JWT-based Authentication** with HS256/HS512 algorithms
- 👥 **Role-Based Access Control (RBAC)** with permissions
- 🔑 **Multiple Password Hashing Algorithms** (Argon2id, SHA-512 legacy)
- 🌐 **Framework-Agnostic Design** - works with Genie, Oxygen, HTTP.jl and more
- 📝 **Comprehensive API** with docstrings and type safety
- ✅ **Well-Tested** with extensive test coverage

## Installation

The package can be installed with the Julia package manager.
From the Julia REPL, type `]` to enter the Pkg REPL mode and run:

```
pkg> add "https://github.com/Thiago-Simoes/OrionAuth.jl"
```

Or, equivalently, via the `Pkg` API:

```julia
julia> import Pkg; Pkg.add("https://github.com/Thiago-Simoes/OrionAuth.jl")
```

## Quick Start

### With Genie.jl

```julia
using Genie, Genie.Router
using OrionAuth

# Initialize OrionAuth
OrionAuth.init!()

# Load Genie adapter (automatically done when Genie is loaded first)
Base.include(OrionAuth, joinpath(dirname(pathof(OrionAuth)), "adapters/genie.jl"))

# Public route - signup/signin
route("/api/auth/signup") do
    payload = jsonpayload()
    user, jwt_data = signup(payload["email"], payload["name"], payload["password"])
    return jwt_data
end

route("/api/auth/signin") do
    payload = jsonpayload()
    user, jwt_data = signin(payload["email"], payload["password"])
    return jwt_data
end

# Protected route - requires authentication
route("/api/protected") do
    payload = Auth()  # Throws 401 if not authenticated
    return "Welcome, \$(payload["name"])!"
end

# Permission-protected route
route("/api/admin") do
    payload = Auth("admin")  # Requires "admin" permission
    return "Admin access granted"
end

Genie.up()
```

### With HTTP.jl

```julia
using HTTP
using JSON3
using OrionAuth

# Initialize OrionAuth
OrionAuth.init!()

# Create HTTP server
HTTP.serve("127.0.0.1", 8080) do req
    # Signup endpoint
    if req.target == "/signup" && req.method == "POST"
        data = JSON3.read(String(req.body))
        user, jwt_data = signup(data["email"], data["name"], data["password"])
        return HTTP.Response(200, jwt_data)
    end
    
    # Signin endpoint
    if req.target == "/signin" && req.method == "POST"
        data = JSON3.read(String(req.body))
        user, jwt_data = signin(data["email"], data["password"])
        return HTTP.Response(200, jwt_data)
    end
    
    # Protected endpoint
    if req.target == "/protected"
        ctx = HTTPRequestContext(req)
        try
            payload = Auth(ctx)
            response_data = JSON3.write(Dict("message" => "Welcome, \$(payload["name"])!"))
            return HTTP.Response(200, response_data)
        catch ex
            if ex isa ResponseException
                return to_http_response(ex)
            end
            rethrow()
        end
    end
    
    return HTTP.Response(404, "Not Found")
end
```

### With Oxygen.jl

```julia
using Oxygen
using JSON3
using OrionAuth

# Initialize OrionAuth
OrionAuth.init!()

# Signup route
@post "/signup" function(req)
    data = JSON3.read(String(req.body))
    user, jwt_data = signup(data["email"], data["name"], data["password"])
    return json(jwt_data)
end

# Signin route
@post "/signin" function(req)
    data = JSON3.read(String(req.body))
    user, jwt_data = signin(data["email"], data["password"])
    return json(jwt_data)
end

# Protected route
@get "/protected" function(req)
    ctx = OxygenRequestContext(req)
    try
        payload = Auth(ctx)
        return json(Dict("message" => "Welcome, \$(payload["name"])!"))
    catch ex
        if ex isa ResponseException
            return to_oxygen_response(ex)
        end
        rethrow()
    end
end

serve()
```

## Core Concepts

### Request Context

OrionAuth uses a `RequestContext` abstraction to work with different frameworks:

```julia
# Generic context (for testing or custom frameworks)
ctx = GenericRequestContext(Dict("Authorization" => "Bearer \$token"))

# Genie context
ctx = GenieRequestContext()  # Uses current Genie request

# HTTP.jl context
ctx = HTTPRequestContext(req)

# Oxygen context
ctx = OxygenRequestContext(req)
```

### Authentication

```julia
# Basic authentication - verifies JWT and returns payload
payload = Auth(ctx)
user_id = payload["sub"]
user_email = payload["email"]

# With permission check
payload = Auth(ctx, "admin")  # Requires "admin" permission
payload = Auth(ctx, ["read", "write"])  # Requires both permissions
```

### Roles and Permissions

```julia
# Create roles and permissions
syncRolesAndPermissions(Dict(
    "admin" => ["read", "write", "delete"],
    "user" => ["read"],
    "moderator" => ["read", "write"]
))

# Assign role to user
assignRole(user_id, "admin")

# Assign direct permission
assignPermission(user_id, "special_action")

# Check user permissions
permissions = getUserPermissions(user_id)
has_admin = checkPermission(user_id, "admin")

# Remove role
removeRole(user_id, "moderator")
```

### Password Hashing

OrionAuth supports multiple password hashing algorithms:

```julia
# Argon2id (default, recommended)
hashed = hash_password("my_password")

# Legacy SHA-512 (for backward compatibility)
hashed = hash_password("my_password", algorithm=:sha512)

# Verify password (auto-detects algorithm)
is_valid = verify_password(stored_hash, "my_password")
```

Configure the default algorithm via environment variable:
```bash
OrionAuth_PASSWORD_ALGORITHM=argon2id  # or sha512
```

## Migration Guide

### For Existing Genie Users

If you're currently using OrionAuth with Genie, your code will continue to work with backward compatibility:

**Old way (still works):**
```julia
route("/protected") do
    Auth()  # Uses Genie.Requests.request() internally
    return "Protected"
end
```

**New way (recommended):**
```julia
route("/protected") do
    ctx = GenieRequestContext()
    Auth(ctx)
    return "Protected"
end
```

The new approach makes testing easier and allows you to potentially migrate to other frameworks in the future.

## Configuration

OrionAuth uses environment variables for configuration. Create a `.env` file:

```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=your_database
DB_PORT=3306

# JWT Configuration
OrionAuth_SECRET=your-secret-key-here
OrionAuth_ALGORITHM=HS256  # or HS512
OrionAuth_JWT_EXP=30  # expiration in minutes

# Password Configuration
OrionAuth_PASSWORD_ALGORITHM=argon2id  # or sha512
OrionAuth_MIN_PASSWORD_ITTERATIONS=25000  # for SHA-512 legacy
```

## Documentation

- [**STABLE**](https://thiago-simoes.github.io/ORM.jl/) &mdash; **documentation of the most recently tagged version.**

## Project Status

The package is tested against, and being developed for, Julia `1.6` and above on Linux, macOS, and Windows.

## Collaboration

Contributions are welcome!  
Feel free to open pull requests or issues with suggestions and enhancements.

## Vulnerabilities

If you discover any **vulnerabilities**, please report them via issues.

### How to build docs?
$ julia --project make.jl

## License
OrionAuth is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
