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

### Configuration

OrionAuth can be configured to work with your framework of choice:

**Option 1: Environment Variable (Recommended)**
```env
# In your .env file
ORIONAUTH_FRAMEWORK=genie  # or: oxygen, http, auto
```

**Option 2: Explicit Configuration**
```julia
using OrionAuth
configure_framework!(:genie)  # :oxygen, :http, or :auto
```

**Option 3: Auto-Detection (Default)**
OrionAuth automatically detects your framework when you use it.

### With Genie.jl

```julia
using Genie, Genie.Router
using OrionAuth

# Initialize OrionAuth
OrionAuth.init!()

# Load Genie adapter
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

# Protected route - auto-detects context, auto-handles errors!
route("/api/protected") do
    payload = Auth()  # That's it! No manual context or error handling
    return "Welcome, \$(payload["name"])!"
end

# Permission-protected route
route("/api/admin") do
    payload = Auth("admin")  # Automatically throws Genie exception if unauthorized
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

# Configure framework (or set ORIONAUTH_FRAMEWORK=http in .env)
configure_framework!(:http)

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
    
    # Protected endpoint - simplified!
    if req.target == "/protected"
        payload = Auth(request=req)  # Auto-converts errors to HTTP.Response!
        response_data = JSON3.write(Dict("message" => "Welcome, \$(payload["name"])!"))
        return HTTP.Response(200, response_data)
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

# Configure framework (or set ORIONAUTH_FRAMEWORK=oxygen in .env)
configure_framework!(:oxygen)

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

# Protected route - simplified!
@get "/protected" function(req)
    payload = Auth(request=req)  # Auto-converts errors to HTTP.Response!
    return json(Dict("message" => "Welcome, \$(payload["name"])!"))
end

serve()
```

## Core Concepts

### Simplified API (Recommended)

OrionAuth now provides a simplified API that eliminates repetition:

```julia
# Genie - no context creation needed!
route("/api/users") do
    payload = Auth("admin")  # Auto-detects, auto-handles errors
    # ... your code
end

# HTTP.jl / Oxygen - just pass the request
HTTP.serve() do req
    payload = Auth("admin", request=req)  # Auto-converts errors
    # ... your code
end
```

**Benefits:**
- ✅ No manual context creation in every route (DRY!)
- ✅ Automatic error conversion to framework-specific format
- ✅ Configure once, use everywhere
- ✅ Backward compatible with explicit context API

### Request Context (Advanced)

For advanced use cases, you can still use explicit contexts:

```julia
# Generic context (for testing or custom frameworks)
ctx = GenericRequestContext(Dict("Authorization" => "Bearer \$token"))

# Genie context
ctx = GenieRequestContext()  # Uses current Genie request

# HTTP.jl context
ctx = HTTPRequestContext(req)

# Oxygen context
ctx = OxygenRequestContext(req)

# Use with explicit context
payload = Auth(ctx, "admin")
```

### Authentication

**Simplified (Recommended):**
```julia
# Genie
payload = Auth()                    # Basic auth
payload = Auth("admin")             # With permission
payload = Auth(["read", "write"])   # Multiple permissions

# HTTP.jl / Oxygen
payload = Auth(request=req)
payload = Auth("admin", request=req)
```

**Explicit Context (Advanced):**
```julia
ctx = GenieRequestContext()
payload = Auth(ctx)
payload = Auth(ctx, "admin")
payload = Auth(ctx, ["read", "write"])
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

Your existing code continues to work! OrionAuth now offers even simpler APIs:

**Original (still works):**
```julia
route("/protected") do
    Auth()  # Works exactly as before
    return "Protected"
end
```

**Even Simpler (new):**
No changes needed! The simplified API is already what you're using. But now you can configure the framework once and it auto-handles errors:

```julia
# Configure once at startup (optional - auto-detects Genie)
configure_framework!(:genie)

# Or in .env
ORIONAUTH_FRAMEWORK=genie

# Then in all routes - same simple code, but errors auto-convert!
route("/protected") do
    Auth()  # Auto-detects context, auto-converts errors
    return "Protected"
end
```

**Manual Context (advanced, if needed):**
```julia
route("/protected") do
    ctx = GenieRequestContext()
    Auth(ctx)  # Explicit context
    return "Protected"
end
```

### Comparison: Before vs After

| **Before** | **After (Simplified)** |
|------------|------------------------|
| `ctx = GenieRequestContext(); try { Auth(ctx) } catch...` | `Auth()` |
| Manual error handling in every route | Automatic error conversion |
| Repeat context creation everywhere | Configure once, use everywhere |

## Configuration

OrionAuth uses environment variables for configuration. Create a `.env` file:

```env
# Framework Configuration (Optional - auto-detects if not set)
ORIONAUTH_FRAMEWORK=genie  # Options: genie, oxygen, http, auto

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
