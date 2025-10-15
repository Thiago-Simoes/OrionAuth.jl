"""
    LogAction(action::String, user) -> Any
    LogAction(action::String, userId::Int) -> Any

Log a user action to the database.

# Arguments
- `action::String`: Description of the action performed
- `user`: User object with an id field
- `userId::Int`: User ID

# Returns
- Database record of the logged action

# Examples
```julia
LogAction("signup", user)
LogAction("signin", 123)
```
"""
function LogAction(action::String, user)
    return LogAction(action, user.id)
end

function LogAction(action::String, userId::Int)
    ts = string(Dates.now())
    return create(OrionAuth_Log, Dict("userId"=>userId, "action"=>action, "timestamp"=>ts))
end

"""
    signup(email::String, name::String, password::String) -> (User, String)

Register a new user with email, name, and password.

# Arguments
- `email::String`: User email address (e.g., "user@example.com")
- `name::String`: User full name (e.g., "John Doe")
- `password::String`: Plain text password (will be hashed)

# Returns
- Tuple of (User object, JWT response JSON string)

# Throws
- `error("User already exists")`: If email is already registered

# Examples
```julia
user, jwt_data = signup("user@example.com", "John Doe", "securepass123")
println(user.email)  # "user@example.com"
token = JSON3.parse(jwt_data)["access_token"]
```
"""
function signup(email::String, name::String, password::String)
    existing = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if !isnothing(existing)
        error("User already exists")
    end
    uuid = string(UUIDs.uuid4())
    hashed_password = __ORION__HashPassword(password)
    ts = string(Dates.now())
    newUser = create(OrionAuth_User, Dict(
        "email" => email,
        "name" => name,
        "uuid" => uuid,
        "password" => hashed_password
        ))
    @async LogAction("signup", newUser.id)
    
    payload = GenerateJWT(newUser)
    
    returnData = Dict(
        "access_token" => payload,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return newUser, returnData
end

"""
    signin(email::String, password::String) -> (User, String)

Authenticate a user with email and password.

# Arguments
- `email::String`: User email address (e.g., "user@example.com")
- `password::String`: Plain text password

# Returns
- Tuple of (User object, JWT response JSON string)

# Throws
- `error("User not found")`: If email doesn't exist
- `error("Invalid password")`: If password is incorrect

# Examples
```julia
user, jwt_data = signin("user@example.com", "securepass123")
token = JSON3.parse(jwt_data)["access_token"]
```
"""
function signin(email::String, password::String)
    local user = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if user === nothing
        error("User not found")
    end
    
    if !__ORION__VerifyPassword(password, user.password)
        error("Invalid password")
    end
    @async LogAction("signin", user.id)

    payload = GenerateJWT(user)

    returnData = Dict(
        "access_token" => payload,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return user, returnData
end

"""
    extractBearerToken(ctx::RequestContext) -> String

Extract JWT token from Authorization Bearer header.

# Arguments
- `ctx::RequestContext`: Request context from any supported framework

# Returns
- `String`: JWT token

# Throws
- `ResponseException(401, ...)`: If Authorization header is missing
- `ResponseException(400, ...)`: If Authorization header format is invalid

# Examples
```julia
# With Genie
ctx = GenieRequestContext()
token = extractBearerToken(ctx)

# With HTTP.jl
ctx = HTTPRequestContext(req)
token = extractBearerToken(ctx)
```
"""
function extractBearerToken(ctx::RequestContext)
    return extract_bearer_token(ctx)
end

"""
    extractBearerToken() -> String

Legacy Genie-specific method. Extracts JWT from Authorization Bearer header.
For new code, use extractBearerToken(ctx::RequestContext).
Requires Genie to be loaded.

# Returns
- `String`: JWT token

# Throws
- `Genie.Exceptions.ExceptionalResponse(401, ...)`: If header is missing
- `Genie.Exceptions.ExceptionalResponse(400, ...)`: If format is invalid
"""
function extractBearerToken()
    if !isdefined(Main, :Genie)
        error("Genie must be loaded to use the no-argument extractBearerToken(). Use extractBearerToken(ctx::RequestContext) instead.")
    end
    try
        # Dynamically load Genie adapter if not yet loaded
        if !isdefined(@__MODULE__, :GenieRequestContext)
            include(joinpath(@__DIR__, "adapters/genie.jl"))
        end
        ctx = GenieRequestContext()
        return extract_bearer_token(ctx)
    catch ex
        if ex isa ResponseException
            throw(to_genie_response(ex))
        end
        rethrow()
    end
end

"""
    decodeJWT(token::AbstractString) -> Dict

Decode and verify JWT signature.

# Arguments
- `token::AbstractString`: JWT token string

# Returns
- `Dict`: Decoded JWT payload with user data

# Throws
- `ResponseException(401, ...)`: If token is invalid or expired

# Examples
```julia
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
payload = decodeJWT(token)
println(payload["email"])
```
"""
function decodeJWT(token::AbstractString)
    try
        return __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"])
    catch
        throw(ResponseException(401, [], "Invalid or expired token"))
    end
end

"""
    Auth(ctx::RequestContext, requiredPermission::Union{String, Vector{String}}="") -> Dict

Authenticate and authorize request using JWT token.

# Arguments
- `ctx::RequestContext`: Request context from any supported framework
- `requiredPermission::Union{String, Vector{String}}`: Optional permission(s) to check (default: "")

# Returns
- `Dict`: Decoded JWT payload with user information

# Throws
- `ResponseException(401, ...)`: If token is missing/invalid
- `ResponseException(403, ...)`: If required permission is not present

# Examples
```julia
# Basic authentication
ctx = GenieRequestContext()
payload = Auth(ctx)
user_id = payload["sub"]

# With permission check
payload = Auth(ctx, "admin")
payload = Auth(ctx, ["read", "write"])
```
"""
function Auth(ctx::RequestContext, requiredPermission::Union{String, Vector{String}} = "")
    token = extractBearerToken(ctx)
    payload = decodeJWT(token)

    # normalize permissions to a Vector{String}
    userPermissions = payload["permissions"] .|> r -> r[:permission] .|> String

    if requiredPermission != ""
        required = isa(requiredPermission, String) ? [requiredPermission] : requiredPermission
        if !all(r-> r in userPermissions, required)
            throw(ResponseException(403, [], "Forbidden: missing permission(s) $(required)"))
        end
    end

    return payload
end

"""
    Auth(requiredPermission::Union{String, Vector{String}}="") -> Dict

Legacy Genie-specific authentication method.
For new code, use Auth(ctx::RequestContext, ...).
Requires Genie to be loaded.

# Arguments
- `requiredPermission::Union{String, Vector{String}}`: Optional permission(s) to check

# Returns
- `Dict`: Decoded JWT payload

# Throws
- `Genie.Exceptions.ExceptionalResponse(401, ...)`: If token is missing/invalid
- `Genie.Exceptions.ExceptionalResponse(403, ...)`: If required permission is not present
"""
function Auth(requiredPermission::Union{String, Vector{String}} = "")
    if !isdefined(Main, :Genie)
        error("Genie must be loaded to use the no-argument Auth(). Use Auth(ctx::RequestContext, ...) instead.")
    end
    try
        # Dynamically load Genie adapter if not yet loaded
        if !isdefined(@__MODULE__, :GenieRequestContext)
            include(joinpath(@__DIR__, "adapters/genie.jl"))
        end
        ctx = GenieRequestContext()
        return Auth(ctx, requiredPermission)
    catch ex
        if ex isa ResponseException
            throw(to_genie_response(ex))
        end
        rethrow()
    end
end

"""
    getUserData(ctx::RequestContext) -> Dict

Extract user data from JWT token in request.

# Arguments
- `ctx::RequestContext`: Request context from any supported framework

# Returns
- `Dict`: Decoded JWT payload with user information

# Throws
- `ResponseException(401, ...)`: If Authorization header is missing or JWT is invalid
- `ResponseException(400, ...)`: If Authorization header format is invalid

# Examples
```julia
ctx = HTTPRequestContext(req)
user_data = getUserData(ctx)
println(user_data["email"])
```
"""
function getUserData(ctx::RequestContext)
    token = extractBearerToken(ctx)
    
    # Decode JWT token
    try
        payload = __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"])
        return payload
    catch e
        throw(ResponseException(401, [], "Invalid or expired token"))
    end
end

"""
    getUserData() -> Dict

Legacy Genie-specific method to extract user data from JWT.
For new code, use getUserData(ctx::RequestContext).
Requires Genie to be loaded.

# Returns
- `Dict`: Decoded JWT payload

# Throws
- `Genie.Exceptions.ExceptionalResponse(401, ...)`: If header is missing or JWT is invalid
- `Genie.Exceptions.ExceptionalResponse(400, ...)`: If header format is invalid
"""
function getUserData()
    if !isdefined(Main, :Genie)
        error("Genie must be loaded to use the no-argument getUserData(). Use getUserData(ctx::RequestContext) instead.")
    end
    try
        # Dynamically load Genie adapter if not yet loaded
        if !isdefined(@__MODULE__, :GenieRequestContext)
            include(joinpath(@__DIR__, "adapters/genie.jl"))
        end
        ctx = GenieRequestContext()
        return getUserData(ctx)
    catch ex
        if ex isa ResponseException
            throw(to_genie_response(ex))
        end
        rethrow()
    end
end

"""
    GenerateJWT(user) -> String

Generate a JWT token for a user with roles and permissions.

# Arguments
- `user`: User object with id, name, email, and uuid fields

# Returns
- `String`: JWT token

# Examples
```julia
user = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => "user@example.com")))
token = GenerateJWT(user)
```
"""
function GenerateJWT(user)
    payload = Dict("sub" => user.id, "name" => user.name, "email" => user.email, "uuid" => user.uuid, "roles" => getUserRoles(user.id), "permissions" => getUserPermissions(user.id))
    token = __ORION__EncodeJWT(payload, ENV["OrionAuth_SECRET"], ENV["OrionAuth_ALGORITHM"])
    return token
end
