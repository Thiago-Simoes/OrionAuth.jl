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
    
    local newUser
    try
        newUser = create(OrionAuth_User, Dict(
            "email" => email,
            "name" => name,
            "uuid" => uuid,
            "password" => hashed_password
            ))
    catch e
        existing = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
        if !isnothing(existing)
            error("User already exists")
        else
            rethrow(e)
        end
    end
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
        # Mitigate User Enumeration Timing Attack with a dummy verify
        dummy_hash = "\$argon2id\$v=19\$m=65536,t=2,p=1\$AAAAAAAAAAAAAAAAAAAAAA\$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        __ORION__VerifyPassword(password, dummy_hash)
        error("Invalid credentials")
    end

    # Check if account is locked
    if !isnothing(user.locked_until)
        # Handle cases where locked_until is a DateTime or a String representation
        lock_time = typeof(user.locked_until) == String ? DateTime(user.locked_until, dateformat"yyyy-mm-dd HH:MM:SS") : DateTime(user.locked_until)
        if Dates.now() < lock_time
            error("Account temporarily locked due to too many failed attempts")
        end
    end
    
    if !__ORION__VerifyPassword(password, user.password)
        # Increment failed attempts
        new_attempts = get(user, :failed_login_attempts, 0) + 1
        
        max_attempts = parse(Int, get(ENV, "OrionAuth_MAX_LOGIN_ATTEMPTS", "5"))
        lock_minutes = parse(Int, get(ENV, "OrionAuth_LOCKOUT_MINUTES", "15"))

        if new_attempts >= max_attempts
            # Lock the account
            unlock_time = Dates.format(Dates.now() + Minute(lock_minutes), "yyyy-mm-dd HH:MM:SS")
            update(OrionAuth_User, Dict("where" => Dict("id" => user.id)), Dict("locked_until" => unlock_time, "failed_login_attempts" => 0))
            @async LogAction("account_locked", user.id)
            error("Account temporarily locked due to too many failed attempts")
        else
            update(OrionAuth_User, Dict("where" => Dict("id" => user.id)), Dict("failed_login_attempts" => new_attempts))
            error("Invalid credentials")
        end
    end

    # Successful login, reset failed attempts
    update(OrionAuth_User, Dict("where" => Dict("id" => user.id)), Dict("failed_login_attempts" => 0, "locked_until" => nothing))
    
    @async LogAction("signin", user.id)

    payload = GenerateJWT(user)
    
    # Generate Refresh Token and create session
    refresh_token_hex = bytes2hex(Random.rand(RandomDevice(), UInt8, 32))
    refresh_exp_days = parse(Int, get(ENV, "OrionAuth_REFRESH_EXP_DAYS", "7"))
    expires_at = Dates.format(Dates.now(UTC) + Day(refresh_exp_days), "yyyy-mm-dd HH:MM:SS")
    
    create(OrionAuth_Session, Dict(
        "userId" => user.id,
        "refresh_token" => refresh_token_hex,
        "device_info" => "Unknown", # Can be extended to accept device info from Context
        "expires_at" => expires_at
    ))

    returnData = Dict(
        "access_token" => payload,
        "refresh_token" => refresh_token_hex,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return user, returnData
end

"""
    refresh_session(refresh_token::String) -> (User, String)

Exchange a valid refresh token for a new access token.

# Arguments
- `refresh_token::String`: The long-lived refresh token string

# Returns
- Tuple of (User object, JWT response JSON string)

# Throws
- `ResponseException(401, ...)`: If token is invalid, revoked, or expired
"""
function refresh_session(refresh_token::String)
    session = findFirst(OrionAuth_Session; query=Dict("where" => Dict("refresh_token" => refresh_token)))
    
    if isnothing(session)
        throw(ResponseException(401, [], "Invalid or revoked refresh token"))
    end
    
    if session.is_revoked == true || session.is_revoked == 1
        throw(ResponseException(401, [], "Invalid or revoked refresh token"))
    end
    
    expires_time = typeof(session.expires_at) == String ? DateTime(session.expires_at, dateformat"yyyy-mm-dd HH:MM:SS") : DateTime(session.expires_at)
    if Dates.now(UTC) > expires_time
        # Token expired, clean up
        update(OrionAuth_Session, Dict("where" => Dict("id" => session.id)), Dict("is_revoked" => true))
        throw(ResponseException(401, [], "Refresh token has expired"))
    end
    
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => session.userId)))
    if isnothing(user)
        throw(ResponseException(401, [], "User associated with session not found"))
    end
    
    # Generate new JWT
    payload = GenerateJWT(user)
    
    returnData = Dict(
        "access_token" => payload,
        "refresh_token" => refresh_token,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write
    
    @async LogAction("refresh_session", user.id)

    return user, returnData
end

"""
    revoke_session(refresh_token::String) -> Bool

Revokes a specific session immediately.

# Arguments
- `refresh_token::String`: The refresh token of the session to revoke

# Returns
- `Bool`: true if successfully revoked
"""
function revoke_session(refresh_token::String)
    session = findFirst(OrionAuth_Session; query=Dict("where" => Dict("refresh_token" => refresh_token)))
    if !isnothing(session)
        update(OrionAuth_Session, Dict("where" => Dict("id" => session.id)), Dict("is_revoked" => true))
        @async LogAction("revoke_session", session.userId)
        return true
    end
    return false
end

"""
    revoke_all_sessions(user_id::Int) -> Bool

Revokes all active sessions for a user (Kill switch).

# Arguments
- `user_id::Int`: The user's ID

# Returns
- `Bool`: true if successfully executed
"""
function revoke_all_sessions(user_id::Int)
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if isnothing(user)
        error("User not found")
    end
    
    updateMany(OrionAuth_Session, Dict("where" => Dict("userId" => user_id)), Dict("is_revoked" => true))
    @async LogAction("revoke_all_sessions", user_id)
    
    return true
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
    Auth(requiredPermission::Union{String, Vector{String}}=""; request=nothing) -> Dict

Simplified authentication with automatic context creation and error handling.
Automatically detects the framework and creates the appropriate context.

# Arguments
- `requiredPermission::Union{String, Vector{String}}`: Optional permission(s) to check
- `request`: Optional request object (auto-detected for Genie, required for HTTP.jl/Oxygen)

# Returns
- `Dict`: Decoded JWT payload

# Throws
- Framework-specific error response (automatically converted)

# Examples
```julia
# Genie (auto-detected, no request needed)
payload = Auth()
payload = Auth("admin")

# HTTP.jl or Oxygen (pass request)
payload = Auth(request=req)
payload = Auth("admin", request=req)
```
"""
function Auth(requiredPermission::Union{String, Vector{String}} = ""; request=nothing)
    try
        ctx = create_request_context(request)
        return Auth(ctx, requiredPermission)
    catch ex
        if ex isa ResponseException
            throw(handle_auth_exception(ex))
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
    getUserData(; request=nothing) -> Dict

Simplified method to extract user data from JWT with automatic context creation.
Automatically detects the framework and creates the appropriate context.

# Arguments
- `request`: Optional request object (auto-detected for Genie, required for HTTP.jl/Oxygen)

# Returns
- `Dict`: Decoded JWT payload

# Throws
- Framework-specific error response (automatically converted)

# Examples
```julia
# Genie (auto-detected)
user_data = getUserData()

# HTTP.jl or Oxygen
user_data = getUserData(request=req)
```
"""
function getUserData(; request=nothing)
    try
        ctx = create_request_context(request)
        return getUserData(ctx)
    catch ex
        if ex isa ResponseException
            throw(handle_auth_exception(ex))
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
