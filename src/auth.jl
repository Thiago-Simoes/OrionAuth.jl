
function LogAction(action::String, user)
    return LogAction(action, user.id)
end
function LogAction(action::String, userId::Int)
    ts = string(Dates.now())
    return create(OrionAuth_Log, Dict("userId"=>userId, "action"=>action, "timestamp"=>ts))
end

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
    extractBearerToken() -> String

Extracts the JWT from the `Authorization: Bearer <token>` header.
Throws 401 if header is missing, 400 if format is invalid.
"""
function extractBearerToken()
    headers = Genie.Requests.request().headers |> Dict

    auth_key = nothing
    for k in keys(headers)
        if lowercase(k) == "authorization"
        auth_key = k
        break
        end
    end
    if isnothing(auth_key)
        # Uses ExceptionalResponse - ExceptionalResponse(status, headers, body)
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end  

    auth_header = headers[auth_key]

    # Get JWT token from the header
    # Split using space
    parts = split(auth_header, " ")
    if length(parts) != 2 || parts[1] != "Bearer"
        throw(Genie.Exceptions.ExceptionalResponse(400, [], "Invalid Authorization header format"))
    end

    token = parts[2]
    return token
end

"""
    decodeJWT(token::AbstractString) -> Dict

Decodes and verifies the JWT signature.
Throws 401 if token is invalid or expired.
"""
function decodeJWT(token::AbstractString)
    try
        return __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"])
    catch
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Invalid or expired token"))
    end
end

"""
    Auth(requiredRole::Union{String, Vector{String}}="") -> Dict

1. Extracts and verifies JWT.
2. Optionally checks that the decoded payload contains the given role(s).
3. Returns the decoded payload for further use (e.g. getUserData can just call Auth()).

Throws:
- 401 if token missing/invalid,
- 403 if requiredRole is not present in user roles.
"""
function Auth(requiredPermission::Union{String, Vector{String}} = "")
    token = extractBearerToken()
    payload = decodeJWT(token)

    # normalize roles to a Vector{String}
    userPermissions = payload["permissions"] .|> r -> r[:permission] .|> String

    if requiredPermission != ""
        required = isa(requiredPermission, String) ? [requiredPermission] : requiredPermission
        if !all(r-> r in userPermissions, required)
            throw(Genie.Exceptions.ExceptionalResponse(403, [], "Forbidden: missing role(s) $(required)"))
        end
    end

    return payload
end


function getUserData()
    headers = Genie.Requests.request().headers |> Dict
    # Find user by Authorization header (case insensitive)
    auth_key = nothing
    for k in keys(headers)
        if lowercase(k) == "authorization"
        auth_key = k
        break
        end
    end
    if isnothing(auth_key)
        # Uses ExceptionalResponse - ExceptionalResponse(status, headers, body)
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end  

    auth_header = headers[auth_key]

    # Get JWT token from the header
    # Split using space
    parts = split(auth_header, " ")
    if length(parts) != 2 || parts[1] != "Bearer"
        throw(Genie.Exceptions.ExceptionalResponse(400, [], "Invalid Authorization header format"))
    end

    token = parts[2]

    # Decode JWT token
    payload = nothing
    try
        payload = __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"]) # Auto verify signature
    catch e
        # Return 401 Unauthorized if JWT is invalid
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end
    return payload
end
    

function GenerateJWT(user)
    payload = Dict("sub" => user.id, "name" => user.name, "email" => user.email, "uuid" => user.uuid, "roles" => getUserRoles(user.id), "permissions" => getUserPermissions(user.id))
    token = __ORION__EncodeJWT(payload, ENV["OrionAuth_SECRET"], ENV["OrionAuth_ALGORITHM"])
    return token
end
