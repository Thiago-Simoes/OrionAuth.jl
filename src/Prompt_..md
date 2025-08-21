    📄 OrionAuth.jl
      🔹 Conteúdo:
        ```
        module OrionAuth

using Base64
using DataFrames
using Dates
using DotEnv
using HTTP
using JSON3
using OrionORM
using Nettle
using Random
using SHA
using UUIDs
using Genie
using Genie.Requests

# Initialize .env
DotEnv.load!()


function init!()
    DotEnv.load!()

    dir = @__DIR__
    include(joinpath(dir, "bin/base64.jl"))
    
    include(joinpath(dir, "password.jl"))
    include(joinpath(dir, "roles.jl"))
    include(joinpath(dir, "auth.jl"))
    include(joinpath(dir, "jwt.jl"))
    include(joinpath(dir, "response.jl"))

    @eval begin
        OrionAuth_Log = Model(
            :OrionAuth_Log,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("action", TEXT(), []),
                ("timestamp", TEXT(), [])
            ]
        )
        
        OrionAuth_User = Model(
            :OrionAuth_User,
            [
                ("id",         INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("email",      TEXT(),    []),
                ("email_confirmed",      BOOLEAN(),    [Defalt(true)]),
                ("name",       TEXT(),    []),
                ("uuid",       OrionORM.UUID(),    []),
                ("password",   TEXT(),    []),
                ("created_at", TIMESTAMP(),    [Default("CURRENT_TIMESTAMP()")]),
                ("updated_at", TIMESTAMP(),    [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        OrionAuth_Permission = Model(
            :OrionAuth_Permission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("permission", VARCHAR(100), []),
                ("description", VARCHAR(250), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )
        
        OrionAuth_Role = Model(
            :OrionAuth_Role,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("role", VARCHAR(100), []),
                ("description", VARCHAR(250), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        OrionAuth_RolePermission = Model(
            :OrionAuth_RolePermission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("roleId", INTEGER(), []),
                ("permissionId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("roleId", OrionAuth_Role, "id", :belongsTo),
                ("permissionId", OrionAuth_Permission, "id", :belongsTo)
            ]
        )

        OrionAuth_UserRole = Model(
            :OrionAuth_UserRole,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("roleId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("userId", OrionAuth_User, "id", :belongsTo),
                ("roleId", OrionAuth_Role, "id", :belongsTo)
            ]
        )

        OrionAuth_UserPermission = Model(
            :OrionAuth_UserPermission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("permissionId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("userId", OrionAuth_User, "id", :belongsTo),
                ("permissionId", OrionAuth_Permission, "id", :belongsTo)
            ]
        )

        OrionAuth_EmailVerification = Model(
            :OrionAuth_EmailVerification,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("token", TEXT(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        OrionAuth_PasswordReset = Model(
            :OrionAuth_PasswordReset,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("token", TEXT(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )

    end

    nothing
end

export Auth, signin, signup, syncRolesPermissions, assignRole, assignPermission, syncRolesAndPermissions, getUserPermissions, getUserRoles, checkPermission, removeRole, __ORION__DecodeJWT, Unauthorized, getUserData

end # module OrionAuth

        ```

    📄 auth.jl
      🔹 Conteúdo:
        ```
        
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

        ```

    📁 bin/
    📁 email/
    📄 jwt.jl
      🔹 Conteúdo:
        ```
        # Implements JSON Web Token (JWT) encoding and decoding

# Based on https://datatracker.ietf.org/doc/html/rfc7519
# Accessed on 2025-05-03

using JSON3
using Base64
using Nettle

function __ORION__EncodeJWT(inputPayload::Dict, secret::AbstractString, algorithm::AbstractString="HS256")
    header = Dict("alg" => algorithm, "typ" => "JWT")
    headerEncoded = base64encode(JSON3.write(header))

    iat = round(Int, time())
    exp = iat + (parse(Int, ENV["OrionAuth_JWT_EXP"]) * 60)
    payload = Dict("sub" => inputPayload["sub"], "name" => inputPayload["name"], "iat" => iat, "exp" => exp)

    for key in ("email", "uuid", "roles", "permissions")
        if haskey(inputPayload, key)
            payload[key] = inputPayload[key]
        end
    end

    payload_encoded = base64url_encode(JSON3.write(payload))
    signature = __ORION__Sign(headerEncoded, payload_encoded, ENV["OrionAuth_SECRET"], algorithm)
    return "$headerEncoded.$payload_encoded.$signature"
end

function __ORION__DecodeJWT(token::AbstractString, secret::AbstractString = ENV["OrionAuth_SECRET"])
    parts = split(token, ".")
    if length(parts) != 3
        error("Invalid JWT format")
    end
    
    headerEncoded, payloadEncoded, signature = parts
    header = JSON3.read(base64url_decode2string(headerEncoded))
    payload = JSON3.read(base64url_decode2string(payloadEncoded))

    if header["alg"] != ENV["OrionAuth_ALGORITHM"]
        error("Invalid JWT algorithm")
    end

    verified = __ORION__Verify(headerEncoded, payloadEncoded, signature, ENV["OrionAuth_SECRET"], header["alg"])

    if !haskey(payload, "exp")
        error("JWT does not contain expiration time")
    end

    if payload["exp"] < time()
        error("JWT has expired")
    end

    if !verified
        error("Invalid JWT signature")
    end
    return payload
end


function __ORION__Sign(
    headerEncoded::AbstractString,
    payloadEncoded::AbstractString,
    secret::AbstractString,
    algorithm::AbstractString
)::AbstractString
    if algorithm == "HS256"
        h = HMACState("sha256", secret)
        Nettle.update!(h, "$headerEncoded.$payloadEncoded")
        
        return base64url_encode(Nettle.digest!(h)) # digest! returns a vector of UInt8
    elseif algorithm == "HS512"
        h = HMACState("sha512", secret)
        Nettle.update!(h, "$headerEncoded.$payloadEncoded")

        return base64url_encode(Nettle.digest!(h)) # digest! returns a vector of UInt8
    else
        error("Unsupported algorithm: $algorithm")
    end
end

function __ORION__Verify(
    headerEncoded::AbstractString,
    payloadEncoded::AbstractString,
    signature::AbstractString,
    secret::AbstractString,
    algorithm::AbstractString
)::Bool
    if algorithm in ["HS256", "HS512"]
        expectedSignature = __ORION__Sign(headerEncoded, payloadEncoded, secret, algorithm)
        return expectedSignature == signature
    else
        error("Unsupported algorithm: $algorithm")
    end
end

        ```

    📄 password.jl
      🔹 Conteúdo:
        ```
        using Random
using SHA

# Utils for password validation and hashing
function __ORION__HashPassword(password::String)
    generateSalt = Random.randstring(RandomDevice(), 32)
    nIterations = rand(parse(Int, ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"]):(parse(Int, ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"])*2))

    hashed = "$(password)&$(generateSalt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end
    return "sha512&$(hashed)&$(generateSalt)&$(nIterations)"
end

function __ORION__VerifyPassword(password::String, hashed::String)
    parts = split(hashed, "&")
    if length(parts) != 4
        return false
    end

    algorithm = parts[1]
    hashedPassword = parts[2]
    salt = parts[3]
    nIterations = parse(Int, parts[4])

    if algorithm != "sha512"
        return false
    end

    hashed = "$(password)&$(salt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end

    return hashed == hashedPassword
end
        ```

    📄 response.jl
      🔹 Conteúdo:
        ```
        function Unauthorized()
    return HTTP.Response(401, "Unauthorized")
end

function Forbidden()
    return HTTP.Response(403, "Forbidden")
end

function NotFound()
    return HTTP.Response(404, "Not Found")
end
        ```

    📄 roles.jl
      🔹 Conteúdo:
        ```
        
"""
    assign_role(user_id::Int, role::String)

Assign a role to a user.
"""
function assignRole(user_id::Int, role::String)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if user === nothing
        error("User not found")
    end

    # Check if role exists
    role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => role)))
    if role === nothing
        error("Role not found")
    end

    # Check if user already has the role
    existing = findFirst(OrionAuth_UserRole; query=Dict("where" => Dict("userId" => user_id, "roleId" => role.id)))
    if existing !== nothing
        error("User already has this role")
    end

    # Assign role to user
    new_user_role = create(OrionAuth_UserRole, Dict(
        "userId" => user_id,
        "roleId" => role.id
    ))

    # Log the action
    LogAction("assign_role: Assigned role \"$(role.role)\" (Role ID: $(role.id)) to user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
    return new_user_role    
end

function removeRole(user_id::Int, role::String)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if user === nothing
        error("User not found")
    end

    # Check if role exists
    role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => role)))
    if role === nothing
        error("Role not found")
    end

    # Check if user has the role
    existing = findFirst(OrionAuth_UserRole; query=Dict("where" => Dict("userId" => user_id, "roleId" => role.id)))
    if existing === nothing
        error("User does not have this role")
    end

    # Remove the role from the user
    delete(existing)

    # Log the action
    LogAction("remove_role: Removed role \"$(role.role)\" (Role ID: $(role.id)) from user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
    return true
end

function getUserRoles(user_id::Int)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserRole]))
    if user === nothing
        error("User not found")
    end

    # Get roles assigned to the user
    roles = user["OrionAuth_UserRole"]
    if isempty(roles)
        []
    end
    
    # Log the action
    userId = user["OrionAuth_User"].id
    LogAction("get_user_roles: Retrieved roles for user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
    return roles
end

function assignPermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserPermission]))
    if isnothing(user)
        error("User not found")
    end

    # Check if permission exists
    permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => permission)))
    if isnothing(permission)
        error("Permission not found")
    end

    # Check if user already has the permission
    # Using the user["OrionAuth_UserPermission"] to check if the user has the permission
    existing = user["OrionAuth_UserPermission"]
    if !isempty(existing)
        for perm in existing
            if perm.permissionId == permission.id
                error("User already has this permission")
            end
        end
    end

    # Assign permission to user
    new_user_permission = create(OrionAuth_UserPermission, Dict(
        "userId" => user_id,
        "permissionId" => permission.id
    ))

    # Log the action
    userId = user["OrionAuth_User"].id
    LogAction("assign_permission: Assigned permission \"$(permission.permission)\" (Permission ID: $(permission.id)) to user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
    return new_user_permission    
end

function removePermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserPermission]))
    if user === nothing
        error("User not found")
    end

    # Check if permission exists in the database
    # Using the user["OrionAuth_UserPermission"] to check if the user has the permission
    if isempty(user["OrionAuth_UserPermission"])
        error("Permission not found")
    end

    existing = nothing
    for perm in user["OrionAuth_UserPermission"]
        if perm.permissionId == permission
            existing = perm
            break
        end
    end

    # Remove the permission from the user
    delete!(existing)

    # Log the action
    userId = user["OrionAuth_User"].id
    LogAction("remove_permission: Removed permission \"$(permission.permission)\" (Permission ID: $(permission.id)) from user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
    return true
end

function getUserPermissions(user_id::Int)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserRole, OrionAuth_UserPermission]))
    if isnothing(user)
        error("User not found")
    end

    # Get permissions assigned to the user
    permissions = []
    
    # Get permissions for each role
    for role in user["OrionAuth_UserRole"]
        role_permissions = findMany(OrionAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.roleId)))
        if role_permissions !== nothing
            permissions = vcat(permissions, role_permissions)
        end
    end
    # Remove duplicates
    permissions = unique(permissions)

    # Get permissions directly assigned to role permissions
    for perm in user["OrionAuth_UserPermission"]
        permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("id" => perm.permissionId)))
        if permission !== nothing
            permissions = vcat(permissions, permission)
        end
    end

    permissionsList = []
    for perm in permissions
        if isa(perm, OrionAuth_Permission)
            push!(permissionsList, perm)
            continue
        end

        permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("id" => perm.permissionId)))
        if permission !== nothing
            permissionsList = vcat(permissionsList, permission)
        end
    end

    # Log the action
    LogAction("get_user_permissions: Retrieved permissions for user ID $(user_id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
    return permissionsList
end

function checkPermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if user === nothing
        error("User not found")
    end

    # Check if permission exists
    permissions = getUserPermissions(user.id)
    if isempty(permissions)
        error("Permission not found")
    end

    # Check if user has the permission
    for perm in permissions
        if perm.permission == permission
            return true
        end
    end
    return false   
end


"""
    syncRolesAndPermissions(roles::Dict{String, Vector{String}})

Sync roles and permissions from a Dict, creating any missing roles, permissions, and relations.

Example:

"""
function syncRolesAndPermissions(roles::Dict{String, Vector{String}})
    # Iterate over each role
    for (role_name, permissions) in roles
        # Check if the role already exists
        role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => role_name)))
        if role === nothing
            # Create the role if it doesn't exist
            role = create(OrionAuth_Role, Dict(
                "role" => role_name,
                "description" => "Role: $role_name"
            ))
        end

        # Iterate over each permission for the role
        for permission_name in permissions
            # Check if the permission already exists
            permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => permission_name)))
            if permission === nothing
                # Create the permission if it doesn't exist
                permission = create(OrionAuth_Permission, Dict(
                    "permission" => permission_name,
                    "description" => "Permission: $permission_name"
                ))
            end

            # Check if the role-permission relation already exists
            existing_relation = findFirst(OrionAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => permission.id)))
            if existing_relation === nothing
                # Create the relation if it doesn't exist
                create(OrionAuth_RolePermission, Dict(
                    "roleId" => role.id,
                    "permissionId" => permission.id
                ))
            end
        end
    end

    return true
end
        ```

