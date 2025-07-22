    �� README.md
      🔹 Conteúdo inicial:
        ```
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
 
 OrionORM_LOG_LEVEL=error
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
 ...
        ```

    📁 build/
    �� make.jl
      🔹 Conteúdo inicial:
        ```
        import Pkg
 Pkg.activate(".")
 using Documenter, OrionAuth
 
 push!(LOAD_PATH,"../src/")
 makedocs(
     sitename="OrionAuth.jl",
     modules=[OrionAuth],
     pages = [
     "Home" => "index.md",
     "Manual" => ["manual/start.md", "manual/relationships.md", "manual/security.md"],
     "Security" => ["security/security_policy.md", "security/references.md", "security/threat_model.md", "security/vulnerability_report.md"],
     "Reference" => ["Reference/API.md"]
     ]
 )
 ...
        ```

    📁 src/
    �� OrionAuth.jl
      🔹 Conteúdo inicial:
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
 
 # Initialize .env
 DotEnv.load!()
 
 function init!()
     dir = @__DIR__
     
     include(joinpath(dir, "bin/base64.jl"))
 
     include(joinpath(dir, "password.jl"))
     include(joinpath(dir, "roles.jl"))
     include(joinpath(dir, "auth.jl"))
     include(joinpath(dir, "jwt.jl"))
 
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
 
 export OrionAuth_User, signin, signup, syncRolesPermissions, AssignRole, AssignPermissionToUser, SyncRolesAndPermissions, GetUserPermissions, GetUserRoles, CheckPermission, RemoveRole
 
 end # module OrionAuth
 ...
        ```

    �� auth.jl
      🔹 Conteúdo inicial:
        ```
        
 function LogAction(action::String, userId::Int)
     ts = string(Dates.now())
     return create(OrionAuth_Log, Dict("userId"=>userId, "action"=>action, "timestamp"=>ts))
 end
 
 function signup(email::String, name::String, password::String)
     existing = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
     if existing !== nothing
         error("User already exists")
     end
     uuid = string(UUIDs.uuid4())
     hashed_password = __ORION__HashPassword(password)
     ts = string(Dates.now())
     local newUser = create(OrionAuth_User, Dict(
         "email"      => email,
         "name"       => name,
         "uuid"       => uuid,
         "password"   => hashed_password
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
 
 function GenerateJWT(user)
     payload = Dict("sub" => user.id, "name" => user.name, "email" => user.email, "uuid" => user.uuid, "roles" => GetUserRoles(user.id), "permissions" => GetUserPermissions(user.id))
     token = __ORION__EncodeJWT(payload, ENV["OrionAuth_SECRET"], ENV["OrionAuth_ALGORITHM"])
     return token
 end
 ...
        ```

    📁 bin/
    �� jwt.jl
      🔹 Conteúdo inicial:
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
 ...
        ```

    �� password.jl
      🔹 Conteúdo inicial:
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
 end...
        ```

    �� roles.jl
      🔹 Conteúdo inicial:
        ```
        
 """
     assign_role(user_id::Int, role::String)
 
 Assign a role to a user.
 """
 function AssignRole(user_id::Int, role::String)
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
     LogAction("assign_role: Assigned role \"$(role.role)\" (Role ID: $(role.id)) to user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user.id)
     return new_user_role    
 end
 
 function RemoveRole(user_id::Int, role::String)
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
 
 function GetUserRoles(user_id::Int)
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
     LogAction("get_user_roles: Retrieved roles for user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"].id)
     return roles
 end
 
 function AssignPermission(user_id::Int, permission::String)
     # Check if user exists
     user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserPermission]))
     if user === nothing
         error("User not found")
     end
 
     # Check if permission exists
     permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => permission)))
     if permission === nothing
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
 
 function RemovePermission(user_id::Int, permission::String)
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
 
 function GetUserPermissions(user_id::Int)
     # Check if user exists
     user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [OrionAuth_UserRole]))
     if user === nothing
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
 
     permissionsList = []
     for perm in permissions
         permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("id" => perm.permissionId)))
         if permission !== nothing
             permissionsList = vcat(permissionsList, permission)
         end
     end
 
 
     # Log the action
     LogAction("get_user_permissions: Retrieved permissions for user ID $(user_id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"].id)
     return permissionsList
 end
 
 function CheckPermission(user_id::Int, permission::String)
     # Check if user exists
     user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user_id)))
     if user === nothing
         error("User not found")
     end
 
     # Check if permission exists
     permissions = GetUserPermissions(user.id)
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
     SyncRolesAndPermissions(roles::Dict{String, Vector{String}})
 
 Sync roles and permissions from a Dict, creating any missing roles, permissions, and relations.
 
 Example:
 
 """
 function SyncRolesAndPermissions(roles::Dict{String, Vector{String}})
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
 end...
        ```

    �� runtests.jl
      🔹 Conteúdo inicial:
        ```
        using Test
 using Dates
 
 using DotEnv
 DotEnv.load!()
 
 using JSON3
 using OrionORM
 
 using OrionAuth
 OrionAuth.init!()
 
 @testset "OrionAuth" begin
     user, jwt = signup("th.simoes@proton.me", "Thiago Simões", "123456")
     userLogging, jwt = signin("th.simoes@proton.me", "123456")
     @testset verbose=true "Authentication - Login/Register" begin
         @test userLogging !== nothing
         @test userLogging.id == user.id
         @test userLogging.name == user.name
         @test userLogging.email == user.email
     end
 
     Model(
         :Profile,
         [
             ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
             ("userId", INTEGER(), []),
             ("bio", TEXT(), []),
             ("location", TEXT(), []),
             ("website", TEXT(), []),
             ("created_at", TEXT(), []),
             ("updated_at", TEXT(), [])
         ],
         [
             ("userId", OrionAuth_User, "id", :belongsTo)
         ]
     )
 
     profile = create(Profile, Dict(
         "userId" => user.id,
         "bio" => "Software Engineer",
         "location" => "Brazil",
         "website" => "https://example.com"
     ))
 
     @testset verbose=true "Relationship" begin
         @test profile.userId == user.id
         @test profile.bio == "Software Engineer"
 
         # # Testar busca
         profile_user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => profile.userId)))
         @test profile_user !== nothing
         @test profile_user.id == user.id
 
         # # Buscar o perfil do usuário
         profile_user = findFirst(Profile; query=Dict("where" => Dict("userId" => user.id)))
         @test profile_user !== nothing
         @test profile_user.id == profile.id
         @test profile_user.userId == user.id
 
         # # Buscar pela relação
         profile_user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => profile.userId), "include" => [Profile]))
         @test profile_user !== nothing
         @test profile_user["OrionAuth_User"].id == user.id
         @test profile_user["Profile"][1].id == profile.id
     end
 
     role = create(OrionAuth_Role, Dict(
         "role" => "admin",
         "description" => "Administrator role"
     ))
 
     @testset verbose=true "Roles" begin
         @test role !== nothing
         @test role.role == "admin"
         @test role.description == "Administrator role"
 
         role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => "admin")))
         @test role !== nothing
         @test role.role == "admin"
 
         AssignRole(user.id, role.role)
         user_role = findFirst(OrionAuth_UserRole; query=Dict("where" => Dict("userId" => user.id, "roleId" => role.id)))
         @test user_role !== nothing
         @test user_role.userId == user.id
 
         user_with_role = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserRole]))
         @test user_with_role !== nothing
         @test user_with_role["OrionAuth_UserRole"][1].userId == user.id
     end
 
     @testset verbose=true "Permissions - Create and assign" begin
         permission = create(OrionAuth_Permission, Dict(
             "permission" => "read",
             "description" => "Read permission"
         ))
 
         @test permission !== nothing
         @test permission.permission == "read"
         @test permission.description == "Read permission"
 
         permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => "read")))
         @test permission !== nothing
         @test permission.permission == "read"
 
         AssignPermission(user.id, permission.permission)
         user_permission = findFirst(OrionAuth_UserPermission; query=Dict("where" => Dict("userId" => user.id, "permissionId" => permission.id)))
         @test user_permission !== nothing
         @test user_permission.userId == user.id
 
         user_with_permission = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserPermission]))
         @test user_with_permission !== nothing
         @test user_with_permission["OrionAuth_UserPermission"][1].userId == user.id
     end
 
     @testset verbose=true "Permissions - Inheritance" begin
         parent_permission = create(OrionAuth_Permission, Dict(
             "permission" => "write",
             "description" => "Write permission"
         ))
 
         @test parent_permission !== nothing
         @test parent_permission.permission == "write"
         @test parent_permission.description == "Write permission"
 
         parent_permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => "write")))
         @test parent_permission !== nothing
         @test parent_permission.permission == "write"
 
         deleteMany(OrionAuth_UserPermission, Dict("where" => Dict("userId" => user.id)))
 
         SyncRolesAndPermissions(Dict(
             "admin" => ["read", "write", "delete"],
             "user" => ["read"],
             "god" => ["read", "write", "delete", "sudo"]
         ))
 
         role_permission = findFirst(OrionAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => parent_permission.id)))
         @test role_permission !== nothing
         @test role_permission.roleId == role.id
 
         role_with_permission = findFirst(OrionAuth_Role; query=Dict("where" => Dict("id" => role.id), "include" => [OrionAuth_RolePermission]))
         @test role_with_permission !== nothing
         @test role_with_permission["OrionAuth_RolePermission"][1].roleId == role.id
 
         user_with_role_permission = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserRole]))
         @test user_with_role_permission !== nothing
         @test user_with_role_permission["OrionAuth_UserRole"][1].userId == user.id
 
         @test OrionAuth.GetUserPermissions(user.id) .|> (x -> x.permission) == ["read", "write", "delete"]
         @test CheckPermission(user.id, "read") == true
     end
 
     @testset verbose=true "Permissions - Direct permission" begin
         # Add direct permission to user
         AssignPermission(user.id, "sudo")
         user_with_permission = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserPermission]))
         @test user_with_permission !== nothing
         @test user_with_permission["OrionAuth_UserPermission"][1].userId == user.id
         @test OrionAuth.GetUserPermissions(user.id) .|> (x -> x.permission) == ["read", "write", "delete", "sudo"]
         @test CheckPermission(user.id, "sudo") == true
     end
 
     @testset verbose=true "SignIn and SignUp - JWT" begin
         @testset verbose=true "SignUp" begin
             # Use signup function to get JWT and user
             user, jwt = signup("eu@thiago.com", "Thiago Simões", "123456")
             jwtStr = JSON3.parse(jwt)
             # Check if JWT is generated
             @test !isnothing(jwt)
             # Decode JWT
             decoded_payload = OrionAuth.__ORION__DecodeJWT(jwtStr[:access_token])
             # Check if payload contains expected fields
             @test haskey(decoded_payload, "iat")
             @test haskey(decoded_payload, "exp")
 
             # Check if payload contains user information
             @test decoded_payload["email"] == "eu@thiago.com"
             @test decoded_payload["name"] == "Thiago Simões"
 
             # Check if payload contains roles and permissions
             @test haskey(decoded_payload, "roles")
             @test haskey(decoded_payload, "permissions")
 
             # Check if roles and permissions are empty
             @test decoded_payload["roles"] == []
             @test decoded_payload["permissions"] == []
 
             # Check if expiration time is correct
             @test decoded_payload["exp"] > decoded_payload["iat"]
         end
 
         @testset verbose=true "SignIn" begin
             # Assign role to user
             AssignRole(user.id, "admin")
             # Check if user has role, using function
             user_with_role = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserRole]))
             @test user_with_role !== nothing
             @test user_with_role["OrionAuth_UserRole"][1].userId == user.id
             # Check if user has role, using function
             @test (OrionAuth.GetUserPermissions(user.id) .|> (x -> x.permission)) == ["read", "write", "delete"]
             # Use signin function to get JWT and user
             user, jwt = signin("eu@thiago.com", "123456")
             jwtStr = JSON3.parse(jwt)
             # Check if JWT is generated
             @test !isnothing(jwt)
             # Decode JWT
             decoded_payload = OrionAuth.__ORION__DecodeJWT(jwtStr[:access_token])
             # Check if payload contains expected fields
             @test haskey(decoded_payload, "iat")
             @test haskey(decoded_payload, "exp")
 
             # Getroles from database for know name and id
             role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => "admin")))
 
             # Check roles
             @test decoded_payload["roles"][1][:roleId] == role.id
             @test (decoded_payload["permissions"] .|> (x -> x.permission)) == ["read", "write", "delete"]
         end
     end
 end
 
 conn = dbConnection()
 dropTable!(conn, "OrionAuth_User")
 dropTable!(conn, "OrionAuth_Log")
 dropTable!(conn, "Profile")
 dropTable!(conn, "OrionAuth_Role")
 dropTable!(conn, "OrionAuth_RolePermission")
 dropTable!(conn, "OrionAuth_Permission")
 dropTable!(conn, "OrionAuth_UserRole")
 dropTable!(conn, "OrionAuth_UserPermission")
 dropTable!(conn, "OrionAuth_EmailVerification")
 dropTable!(conn, "OrionAuth_PasswordReset")...
        ```

