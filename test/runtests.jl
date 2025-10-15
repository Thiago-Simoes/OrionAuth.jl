using Test
using Dates
using JSON3
using HTTP
using Genie
using Genie.Router
using OrionORM

using OrionAuth

# Load Genie adapter since Genie is available
if !isdefined(OrionAuth, :GenieRequestContext)
    include(joinpath(dirname(pathof(OrionAuth)), "adapters/genie.jl"))
    @eval OrionAuth export GenieRequestContext, to_genie_response
end

OrionAuth.init!()

@testset verbose=true "OrionAuth" begin
    # Include framework-agnostic tests
    include("test_generic.jl")
    include("test_httpjl.jl")
    include("test_oxygen.jl")
    
    @testset "Password hashing" begin
        password = "correct horse battery staple"

        hash = OrionAuth.hash_password(password)
        @test startswith(hash, "\$argon2id\$")
        @test OrionAuth.verify_password(hash, password)
        @test !OrionAuth.verify_password(hash, "wrong password")

        legacy_algo = OrionAuth.LegacySHA512Algorithm()
        legacy_hash = ""
        original_min = get(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS", nothing)
        try
            ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"] = "1"
            legacy_hash = OrionAuth.hash_password(password; algorithm = legacy_algo)
        finally
            if original_min === nothing
                pop!(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS", nothing)
            else
                ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"] = original_min
            end
        end

        @test startswith(legacy_hash, "sha512&")
        @test OrionAuth.verify_password(legacy_hash, password)
        @test !OrionAuth.verify_password(legacy_hash, "wrong password")
    end

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

        assignRole(user.id, role.role)
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

        assignPermission(user.id, permission.permission)
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

        syncRolesAndPermissions(Dict(
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

        permissions = getUserPermissions(user.id) .|> (x -> x.permission)
        @test all(x in permissions for x in ["read", "write", "delete"])
        @test checkPermission(user.id, "read") == true
    end

    @testset verbose=true "Permissions - Direct permission" begin
        # Garantir que a permissão "sudo" existe
        sudo_permission = findFirst(OrionAuth_Permission; query=Dict("where" => Dict("permission" => "sudo")))
        if isnothing(sudo_permission)
            sudo_permission = create(OrionAuth_Permission, Dict(
                "permission" => "sudo",
                "description" => "Sudo permission"
            ))
        end
    
        # Add direct permission to user
        assignPermission(user.id, "sudo")
    
        user_with_permission = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserPermission]))
        @test user_with_permission !== nothing
        @test user_with_permission["OrionAuth_UserPermission"][1].userId == user.id
    
        permissions = getUserPermissions(user.id) .|> (x -> x.permission)
        @test all([x in permissions for x in ["read", "write", "delete", "sudo"]])
        @test checkPermission(user.id, "sudo") == true
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
            assignRole(user.id, "admin")
            # Check if user has role, using function
            user_with_role = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [OrionAuth_UserRole]))
            @test user_with_role !== nothing
            @test user_with_role["OrionAuth_UserRole"][1].userId == user.id
            # Check if user has role, using function
            permissions = getUserPermissions(user.id) .|> (x -> x.permission)
            expected_permissions = ["read", "write", "delete"]
            for perm in expected_permissions
                @test perm in permissions
            end
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

            # Get roles from database for known name and id
            role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => "admin")))

            # Check roles
            @test decoded_payload["roles"][1][:roleId] == role.id

            jwt_permissions = decoded_payload["permissions"] .|> (x -> x.permission)
            for perm in expected_permissions
                @test perm in jwt_permissions
            end
        end
    end

    #-------------------------------------------------------------------------------
    # Setup test routes with middleware Auth() / getUserData()
    #-------------------------------------------------------------------------------
    function setupTestRoutes()
        function protected()
            Auth()                                 # throws 401/400 if not authorized
            "protected content"
        end
        route("/protected", protected, method = "GET")

        function userRoute()
            data = getUserData()                   # throws 401/400 if not authorized
            JSON3.write(data)
        end
        route("/user", userRoute, method = "GET")

        function deleteResource()
            Auth()
            payload = getUserData()
            if !checkPermission(payload["sub"], "delete")
                throw(Genie.Exceptions.ExceptionalResponse(403, [], "Forbidden"))
            end
            "deleted"
        end
        route("/delete-resource", deleteResource, method = "DELETE")
    end

    #-------------------------------------------------------------------------------
    # Initialize Genie in test mode and start the server
    #-------------------------------------------------------------------------------
    Genie.config.run_as_server = false
    setupTestRoutes()
    @async Genie.up()

    #-------------------------------------------------------------------------------
    # Test suite for middleware and role‐protected routes
    #-------------------------------------------------------------------------------
    @testset "Middleware and Protected Routes" begin

        # Prepare a fresh user and extract initial JWT
        user, signupData = signup("route@thiago.com", "Route Tester", "testPwd")
        initialToken = JSON3.parse(signupData)["access_token"]

        # 1) /protected without Authorization → should throw 401
        @test_throws HTTP.Exceptions.StatusError HTTP.request("GET", "http://127.0.0.1:8000/protected")

        # 2) /protected with bad header format → should throw 400
        @test_throws HTTP.Exceptions.StatusError HTTP.request("GET", "http://127.0.0.1:8000/protected";
                                                            headers = ["Authorization" => "Token $initialToken"])

        # 3) /protected with valid Bearer token → 200 + correct body
        resp = HTTP.request("GET", "http://127.0.0.1:8000/protected";
                            headers = ["Authorization" => "Bearer $initialToken"])
        @test resp.status == 200
        @test String(resp.body) == "protected content"

        # 4) /user without Authorization → should throw 401
        @test_throws HTTP.Exceptions.StatusError HTTP.request("GET", "http://127.0.0.1:8000/user")

        # 5) /user with valid token → 200 + correct payload
        resp = HTTP.request("GET", "http://127.0.0.1:8000/user";
                            headers = ["Authorization" => "Bearer $initialToken"])
        @test resp.status == 200
        payload = JSON3.read(String(resp.body))
        @test payload["email"] == user.email
        @test payload["name"]  == user.name
        @test payload["sub"]   == user.id

        # 6) DELETE /delete-resource without 'delete' permission → should throw 403
        @test_throws HTTP.Exceptions.StatusError HTTP.request("DELETE", "http://127.0.0.1:8000/delete-resource";
                                                            headers = ["Authorization" => "Bearer $initialToken"])

        # 7) Grant admin role, then signin again to refresh JWT with new permissions
        assignRole(user.id, "admin")
        _, signinData = signin("route@thiago.com", "testPwd")
        updatedToken = JSON3.parse(signinData)["access_token"]

        # 8) DELETE /delete-resource with delete permission → 200 + correct body
        resp = HTTP.request("DELETE", "http://127.0.0.1:8000/delete-resource";
                            headers = ["Authorization" => "Bearer $updatedToken"])
        @test resp.status == 200
        @test String(resp.body) == "deleted"
    end

end



conn = dbConnection()
dropTable!(conn, "OrionAuth_Log")
dropTable!(conn, "Profile")
dropTable!(conn, "OrionAuth_RolePermission")
dropTable!(conn, "OrionAuth_UserRole")
dropTable!(conn, "OrionAuth_UserPermission")
dropTable!(conn, "OrionAuth_EmailVerification")
dropTable!(conn, "OrionAuth_PasswordReset")
dropTable!(conn, "OrionAuth_Permission")
dropTable!(conn, "OrionAuth_Role")
dropTable!(conn, "OrionAuth_User")