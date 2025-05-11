using Test
using Dates

using DotEnv
DotEnv.load!()

using JSON3
using NebulaORM

using NebulaAuth
NebulaAuth.init!()

@testset "NebulaAuth" begin
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
            ("userId", NebulaAuth_User, "id", :belongsTo)
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
        profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId)))
        @test profile_user !== nothing
        @test profile_user.id == user.id

        # # Buscar o perfil do usuário
        profile_user = findFirst(Profile; query=Dict("where" => Dict("userId" => user.id)))
        @test profile_user !== nothing
        @test profile_user.id == profile.id
        @test profile_user.userId == user.id

        # # Buscar pela relação
        profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId), "include" => [Profile]))
        @test profile_user !== nothing
        @test profile_user["NebulaAuth_User"].id == user.id
        @test profile_user["Profile"][1].id == profile.id
    end

    role = create(NebulaAuth_Role, Dict(
        "role" => "admin",
        "description" => "Administrator role"
    ))

    @testset verbose=true "Roles" begin
        @test role !== nothing
        @test role.role == "admin"
        @test role.description == "Administrator role"

        role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => "admin")))
        @test role !== nothing
        @test role.role == "admin"

        AssignRoleToUser(user.id, role.role)
        user_role = findFirst(NebulaAuth_UserRole; query=Dict("where" => Dict("userId" => user.id, "roleId" => role.id)))
        @test user_role !== nothing
        @test user_role.userId == user.id

        user_with_role = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserRole]))
        @test user_with_role !== nothing
        @test user_with_role["NebulaAuth_UserRole"][1].userId == user.id
    end

    @testset verbose=true "Permissions - Create and assign" begin
        permission = create(NebulaAuth_Permission, Dict(
            "permission" => "read",
            "description" => "Read permission"
        ))

        @test permission !== nothing
        @test permission.permission == "read"
        @test permission.description == "Read permission"

        permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => "read")))
        @test permission !== nothing
        @test permission.permission == "read"

        AssignPermissionToUser(user.id, permission.permission)
        user_permission = findFirst(NebulaAuth_UserPermission; query=Dict("where" => Dict("userId" => user.id, "permissionId" => permission.id)))
        @test user_permission !== nothing
        @test user_permission.userId == user.id

        user_with_permission = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserPermission]))
        @test user_with_permission !== nothing
        @test user_with_permission["NebulaAuth_UserPermission"][1].userId == user.id
    end

    @testset verbose=true "Permissions - Inheritance" begin
        parent_permission = create(NebulaAuth_Permission, Dict(
            "permission" => "write",
            "description" => "Write permission"
        ))

        @test parent_permission !== nothing
        @test parent_permission.permission == "write"
        @test parent_permission.description == "Write permission"

        parent_permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => "write")))
        @test parent_permission !== nothing
        @test parent_permission.permission == "write"

        deleteMany(NebulaAuth_UserPermission, Dict("where" => Dict("userId" => user.id)))

        SyncRolesAndPermissions(Dict(
            "admin" => ["read", "write", "delete"],
            "user" => ["read"],
            "god" => ["read", "write", "delete", "sudo"]
        ))

        role_permission = findFirst(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => parent_permission.id)))
        @test role_permission !== nothing
        @test role_permission.roleId == role.id

        role_with_permission = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("id" => role.id), "include" => [NebulaAuth_RolePermission]))
        @test role_with_permission !== nothing
        @test role_with_permission["NebulaAuth_RolePermission"][1].roleId == role.id

        user_with_role_permission = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserRole]))
        @test user_with_role_permission !== nothing
        @test user_with_role_permission["NebulaAuth_UserRole"][1].userId == user.id

        @test NebulaAuth.GetUserPermissions(user.id) .|> (x -> x.permission) == ["read", "write", "delete"]
        @test CheckUserPermission(user.id, "read") == true
    end

    @testset verbose=true "Permissions - Direct permission" begin
        # Add direct permission to user
        AssignPermissionToUser(user.id, "sudo")
        user_with_permission = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserPermission]))
        @test user_with_permission !== nothing
        @test user_with_permission["NebulaAuth_UserPermission"][1].userId == user.id
        @test NebulaAuth.GetUserPermissions(user.id) .|> (x -> x.permission) == ["read", "write", "delete", "sudo"]
        @test CheckUserPermission(user.id, "sudo") == true
    end

    @testset verbose=true "SignIn and SignUp - JWT" begin
        @testset verbose=true "SignUp" begin
            # Use signup function to get JWT and user
            user, jwt = signup("eu@thiago.com", "Thiago Simões", "123456")
            jwtStr = JSON3.parse(jwt)
            # Check if JWT is generated
            @test !isnothing(jwt)
            # Decode JWT
            decoded_payload = NebulaAuth.__NEBULA__DecodeJWT(jwtStr[:access_token])
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
            AssignRoleToUser(user.id, "admin")
            # Check if user has role, using function
            user_with_role = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserRole]))
            @test user_with_role !== nothing
            @test user_with_role["NebulaAuth_UserRole"][1].userId == user.id
            # Check if user has role, using function
            @test (NebulaAuth.GetUserPermissions(user.id) .|> (x -> x.permission)) == ["read", "write", "delete"]
            # Use signin function to get JWT and user
            user, jwt = signin("eu@thiago.com", "123456")
            jwtStr = JSON3.parse(jwt)
            # Check if JWT is generated
            @test !isnothing(jwt)
            # Decode JWT
            decoded_payload = NebulaAuth.__NEBULA__DecodeJWT(jwtStr[:access_token])
            # Check if payload contains expected fields
            @test haskey(decoded_payload, "iat")
            @test haskey(decoded_payload, "exp")

            # Getroles from database for know name and id
            role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => "admin")))

            # Check roles
            @test decoded_payload["roles"][1][:roleId] == role.id
            @test (decoded_payload["permissions"] .|> (x -> x.permission)) == ["read", "write", "delete"]
        end
    end
end

conn = dbConnection()
dropTable!(conn, "NebulaAuth_User")
dropTable!(conn, "NebulaAuth_Log")
dropTable!(conn, "Profile")
dropTable!(conn, "NebulaAuth_Role")
dropTable!(conn, "NebulaAuth_RolePermission")
dropTable!(conn, "NebulaAuth_Permission")
dropTable!(conn, "NebulaAuth_UserRole")
dropTable!(conn, "NebulaAuth_UserPermission")
dropTable!(conn, "NebulaAuth_EmailVerification")
dropTable!(conn, "NebulaAuth_PasswordReset")