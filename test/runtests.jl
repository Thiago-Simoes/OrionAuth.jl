# Implementa os testes unitários para o módulo `ORM.jl` e suas dependências.

using Test
using Dates

using DotEnv
DotEnv.load!()

using NebulaORM

using NebulaAuth
NebulaAuth.init!()

@testset "NebulaAuth" begin
    # Define um usuário de autenticação
    user, jwt = signup("th.simoes@proton.me", "Thiago Simões", "123456")
    userLogging, jwt = signin("th.simoes@proton.me", "123456")
    @testset verbose=true "Authentication - Login/Register" begin
        @test userLogging !== nothing
        @test userLogging.id == user.id
        @test userLogging.name == user.name
        @test userLogging.email == user.email
    end

    # Relationship
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

        # Testar busca
        role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => "admin")))
        @test role !== nothing
        @test role.role == "admin"

        # Assing role
        assignRole(user.id, role.role)
        # Testar busca
        user_role = findFirst(NebulaAuth_UserRole; query=Dict("where" => Dict("userId" => user.id, "roleId" => role.id)))
        @test user_role !== nothing
        @test user_role.userId == user.id

        # Testar busca
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

        # Testar busca
        permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => "read")))
        @test permission !== nothing
        @test permission.permission == "read"

        assignPermission(user.id, permission.permission)
        # Testar busca
        user_permission = findFirst(NebulaAuth_UserPermission; query=Dict("where" => Dict("userId" => user.id, "permissionId" => permission.id)))
        @test user_permission !== nothing
        @test user_permission.userId == user.id

        # Testar busca
        user_with_permission = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserPermission]))
        @test user_with_permission !== nothing
        @test user_with_permission["NebulaAuth_UserPermission"][1].userId == user.id
    end

    @testset verbose=true "Permissions - Inheritance" begin
        # Criar uma permissão pai
        parent_permission = create(NebulaAuth_Permission, Dict(
            "permission" => "write",
            "description" => "Write permission"
        ))

        @test parent_permission !== nothing
        @test parent_permission.permission == "write"
        @test parent_permission.description == "Write permission"

        # Testar busca
        parent_permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => "write")))
        @test parent_permission !== nothing
        @test parent_permission.permission == "write"

        # Clean permission
        deleteMany(NebulaAuth_UserPermission, Dict("where" => Dict("userId" => user.id)))

        # Assign permission to role
        syncRolesAndPermissions(Dict(
            "admin" => ["read", "write", "delete"],
            "user" => ["read"]
        ))

        # Testar busca
        role_permission = findFirst(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => parent_permission.id)))
        @test role_permission !== nothing
        @test role_permission.roleId == role.id

        # Testar busca
        role_with_permission = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("id" => role.id), "include" => [NebulaAuth_RolePermission]))
        @test role_with_permission !== nothing
        @test role_with_permission["NebulaAuth_RolePermission"][1].roleId == role.id

        # Testar busca
        user_with_role_permission = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user.id), "include" => [NebulaAuth_UserRole]))
        @test user_with_role_permission !== nothing
        @test user_with_role_permission["NebulaAuth_UserRole"][1].userId == user.id

        # Testar busca
        @test NebulaAuth.getUserPermissions(user.id) .|> (x -> x.permission) == ["read", "write", "delete"]
        @test checkPermission(user.id, "read") == true
    end

end

# Reset o banco de dados
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