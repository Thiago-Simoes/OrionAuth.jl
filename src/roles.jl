
"""
    FetchUser(userId::Int) :: Dict

Busca um usuário pelo ID. Se não existir, gera erro.
"""
function FetchUser(userId::Int)::NebulaAuth_User
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => userId)))
    if user === nothing
        error("User not found")
    end
    return user
end

"""
    FetchRole(roleName::String) :: Dict

Busca uma role pelo nome. Se não existir, gera erro.
"""
function FetchRole(roleName::String)::NebulaAuth_Role
    role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => roleName)))
    if role === nothing
        error("Role not found")
    end
    return role
end

"""
    FetchPermission(permissionName::String) :: Dict

Busca uma permissão pelo nome. Se não existir, gera erro.
"""
function FetchPermission(permissionName::String)::NebulaAuth_Permission
    permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => permissionName)))
    if permission === nothing
        error("Permission not found")
    end
    return permission
end

"""
    FetchUserRoleRelation(userId::Int, roleId::Int) :: Union{Nothing, Dict}

Busca a relação usuário-role. Retorna nothing se não existir.
"""
function FetchUserRoleRelation(userId::Int, roleId::Int)::Union{Nothing, NebulaAuth_UserRole}
    return findFirst(NebulaAuth_UserRole; query=Dict("where" => Dict("userId" => userId, "roleId" => roleId)))
end

"""
    FetchUserPermissionRelation(userId::Int, permissionId::Int) :: Union{Nothing, Dict}

Busca a relação usuário-permissão. Retorna nothing se não existir.
"""
function FetchUserPermissionRelation(userId::Int, permissionId::Int)::Union{Nothing, NebulaAuth_UserPermission}
    return findFirst(NebulaAuth_UserPermission; query=Dict("where" => Dict("userId" => userId, "permissionId" => permissionId)))
end


# Funções de Responsabilidade Única

"""
    AssignRoleToUser(userId::Int, roleName::String) :: Any

Atribui uma role a um usuário após as devidas verificações.
"""
function AssignRoleToUser(userId::Int, roleName::String)
    user = FetchUser(userId)
    role = FetchRole(roleName)
    if FetchUserRoleRelation(userId, role.id) !== nothing
        error("User already has this role")
    end

    newUserRole = create(NebulaAuth_UserRole, Dict(
        "userId" => userId,
        "roleId" => role.id
    ))

    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    @async log_action(
        "AssignRoleToUser: Assigned role $(role.role) (ID: $(role.id)) to user ID $(user.id) at $(ts)",
        user.id
    )
    return newUserRole
end

"""
    RemoveRoleFromUser(userId::Int, roleName::String) :: Bool

Remove uma role de um usuário após verificações.
"""
function RemoveRoleFromUser(userId::Int, roleName::String)::Bool
    user = FetchUser(userId)
    role = FetchRole(roleName)
    local existing = FetchUserRoleRelation(userId, role.id)
    if existing === nothing
        error("User does not have this role")
    end

    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    delete(existing)
    @async log_action(
        "RemoveRoleFromUser: Removed role $(role.role) (ID: $(role.id)) from user ID $(user.id) at $(ts)",
        user.id
    )
    return true
end

"""
    GetUserRoles(userId::Int) :: Vector{Any}

Retorna as roles atribuídas a um usuário.
"""
function GetUserRoles(userId::Int)::Vector{Any}
    # Inclui roles na consulta
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => userId), "include" => [NebulaAuth_UserRole]))
    if user === nothing
        error("User not found")
    end

    local roles = user["NebulaAuth_UserRole"]
    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    @async log_action(
        "GetUserRoles: Retrieved roles for user ID $(user["NebulaAuth_User"].id) at $(ts)",
        user["NebulaAuth_User"].id
    )
    return roles
end

"""
    AssignPermissionToUser(userId::Int, permissionName::String) :: Any

Atribui uma permissão a um usuário após verificar se já não existe.
"""
function AssignPermissionToUser(userId::Int, permissionName::String)
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => userId), "include" => [NebulaAuth_UserPermission]))
    if user === nothing
        error("User not found")
    end

    permission = FetchPermission(permissionName)
    for perm in user["NebulaAuth_UserPermission"]
        if perm.permissionId == permission.id
            error("User already has this permission")
        end
    end

    newUserPermission = create(NebulaAuth_UserPermission, Dict(
        "userId" => userId,
        "permissionId" => permission.id
    ))

    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    @async log_action(
        "AssignPermissionToUser: Assigned permission \"$(permission.permission)\" (ID: $(permission.id)) to user ID $(user["NebulaAuth_User"].id) at $(ts)",
        user["NebulaAuth_User"].id
    )
    return newUserPermission
end

"""
    RemovePermissionFromUser(userId::Int, permissionName::String) :: Bool

Remove uma permissão de um usuário após verificar se a relação existe.
"""
function RemovePermissionFromUser(userId::Int, permissionName::String)::Bool
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => userId), "include" => [NebulaAuth_UserPermission]))
    if user === nothing
        error("User not found")
    end

    permission = FetchPermission(permissionName)
    local existing = nothing
    for perm in user["NebulaAuth_UserPermission"]
        if perm.permissionId == permission.id
            existing = perm
            break
        end
    end
    if existing === nothing
        error("User does not have this permission")
    end

    delete(existing)

    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    @async log_action(
        "RemovePermissionFromUser: Removed permission \"$(permission.permission)\" (ID: $(permission.id)) from user ID $(user["NebulaAuth_User"].id) at $(ts)",
        user["NebulaAuth_User"].id
    )
    return true
end

"""
    GetUserPermissions(userId::Int) :: Vector{Any}

Retorna todas as permissões associadas a um usuário (através de roles e relações diretas).
"""
function GetUserPermissions(userId::Int)::Vector{Any}
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => userId), "include" => [NebulaAuth_UserRole]))
    if user === nothing
        error("User not found")
    end

    permissions = Any[]
    for role in user["NebulaAuth_UserRole"]
        rolePermissions = findMany(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.roleId)))
        if rolePermissions !== nothing
            permissions = vcat(permissions, rolePermissions)
        end
    end
    permissions = unique(permissions)

    permissionsList = Any[]
    for rel in permissions
        perm = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("id" => rel.permissionId)))
        if perm !== nothing
            permissionsList = vcat(permissionsList, perm)
        end
    end

    userPermissions = findMany(NebulaAuth_UserPermission; query=Dict("where" => Dict("userId" => userId)))
    for rel in userPermissions
        perm = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("id" => rel.permissionId)))
        if perm !== nothing
            permissionsList = vcat(permissionsList, perm)
        end
    end

    ts = Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS")
    @async log_action(
        "GetUserPermissions: Retrieved permissions for user ID $(userId) at $(ts)",
        user["NebulaAuth_User"].id
    )
    return permissionsList
end

"""
    CheckUserPermission(userId::Int, permissionName::String) :: Bool

Verifica se um usuário possui uma permissão específica.
"""
function CheckUserPermission(userId::Int, permissionName::String)::Bool
    user = FetchUser(userId)
    permissions = GetUserPermissions(user.id)
    for perm in permissions
        if perm.permission == permissionName
            return true
        end
    end
    return false
end

"""
    SyncRolesAndPermissions(rolesAndPermissions::Dict{String, Vector{String}}) :: Bool

Sincroniza roles e permissões a partir de um Dict, criando registros e relações ausentes.
"""
function SyncRolesAndPermissions(rolesAndPermissions::Dict{String, Vector{String}})::Bool
    for (roleName, permissionList) in rolesAndPermissions
        role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => roleName)))
        if role === nothing
            role = create(NebulaAuth_Role, Dict(
                "role" => roleName,
                "description" => "Role: $roleName"
            ))
        end

        for permissionName in permissionList
            permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => permissionName)))
            if permission === nothing
                permission = create(NebulaAuth_Permission, Dict(
                    "permission" => permissionName,
                    "description" => "Permission: $permissionName"
                ))
            end

            existingRelation = findFirst(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => permission.id)))
            if existingRelation === nothing
                create(NebulaAuth_RolePermission, Dict(
                    "roleId" => role.id,
                    "permissionId" => permission.id
                ))
            end
        end
    end
    return true
end