
"""
    assign_role(user_id::Int, role::String)

Assign a role to a user.
"""
function assignRole(user_id::Int, role::String)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if isnothing(user)
        error("User not found")
    end

    # Check if role exists
    role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => role)))
    if isnothing(role)
        error("Role not found")
    end

    # Check if user already has the role
    existing = findFirst(NebulaAuth_UserRole; query=Dict("where" => Dict("userId" => user_id, "roleId" => role.id)))
    if existing !== nothing
        error("User already has this role")
    end

    # Assign role to user
    new_user_role = create(NebulaAuth_UserRole, Dict(
        "userId" => user_id,
        "roleId" => role.id
    ))

    # Log the action
    log_action("assign_role: Assigned role \"$(role.role)\" (Role ID: $(role.id)) to user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
    return new_user_role    
end

function removeRole(user_id::Int, role::String)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if isnothing(user)
        error("User not found")
    end

    # Check if role exists
    role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => role)))
    if isnothing(role)
        error("Role not found")
    end

    # Check if user has the role
    existing = findFirst(NebulaAuth_UserRole; query=Dict("where" => Dict("userId" => user_id, "roleId" => role.id)))
    if isnothing(existing)
        error("User does not have this role")
    end

    # Remove the role from the user
    delete(existing)

    # Log the action
    log_action("remove_role: Removed role \"$(role.role)\" (Role ID: $(role.id)) from user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
    return true
end

function getUserRoles(user_id::Int)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [NebulaAuth_UserRole]))
    if isnothing(user)
        error("User not found")
    end

    # Get roles assigned to the user
    roles = user["NebulaAuth_UserRole"]
    if isempty(roles)
        []
    end
    
    # Log the action
    userId = user["NebulaAuth_User"].id
    log_action("get_user_roles: Retrieved roles for user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["NebulaAuth_User"])
    return roles
end

function assignPermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [NebulaAuth_UserPermission]))
    if isnothing(user)
        error("User not found")
    end

    # Check if permission exists
    permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => permission)))
    if permission === nothing
        error("Permission not found")
    end

    # Check if user already has the permission
    # Using the user["NebulaAuth_UserPermission"] to check if the user has the permission
    existing = user["NebulaAuth_UserPermission"]
    if !isempty(existing)
        for perm in existing
            if perm.permissionId == permission.id
                error("User already has this permission")
            end
        end
    end

    # Assign permission to user
    new_user_permission = create(NebulaAuth_UserPermission, Dict(
        "userId" => user_id,
        "permissionId" => permission.id
    ))

    # Log the action
    userId = user["NebulaAuth_User"].id
    log_action("assign_permission: Assigned permission \"$(permission.permission)\" (Permission ID: $(permission.id)) to user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["NebulaAuth_User"])
    return new_user_permission    
end

function removePermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [NebulaAuth_UserPermission]))
    if isnothing(user)
        error("User not found")
    end

    # Check if permission exists in the database
    # Using the user["NebulaAuth_UserPermission"] to check if the user has the permission
    if isempty(user["NebulaAuth_UserPermission"])
        error("Permission not found")
    end

    existing = nothing
    for perm in user["NebulaAuth_UserPermission"]
        if perm.permissionId == permission
            existing = perm
            break
        end
    end

    # Remove the permission from the user
    delete!(existing)

    # Log the action
    userId = user["NebulaAuth_User"].id
    log_action("remove_permission: Removed permission \"$(permission.permission)\" (Permission ID: $(permission.id)) from user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["NebulaAuth_User"])
    return true
end

function getUserPermissions(user_id::Int)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id), "include" => [NebulaAuth_UserRole]))
    if isnothing(user)
        error("User not found")
    end

    # Get permissions assigned to the user
    permissions = []
    
    # Get permissions for each role
    for role in user["NebulaAuth_UserRole"]
        role_permissions = findMany(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.roleId)))
        if role_permissions !== nothing
            permissions = vcat(permissions, role_permissions)
        end
    end
    # Remove duplicates
    permissions = unique(permissions)

    # Get permissions directly assigned to role permissions

    permissionsList = []
    for perm in permissions
        permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("id" => perm.permissionId)))
        if permission !== nothing
            permissionsList = vcat(permissionsList, permission)
        end
    end


    # Log the action
    log_action("get_user_permissions: Retrieved permissions for user ID $(user_id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["NebulaAuth_User"])
    return permissionsList
end

function checkPermission(user_id::Int, permission::String)
    # Check if user exists
    user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => user_id)))
    if isnothing(user)
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
        role = findFirst(NebulaAuth_Role; query=Dict("where" => Dict("role" => role_name)))
        if isnothing(role)
            # Create the role if it doesn't exist
            role = create(NebulaAuth_Role, Dict(
                "role" => role_name,
                "description" => "Role: $role_name"
            ))
        end

        # Iterate over each permission for the role
        for permission_name in permissions
            # Check if the permission already exists
            permission = findFirst(NebulaAuth_Permission; query=Dict("where" => Dict("permission" => permission_name)))
            if isnothing(permission)
                permission = create(NebulaAuth_Permission, Dict(
                    "permission" => permission_name,
                    "description" => "Permission: $permission_name"
                ))
            end

            existing_relation = findFirst(NebulaAuth_RolePermission; query=Dict("where" => Dict("roleId" => role.id, "permissionId" => permission.id)))
            if existing_relation === nothing
                create(NebulaAuth_RolePermission, Dict(
                    "roleId" => role.id,
                    "permissionId" => permission.id
                ))
            end
        end
    end

    return true
end