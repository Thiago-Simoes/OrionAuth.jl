
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
    log_action("assign_role: Assigned role \"$(role.role)\" (Role ID: $(role.id)) to user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
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
    log_action("remove_role: Removed role \"$(role.role)\" (Role ID: $(role.id)) from user ID $(user.id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user)
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
    log_action("get_user_roles: Retrieved roles for user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"].id)
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
    log_action("assign_permission: Assigned permission \"$(permission.permission)\" (Permission ID: $(permission.id)) to user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
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
    log_action("remove_permission: Removed permission \"$(permission.permission)\" (Permission ID: $(permission.id)) from user ID $(userId) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"])
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
    log_action("get_user_permissions: Retrieved permissions for user ID $(user_id) at $(Dates.format(Dates.now(), "yyyy-mm-dd HH:MM:SS"))", user["OrionAuth_User"].id)
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
end