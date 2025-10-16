"""
    assignRole(user_id::Int, role::String) -> OrionAuth_UserRole

Assign a role to a user.

# Arguments
- `user_id::Int`: User ID (e.g., 1)
- `role::String`: Role name (e.g., "admin")

# Returns
- `OrionAuth_UserRole`: The created user-role association record

# Throws
- `error("User not found")`: If user ID doesn't exist
- `error("Role not found")`: If role name doesn't exist
- `error("User already has this role")`: If role is already assigned

# Examples
```julia
assignRole(123, "admin")
assignRole(456, "moderator")
```
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

"""
    removeRole(user_id::Int, role::String) -> Bool

Remove a role from a user.

# Arguments
- `user_id::Int`: User ID (e.g., 1)
- `role::String`: Role name to remove (e.g., "admin")

# Returns
- `Bool`: true if role was successfully removed

# Throws
- `error("User not found")`: If user ID doesn't exist
- `error("Role not found")`: If role name doesn't exist
- `error("User does not have this role")`: If user doesn't have the role

# Examples
```julia
removeRole(123, "admin")
```
"""
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

"""
    getUserRoles(user_id::Int) -> Vector

Get all roles assigned to a user.

# Arguments
- `user_id::Int`: User ID (e.g., 1)

# Returns
- `Vector`: List of user role records, or empty array if no roles

# Throws
- `error("User not found")`: If user ID doesn't exist

# Examples
```julia
roles = getUserRoles(123)
for role in roles
    println(role.roleId)
end
```
"""
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

"""
    assignPermission(user_id::Int, permission::String) -> OrionAuth_UserPermission

Assign a permission directly to a user (not through a role).

# Arguments
- `user_id::Int`: User ID (e.g., 1)
- `permission::String`: Permission name (e.g., "read")

# Returns
- `OrionAuth_UserPermission`: The created user-permission association record

# Throws
- `error("User not found")`: If user ID doesn't exist
- `error("Permission not found")`: If permission name doesn't exist
- `error("User already has this permission")`: If permission is already assigned

# Examples
```julia
assignPermission(123, "read")
assignPermission(456, "write")
```
"""
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

"""
    removePermission(user_id::Int, permission::String) -> Bool

Remove a directly assigned permission from a user.

# Arguments
- `user_id::Int`: User ID (e.g., 1)
- `permission::String`: Permission name to remove (e.g., "read")

# Returns
- `Bool`: true if permission was successfully removed

# Throws
- `error("User not found")`: If user ID doesn't exist
- `error("Permission not found")`: If user doesn't have the permission

# Examples
```julia
removePermission(123, "read")
```
"""
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

"""
    getUserPermissions(user_id::Int) -> Vector

Get all permissions for a user (both direct and inherited from roles).

# Arguments
- `user_id::Int`: User ID (e.g., 1)

# Returns
- `Vector`: List of permission records with unique permissions

# Throws
- `error("User not found")`: If user ID doesn't exist

# Examples
```julia
permissions = getUserPermissions(123)
for perm in permissions
    println(perm.permission)  # e.g., "read", "write", "delete"
end
```
"""
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

"""
    checkPermission(user_id::Int, permission::String) -> Bool

Check if a user has a specific permission.

# Arguments
- `user_id::Int`: User ID (e.g., 1)
- `permission::String`: Permission name to check (e.g., "read")

# Returns
- `Bool`: true if user has the permission, false otherwise

# Throws
- `error("User not found")`: If user ID doesn't exist
- `error("Permission not found")`: If user has no permissions at all

# Examples
```julia
if checkPermission(123, "admin")
    println("User is admin")
end

has_write = checkPermission(456, "write")
```
"""
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
    syncRolesAndPermissions(roles::Dict{String, Vector{String}}) -> Bool

Synchronize roles and permissions from a dictionary structure.
Creates any missing roles, permissions, and their associations.

# Arguments
- `roles::Dict{String, Vector{String}}`: Dictionary mapping role names to permission lists

# Returns
- `Bool`: true when synchronization is complete

# Examples
```julia
syncRolesAndPermissions(Dict(
    "admin" => ["read", "write", "delete"],
    "user" => ["read"],
    "moderator" => ["read", "write"]
))
```
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