module NebulaAuth

using Base64
using DataFrames
using Dates
using DotEnv
using HTTP
using JSON3
using NebulaORM
using Nettle
using Random
using SHA
using UUIDs

# Initialize .env
DotEnv.load!()

function init!()
    dir = @__DIR__
    
    include(joinpath(dir, "bin/base64.jl"))

    include(joinpath(dir, "user.jl"))
    include(joinpath(dir, "password.jl"))
    include(joinpath(dir, "roles.jl"))
    include(joinpath(dir, "auth.jl"))
    include(joinpath(dir, "jwt.jl"))

    @eval begin
        NebulaAuth_Log = Model(
            :NebulaAuth_Log,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("action", TEXT(), []),
                ("timestamp", TEXT(), [])
            ]
        )
        
        NebulaAuth_User = Model(
            :NebulaAuth_User,
            [
                ("id",         INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("email",      TEXT(),    []),
                ("name",       TEXT(),    []),
                ("uuid",       NebulaORM.UUID(),    []),
                ("password",   TEXT(),    []),
                ("created_at", TIMESTAMP(),    [Default("CURRENT_TIMESTAMP()")]),
                ("updated_at", TIMESTAMP(),    [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        NebulaAuth_Permission = Model(
            :NebulaAuth_Permission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("permission", VARCHAR(100), []),
                ("description", VARCHAR(250), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )
        
        NebulaAuth_Role = Model(
            :NebulaAuth_Role,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("role", VARCHAR(100), []),
                ("description", VARCHAR(250), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        NebulaAuth_RolePermission = Model(
            :NebulaAuth_RolePermission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("roleId", INTEGER(), []),
                ("permissionId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("roleId", NebulaAuth_Role, "id", :belongsTo),
                ("permissionId", NebulaAuth_Permission, "id", :belongsTo)
            ]
        )

        NebulaAuth_UserRole = Model(
            :NebulaAuth_UserRole,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("roleId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("userId", NebulaAuth_User, "id", :belongsTo),
                ("roleId", NebulaAuth_Role, "id", :belongsTo)
            ]
        )

        NebulaAuth_UserPermission = Model(
            :NebulaAuth_UserPermission,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("permissionId", INTEGER(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ],
            [
                ("userId", NebulaAuth_User, "id", :belongsTo),
                ("permissionId", NebulaAuth_Permission, "id", :belongsTo)
            ]
        )

        NebulaAuth_EmailVerification = Model(
            :NebulaAuth_EmailVerification,
            [
                ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
                ("userId", INTEGER(), []),
                ("token", TEXT(), []),
                ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
            ]
        )

        NebulaAuth_PasswordReset = Model(
            :NebulaAuth_PasswordReset,
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

# include("./signup.jl")
# include("./login.jl")
# include("./logout.jl")
# include("./reset_password.jl")
# include("./verify_email.jl")
# include("./update_profile.jl")
# include("./update_password.jl")
# include("./update_email.jl")

export NebulaAuth_User, signin, signup, syncRolesPermissions, assignRole,
    hasPermission, assignPermission, syncRolesAndPermissions, getUserPermissions, checkPermission, removeRole

end # module NebulaAuth
