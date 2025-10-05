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
using Mustache
using Sodium
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
                ("email_confirmed",      OrionORM.BOOLEAN(),    [Default(true)]),
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

export Auth, signin, signup, syncRolesPermissions, assignRole, assignPermission, syncRolesAndPermissions, getUserPermissions, getUserRoles, checkPermission, removeRole, __ORION__DecodeJWT, Unauthorized, getUserData,
       verify_email, resend_verification_token, set_email_sender!, set_verification_email_template!, EmailTemplate, VerificationEmail,
       PasswordAlgorithm, register_password_algorithm!, set_default_password_algorithm!

end # module OrionAuth
