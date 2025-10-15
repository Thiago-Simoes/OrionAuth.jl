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

# Load HTTP abstraction layer first
include(joinpath(@__DIR__, "http_adapter.jl"))

# Export abstraction types and functions
export RequestContext, 
       ResponseException, 
       GenericRequestContext,
       get_headers,
       extract_bearer_token

# Load adapters conditionally when frameworks are available
function __init__()
    # Load Genie adapter if Genie is available
    if isdefined(Base, :get_extension) || isdefined(@__MODULE__, :Genie)
        try
            @eval using Genie
            @eval using Genie.Requests
            @eval include(joinpath(@__DIR__, "adapters/genie.jl"))
            @eval export GenieRequestContext, to_genie_response
        catch
            @debug "Genie not available, skipping Genie adapter"
        end
    end
    
    # Note: Oxygen and HTTP.jl adapters are always available since HTTP is a dependency
    @eval include(joinpath(@__DIR__, "adapters/oxygen.jl"))
    @eval include(joinpath(@__DIR__, "adapters/http.jl"))
    @eval export OxygenRequestContext, to_oxygen_response
    @eval export HTTPRequestContext, to_http_response
end

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

export Auth,
       signin,
       signup,
       syncRolesPermissions,
       assignRole,
       assignPermission,
       syncRolesAndPermissions,
       getUserPermissions,
       getUserRoles,
       checkPermission,
       removeRole,
       __ORION__DecodeJWT,
       Unauthorized,
       getUserData,
       hash_password,
       verify_password,
       AbstractPasswordAlgorithm,
       Argon2idAlgorithm,
       LegacySHA512Algorithm

end # module OrionAuth
