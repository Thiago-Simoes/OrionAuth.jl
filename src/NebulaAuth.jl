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
    include(joinpath(dir, "user.jl"))
    include(joinpath(dir, "password.jl"))
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

export NebulaAuth_User, signin, signup

end # module NebulaAuth
