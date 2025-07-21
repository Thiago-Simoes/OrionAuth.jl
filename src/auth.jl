
function log_action(action::String, userId::Int)
    ts = string(Dates.now())
    return create(OrionAuth_Log, Dict("userId"=>userId, "action"=>action, "timestamp"=>ts))
end

function signup(email::String, name::String, password::String)
    existing = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if existing !== nothing
        error("User already exists")
    end
    uuid = string(UUIDs.uuid4())
    hashed_password = __NEBULA__HashPassword(password)
    ts = string(Dates.now())
    local newUser = create(OrionAuth_User, Dict(
        "email"      => email,
        "name"       => name,
        "uuid"       => uuid,
        "password"   => hashed_password
    ))
    @async log_action("signup", newUser.id)

    payload = GenerateJWT(newUser)

    returnData = Dict(
        "access_token" => payload,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return newUser, returnData
end

function signin(email::String, password::String)
    local user = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if user === nothing
        error("User not found")
    end
    
    if !__NEBULA__VerifyPassword(password, user.password)
        error("Invalid password")
    end
    @async log_action("signin", user.id)

    payload = GenerateJWT(user)

    returnData = Dict(
        "access_token" => payload,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return user, returnData
end

function GenerateJWT(user)
    payload = Dict("sub" => user.id, "name" => user.name, "email" => user.email, "uuid" => user.uuid, "roles" => GetUserRoles(user.id), "permissions" => GetUserPermissions(user.id))
    token = __NEBULA__EncodeJWT(payload, ENV["OrionAuth_SECRET"], ENV["OrionAuth_ALGORITHM"])
    return token
end
