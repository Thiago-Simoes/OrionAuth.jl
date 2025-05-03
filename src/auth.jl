
# Função para registrar log de ação.
function log_action(action::String, user)
    ts = string(Dates.now())
    return create(NebulaAuth_Log, Dict("userId"=>user.id, "action"=>action, "timestamp"=>ts))
end

# Altered signup function using module-level NebulaAuth_User.
function signup(email::String, name::String, password::String)
    existing = findFirst(NebulaAuth_User; query=Dict("where" => Dict("email" => email)))
    if existing !== nothing
        error("User already exists")
    end
    uuid = string(UUIDs.uuid4())
    hashed_password = __NEBULA__HashPassword(password)
    ts = string(Dates.now())
    local new_user = create(NebulaAuth_User, Dict(
        "email"      => email,
        "name"       => name,
        "uuid"       => uuid,
        "password"   => hashed_password
    ))
    log_action("signup", new_user)
    return new_user
end

# Altered signin function with password verification.
function signin(email::String, password::String)
    local user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("email" => email)))
    if user === nothing
        error("User not found")
    end
    
    if !__NEBULA__VerifyPassword(password, user.password)
        error("Invalid password")
    end
    log_action("signin", user)
    return user
end

