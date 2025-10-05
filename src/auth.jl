Base.@kwdef struct EmailTemplate
    subject::String
    body::String
end

struct VerificationEmail
    to::String
    subject::String
    body::String
    context::Dict{String,Any}
end

const EMAIL_SENDER = Base.RefValue{Union{Nothing,Function}}(nothing)
const MIN_VERIFICATION_TTL = 60
const VERIFICATION_TOKEN_LENGTH = 48

const VERIFICATION_EMAIL_TEMPLATE = Base.RefValue{EmailTemplate}(EmailTemplate(
    subject = "Confirm your OrionAuth account",
    body = """
Hello {{name}},

Thanks for signing up for OrionAuth.
Use the code {{token}} or visit {{verification_url}} to confirm your account.

Cheers,
The OrionAuth Team
""",
))

email_confirmation_enforced() = lowercase(get(ENV, "OrionAuth_ENFORCE_EMAIL_CONFIRMATION", "false")) in ("1", "true", "yes" )

function verification_token_ttl()
    raw = get(ENV, "OrionAuth_EMAIL_VERIFICATION_TTL", "86400")
    ttl = try
        parse(Int, raw)
    catch
        86_400
    end
    max(ttl, MIN_VERIFICATION_TTL)
end

function verification_base_url()
    get(ENV, "OrionAuth_EMAIL_VERIFICATION_URL", "")
end

function generate_verification_token()
    Random.randstring(RandomDevice(), PASSWORD_TOKEN_ALPHABET, VERIFICATION_TOKEN_LENGTH)
end

function set_email_sender!(sender::Union{Function,Nothing})
    EMAIL_SENDER[] = sender
    return sender
end

function set_verification_email_template!(template::EmailTemplate)
    VERIFICATION_EMAIL_TEMPLATE[] = template
    return template
end

function build_verification_context(user, token::String; extra::Dict{String,Any}=Dict{String,Any}())
    url_base = verification_base_url()
    verification_url = isempty(url_base) ? "" : string(url_base, occursin('?', url_base) ? "&" : "?", "token=", token)

    context = Dict{String,Any}(
        "token" => token,
        "verification_url" => verification_url,
        "email" => user.email,
        "name" => user.name,
        "user_id" => user.id,
        "uuid" => user.uuid,
    )

    merge!(context, extra)
    return context
end

function render_verification_email(user, token::String; extra::Dict{String,Any}=Dict{String,Any}())
    template = VERIFICATION_EMAIL_TEMPLATE[]
    context = build_verification_context(user, token; extra)
    subject = Mustache.render(template.subject, context)
    body = Mustache.render(template.body, context)
    return subject, body, context
end

function dispatch_verification_email(user, token::String)
    sender = EMAIL_SENDER[]
    isnothing(sender) && return nothing

    subject, body, context = render_verification_email(user, token)
    email = VerificationEmail(user.email, subject, body, context)
    sender(email)
end

function maybe_create_verification_record(user)
    if !email_confirmation_enforced()
        return nothing
    end

    deleteMany(OrionAuth_EmailVerification, Dict("where" => Dict("userId" => user.id)))

    token = generate_verification_token()
    create(OrionAuth_EmailVerification, Dict(
        "userId" => user.id,
        "token" => token,
        "created_at" => string(Dates.now()),
    ))

    dispatch_verification_email(user, token)
    return token
end

function verification_record_expired(record)
    ttl_seconds = verification_token_ttl()
    created_at = try
        Dates.DateTime(record.created_at)
    catch
        return false
    end

    created_at + Dates.Second(ttl_seconds) < Dates.now()
end

function verify_email(token::String)
    record = findFirst(OrionAuth_EmailVerification; query=Dict("where" => Dict("token" => token)))
    if isnothing(record)
        error("Invalid verification token")
    end

    if verification_record_expired(record)
        deleteMany(OrionAuth_EmailVerification, Dict("where" => Dict("id" => record.id)))
        error("Verification token expired")
    end

    update(OrionAuth_User, Dict(
        "set" => Dict("email_confirmed" => true),
        "where" => Dict("id" => record.userId),
    ))

    deleteMany(OrionAuth_EmailVerification, Dict("where" => Dict("userId" => record.userId)))
    @async LogAction("verify_email", record.userId)
    return findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => record.userId)))
end

function resend_verification_token(email::String)
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if isnothing(user)
        error("User not found")
    end

    if !email_confirmation_enforced()
        return nothing
    end

    if user.email_confirmed
        return nothing
    end

    token = maybe_create_verification_record(user)
    isnothing(token) && return nothing

    @async LogAction("resend_verification", user.id)
    return token
end


function user_email_confirmed(user)
    if hasproperty(user, :email_confirmed)
        return getproperty(user, :email_confirmed)
    elseif isa(user, AbstractDict)
        return get(user, :email_confirmed, get(user, "email_confirmed", true))
    else
        return true
    end
end


function LogAction(action::String, user)
    return LogAction(action, user.id)
end
function LogAction(action::String, userId::Int)
    ts = string(Dates.now())
    return create(OrionAuth_Log, Dict("userId"=>userId, "action"=>action, "timestamp"=>ts))
end

function signup(email::String, name::String, password::String)
    existing = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if !isnothing(existing)
        error("User already exists")
    end
    uuid = string(UUIDs.uuid4())
    hashed_password = __ORION__HashPassword(password)
    enforce = email_confirmation_enforced()
    newUser = create(OrionAuth_User, Dict(
        "email" => email,
        "name" => name,
        "uuid" => uuid,
        "password" => hashed_password,
        "email_confirmed" => !enforce,
        ))
    @async LogAction("signup", newUser.id)

    if enforce
        maybe_create_verification_record(newUser)
        @async LogAction("signup_pending_verification", newUser.id)
        response = Dict(
            "status" => "verification_required",
            "email_confirmed" => false,
        ) |> JSON3.write
        return newUser, response
    end

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

    if !__ORION__VerifyPassword(password, user.password)
        error("Invalid password")
    end

    if email_confirmation_enforced() && !user_email_confirmed(user)
        error("Email confirmation required")
    end
    @async LogAction("signin", user.id)

    payload = GenerateJWT(user)

    returnData = Dict(
        "access_token" => payload,
        "token_type" => "Bearer",
        "expiration" => parse(Int, ENV["OrionAuth_JWT_EXP"])*60,
    ) |> JSON3.write

    return user, returnData
end


"""
    extractBearerToken() -> String

Extracts the JWT from the `Authorization: Bearer <token>` header.
Throws 401 if header is missing, 400 if format is invalid.
"""
function extractBearerToken()
    headers = Genie.Requests.request().headers |> Dict

    auth_key = nothing
    for k in keys(headers)
        if lowercase(k) == "authorization"
        auth_key = k
        break
        end
    end
    if isnothing(auth_key)
        # Uses ExceptionalResponse - ExceptionalResponse(status, headers, body)
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end  

    auth_header = headers[auth_key]

    # Get JWT token from the header
    # Split using space
    parts = split(auth_header, " ")
    if length(parts) != 2 || parts[1] != "Bearer"
        throw(Genie.Exceptions.ExceptionalResponse(400, [], "Invalid Authorization header format"))
    end

    token = parts[2]
    return token
end

"""
    decodeJWT(token::AbstractString) -> Dict

Decodes and verifies the JWT signature.
Throws 401 if token is invalid or expired.
"""
function decodeJWT(token::AbstractString)
    try
        return __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"])
    catch
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Invalid or expired token"))
    end
end

"""
    Auth(requiredRole::Union{String, Vector{String}}="") -> Dict

1. Extracts and verifies JWT.
2. Optionally checks that the decoded payload contains the given role(s).
3. Returns the decoded payload for further use (e.g. getUserData can just call Auth()).

Throws:
- 401 if token missing/invalid,
- 403 if requiredRole is not present in user roles.
"""
function Auth(requiredPermission::Union{String, Vector{String}} = "")
    token = extractBearerToken()
    payload = decodeJWT(token)

    # normalize roles to a Vector{String}
    userPermissions = payload["permissions"] .|> r -> r[:permission] .|> String

    if requiredPermission != ""
        required = isa(requiredPermission, String) ? [requiredPermission] : requiredPermission
        if !all(r-> r in userPermissions, required)
            throw(Genie.Exceptions.ExceptionalResponse(403, [], "Forbidden: missing role(s) $(required)"))
        end
    end

    return payload
end


function getUserData()
    headers = Genie.Requests.request().headers |> Dict
    # Find user by Authorization header (case insensitive)
    auth_key = nothing
    for k in keys(headers)
        if lowercase(k) == "authorization"
        auth_key = k
        break
        end
    end
    if isnothing(auth_key)
        # Uses ExceptionalResponse - ExceptionalResponse(status, headers, body)
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end  

    auth_header = headers[auth_key]

    # Get JWT token from the header
    # Split using space
    parts = split(auth_header, " ")
    if length(parts) != 2 || parts[1] != "Bearer"
        throw(Genie.Exceptions.ExceptionalResponse(400, [], "Invalid Authorization header format"))
    end

    token = parts[2]

    # Decode JWT token
    payload = nothing
    try
        payload = __ORION__DecodeJWT(token, ENV["OrionAuth_SECRET"]) # Auto verify signature
    catch e
        # Return 401 Unauthorized if JWT is invalid
        throw(Genie.Exceptions.ExceptionalResponse(401, [], "Authorization header is missing"))
    end
    return payload
end
    

function GenerateJWT(user)
    payload = Dict("sub" => user.id, "name" => user.name, "email" => user.email, "uuid" => user.uuid, "roles" => getUserRoles(user.id), "permissions" => getUserPermissions(user.id))
    token = __ORION__EncodeJWT(payload, ENV["OrionAuth_SECRET"], ENV["OrionAuth_ALGORITHM"])
    return token
end
