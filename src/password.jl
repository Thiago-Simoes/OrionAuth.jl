using Random
using SHA
using Sodium

struct PasswordAlgorithm
    name::String
    hash::Function
    matches::Function
    verify::Function
end

const PASSWORD_ALGORITHMS = Dict{String,PasswordAlgorithm}()
const DEFAULT_PASSWORD_ALGORITHM = Base.RefValue{String}("argon2id")

const ARGON2_DEFAULT_OPSLIMIT = UInt64(Sodium.crypto_pwhash_OPSLIMIT_MODERATE)
const ARGON2_DEFAULT_MEMLIMIT = UInt64(Sodium.crypto_pwhash_MEMLIMIT_MODERATE)

const PASSWORD_TOKEN_ALPHABET = join(vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9')))

register_password_algorithm!(algo::PasswordAlgorithm) = PASSWORD_ALGORITHMS[lowercase(algo.name)] = algo

function set_default_password_algorithm!(name::String)
    lname = lowercase(name)
    haskey(PASSWORD_ALGORITHMS, lname) || error("Unknown password algorithm: $(name)")
    DEFAULT_PASSWORD_ALGORITHM[] = lname
end

function configured_password_algorithm()
    configured = lowercase(get(ENV, "OrionAuth_PASSWORD_ALGORITHM", DEFAULT_PASSWORD_ALGORITHM[]))
    return haskey(PASSWORD_ALGORITHMS, configured) ? configured : DEFAULT_PASSWORD_ALGORITHM[]
end

function __ORION__HashPassword(password::String)
    algo = PASSWORD_ALGORITHMS[configured_password_algorithm()]
    return algo.hash(password)
end

function __ORION__VerifyPassword(password::String, hashed::String)
    for algo in values(PASSWORD_ALGORITHMS)
        if algo.matches(hashed)
            return algo.verify(password, hashed)
        end
    end

    legacy = PASSWORD_ALGORITHMS["sha512"]
    return legacy.verify(password, hashed)
end

function argon2_limits()
    opslimit = try
        parse(UInt64, get(ENV, "OrionAuth_ARGON2_OPSLIMIT", string(ARGON2_DEFAULT_OPSLIMIT)))
    catch
        ARGON2_DEFAULT_OPSLIMIT
    end

    memlimit = try
        parse(UInt64, get(ENV, "OrionAuth_ARGON2_MEMLIMIT", string(ARGON2_DEFAULT_MEMLIMIT)))
    catch
        ARGON2_DEFAULT_MEMLIMIT
    end

    return opslimit, memlimit
end

function argon2_hash(password::String)
    opslimit, memlimit = argon2_limits()
    buffer = Vector{UInt8}(undef, Sodium.crypto_pwhash_STRBYTES)
    status = Sodium.crypto_pwhash_str(buffer, password, UInt64(ncodeunits(password)), opslimit, memlimit)
    @assert status == 0 "crypto_pwhash_str failed"
    return unsafe_string(pointer(buffer))
end

function argon2_verify(password::String, hashed::String)
    status = Sodium.crypto_pwhash_str_verify(hashed, password, UInt64(ncodeunits(password)))
    return status == 0
end

function sha512_min_iterations()
    raw = get(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS", "25000")
    value = try
        parse(Int, raw)
    catch
        25_000
    end

    max(value, 1)
end

function sha512_hash(password::String)
    salt = Random.randstring(RandomDevice(), PASSWORD_TOKEN_ALPHABET, 32)
    base_iterations = sha512_min_iterations()
    iterations = rand(base_iterations:(base_iterations * 2))

    hashed = "$(password)&$(salt)"
    for _ in 1:iterations
        hashed = bytes2hex(sha512(hashed))
    end

    return "sha512&$(hashed)&$(salt)&$(iterations)"
end

function sha512_verify(password::String, hashed::String)
    parts = split(hashed, "&")
    if length(parts) != 4
        return false
    end

    _, stored_hash, salt, raw_iterations = parts

    iterations = try
        parse(Int, raw_iterations)
    catch
        return false
    end

    candidate = "$(password)&$(salt)"
    for _ in 1:iterations
        candidate = bytes2hex(sha512(candidate))
    end

    return candidate == stored_hash
end

if isempty(PASSWORD_ALGORITHMS)
    register_password_algorithm!(PasswordAlgorithm(
        "argon2id",
        password -> argon2_hash(password),
        hashed -> startswith(hashed, "\\$argon2id\\$"),
        (password, hashed) -> argon2_verify(password, hashed),
    ))

    register_password_algorithm!(PasswordAlgorithm(
        "sha512",
        password -> sha512_hash(password),
        hashed -> startswith(hashed, "sha512&"),
        (password, hashed) -> sha512_verify(password, hashed),
    ))

    DEFAULT_PASSWORD_ALGORITHM[] = "argon2id"
end

export PasswordAlgorithm, register_password_algorithm!, set_default_password_algorithm!
