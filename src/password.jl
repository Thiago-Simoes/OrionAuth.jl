using Random
using SHA
using Sodium
using Logging

abstract type AbstractPasswordAlgorithm end

"""
    Argon2idAlgorithm(; opslimit, memlimit)

Encapsulates the parameters required to hash passwords using libsodium's
`crypto_pwhash_str` (Argon2id).
"""
struct Argon2idAlgorithm <: AbstractPasswordAlgorithm
    opslimit::UInt64
    memlimit::UInt64
end

Argon2idAlgorithm(; opslimit = Sodium.crypto_pwhash_OPSLIMIT_MODERATE,
                     memlimit = Sodium.crypto_pwhash_MEMLIMIT_MODERATE) =
    Argon2idAlgorithm(UInt64(opslimit), UInt64(memlimit))

"""
    LegacySHA512Algorithm()

Maintains compatibility with OrionAuth's historical SHA-512 based password
hashing scheme.
"""
struct LegacySHA512Algorithm <: AbstractPasswordAlgorithm end

const ARGON2ID_PREFIX = "\$argon2id\$"
const LEGACY_SHA512_PREFIX = "sha512&"

const DEFAULT_PASSWORD_ALGORITHM = :argon2id
const SUPPORTED_PASSWORD_ALGORITHMS = Dict{Symbol, AbstractPasswordAlgorithm}(
    :argon2id => Argon2idAlgorithm(),
    :sha512 => LegacySHA512Algorithm(),
)

_normalize_algorithm_name(name::AbstractString) = Symbol(lowercase(strip(name)))
_normalize_algorithm_name(name::Symbol) = Symbol(lowercase(String(name)))

function _algorithm_from_symbol(name::Symbol)
    algo = get(SUPPORTED_PASSWORD_ALGORITHMS, name, nothing)
    algo === nothing &&
        throw(ArgumentError("Password algorithm '$(name)' is not supported"))
    algo
end

function _default_algorithm_name()
    chosen = get(ENV, "OrionAuth_PASSWORD_ALGORITHM", nothing)
    if chosen !== nothing
        normalized = _normalize_algorithm_name(chosen)
        if haskey(SUPPORTED_PASSWORD_ALGORITHMS, normalized)
            return normalized
        else
            @warn "Unknown password algorithm '$(chosen)'; falling back to '$(DEFAULT_PASSWORD_ALGORITHM)'"
        end
    end
    DEFAULT_PASSWORD_ALGORITHM
end

function _resolve_algorithm(algorithm)
    if algorithm === nothing
        return _algorithm_from_symbol(_default_algorithm_name())
    elseif algorithm isa Symbol
        return _algorithm_from_symbol(_normalize_algorithm_name(algorithm))
    elseif algorithm isa AbstractPasswordAlgorithm
        return algorithm
    else
        throw(ArgumentError("Unsupported algorithm specification of type $(typeof(algorithm))"))
    end
end

"""
    hash_password(password::AbstractString; algorithm = nothing) -> String

Hash `password` using the selected algorithm. If `algorithm` is `nothing`, the
default algorithm (configurable via `ENV["OrionAuth_PASSWORD_ALGORITHM"]`) is
used. You can provide either the algorithm's symbolic name or an
`AbstractPasswordAlgorithm` instance.
"""
function hash_password(password::AbstractString; algorithm = nothing)::String
    algo = _resolve_algorithm(algorithm)
    hash_password(algo, password)
end

hash_password(name::Symbol, password::AbstractString) =
    hash_password(password; algorithm = name)

function hash_password(algorithm::Argon2idAlgorithm, password::AbstractString)::String
    buf = Vector{UInt8}(undef, Sodium.crypto_pwhash_STRBYTES)
    status = Sodium.crypto_pwhash_str(
        buf,
        password,
        UInt64(ncodeunits(password)),
        algorithm.opslimit,
        algorithm.memlimit,
    )
    @assert status == 0 "crypto_pwhash_str failed"
    unsafe_string(pointer(buf))
end

function hash_password(::LegacySHA512Algorithm, password::AbstractString)::String
    salt = Random.randstring(RandomDevice(), 32)
    min_iterations = parse(Int, get(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS", "25000"))
    max_iterations = max(min_iterations, min_iterations * 2)
    iterations = rand(min_iterations:max_iterations)

    hashed = "$(password)&$(salt)"
    for _ in 1:iterations
        hashed = bytes2hex(sha512(hashed))
    end

    "sha512&$(hashed)&$(salt)&$(iterations)"
end

function _try_verify(::AbstractPasswordAlgorithm, ::AbstractString, ::AbstractString)
    nothing
end

function _try_verify(algorithm::Argon2idAlgorithm, stored::AbstractString, password::AbstractString)
    startswith(stored, ARGON2ID_PREFIX) || return nothing
    status = Sodium.crypto_pwhash_str_verify(
        stored,
        password,
        UInt64(ncodeunits(password)),
    )
    status == 0
end

function _try_verify(::LegacySHA512Algorithm, stored::AbstractString, password::AbstractString)
    startswith(stored, LEGACY_SHA512_PREFIX) || return nothing

    parts = split(stored, "&")
    length(parts) == 4 || return false

    hashed_password = parts[2]
    salt = parts[3]
    iterations = tryparse(Int, parts[4])
    iterations === nothing && return false

    hashed = "$(password)&$(salt)"
    for _ in 1:iterations
        hashed = bytes2hex(sha512(hashed))
    end

    hashed == hashed_password
end

"""
    verify_password(stored::AbstractString, password::AbstractString; algorithm = nothing) -> Bool

Verify that `password` matches `stored`. When `algorithm` is omitted, OrionAuth
detects the hash format and validates it with the corresponding supported
algorithm.
"""
function verify_password(stored::AbstractString, password::AbstractString; algorithm = nothing)::Bool
    if algorithm !== nothing
        algo = _resolve_algorithm(algorithm)
        result = _try_verify(algo, stored, password)
        return result === nothing ? false : result
    end

    if startswith(stored, ARGON2ID_PREFIX)
        return _try_verify(SUPPORTED_PASSWORD_ALGORITHMS[:argon2id], stored, password) === true
    elseif startswith(stored, LEGACY_SHA512_PREFIX)
        return _try_verify(SUPPORTED_PASSWORD_ALGORITHMS[:sha512], stored, password) === true
    end

    result = _try_verify(SUPPORTED_PASSWORD_ALGORITHMS[:argon2id], stored, password)
    if result !== nothing
        return result
    end

    result = _try_verify(SUPPORTED_PASSWORD_ALGORITHMS[:sha512], stored, password)
    result === nothing ? false : result
end

"""
    __ORION__HashPassword(password::String) -> String

Backwards-compatible helper used by existing OrionAuth code.
"""
__ORION__HashPassword(password::String) = hash_password(password)

"""
    __ORION__VerifyPassword(password::String, stored::String) -> Bool

Backwards-compatible helper used by existing OrionAuth code.
"""
__ORION__VerifyPassword(password::String, stored::String) =
    verify_password(stored, password)

