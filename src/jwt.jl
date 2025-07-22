# Implements JSON Web Token (JWT) encoding and decoding

# Based on https://datatracker.ietf.org/doc/html/rfc7519
# Accessed on 2025-05-03

using JSON3
using Base64
using Nettle

function __ORION__EncodeJWT(inputPayload::Dict, secret::AbstractString, algorithm::AbstractString="HS256")
    header = Dict("alg" => algorithm, "typ" => "JWT")
    headerEncoded = base64encode(JSON3.write(header))

    iat = round(Int, time())
    exp = iat + (parse(Int, ENV["OrionAuth_JWT_EXP"]) * 60)
    payload = Dict("sub" => inputPayload["sub"], "name" => inputPayload["name"], "iat" => iat, "exp" => exp)

    for key in ("email", "uuid", "roles", "permissions")
        if haskey(inputPayload, key)
            payload[key] = inputPayload[key]
        end
    end

    payload_encoded = base64url_encode(JSON3.write(payload))
    signature = __ORION__Sign(headerEncoded, payload_encoded, ENV["OrionAuth_SECRET"], algorithm)
    return "$headerEncoded.$payload_encoded.$signature"
end

function __ORION__DecodeJWT(token::AbstractString, secret::AbstractString = ENV["OrionAuth_SECRET"])
    parts = split(token, ".")
    if length(parts) != 3
        error("Invalid JWT format")
    end
    
    headerEncoded, payloadEncoded, signature = parts
    header = JSON3.read(base64url_decode2string(headerEncoded))
    payload = JSON3.read(base64url_decode2string(payloadEncoded))

    if header["alg"] != ENV["OrionAuth_ALGORITHM"]
        error("Invalid JWT algorithm")
    end

    verified = __ORION__Verify(headerEncoded, payloadEncoded, signature, ENV["OrionAuth_SECRET"], header["alg"])

    if !haskey(payload, "exp")
        error("JWT does not contain expiration time")
    end

    if payload["exp"] < time()
        error("JWT has expired")
    end

    if !verified
        error("Invalid JWT signature")
    end
    return payload
end


function __ORION__Sign(
    headerEncoded::AbstractString,
    payloadEncoded::AbstractString,
    secret::AbstractString,
    algorithm::AbstractString
)::AbstractString
    if algorithm == "HS256"
        h = HMACState("sha256", secret)
        Nettle.update!(h, "$headerEncoded.$payloadEncoded")
        
        return base64url_encode(Nettle.digest!(h)) # digest! returns a vector of UInt8
    elseif algorithm == "HS512"
        h = HMACState("sha512", secret)
        Nettle.update!(h, "$headerEncoded.$payloadEncoded")

        return base64url_encode(Nettle.digest!(h)) # digest! returns a vector of UInt8
    else
        error("Unsupported algorithm: $algorithm")
    end
end

function __ORION__Verify(
    headerEncoded::AbstractString,
    payloadEncoded::AbstractString,
    signature::AbstractString,
    secret::AbstractString,
    algorithm::AbstractString
)::Bool
    if algorithm in ["HS256", "HS512"]
        expectedSignature = __ORION__Sign(headerEncoded, payloadEncoded, secret, algorithm)
        return expectedSignature == signature
    else
        error("Unsupported algorithm: $algorithm")
    end
end
