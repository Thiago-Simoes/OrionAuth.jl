# Implements JSON Web Token (JWT) encoding and decoding

# Based on https://datatracker.ietf.org/doc/html/rfc7519
# Accessed on 2025-05-03

using JSON3
using Base64

function __NEBULA__EncodeJWT(inputPayload::Dict, secret::AbstractString, algorithm::AbstractString="HS256")
    header = Dict("alg" => algorithm, "typ" => "JWT")
    header_encoded = base64encode(JSON3.write(header))

    # Encode payload
    iat = round(Int, time())
    exp = iat + (parse(Int, ENV["NEBULAAUTH_JWT_EXP"]) * 60)
    payload = Dict("sub" => inputPayload["sub"], "name" => inputPayload["name"], "iat" => iat, "exp" => exp)
    if haskey(inputPayload, "email")
        payload["email"] = inputPayload["email"]
    end

    if haskey(inputPayload, "uuid")
        payload["uuid"] = inputPayload["uuid"]
    end

    # Role-based access control
    if haskey(inputPayload, "roles")
        payload["roles"] = inputPayload["roles"]
    end

    if haskey(inputPayload, "permissions")
        payload["permissions"] = inputPayload["permissions"]
    end

    payload_encoded = base64url_encode(JSON3.write(payload))
    signature = __NEBULA__Sign(header_encoded, payload_encoded, ENV["NEBULAAUTH_SECRET"], algorithm)
    return "$header_encoded.$payload_encoded.$signature"
end

function __NEBULA__DecodeJWT(token::AbstractString, secret::AbstractString = ENV["NEBULAAUTH_SECRET"])
    parts = split(token, ".")
    if length(parts) != 3
        error("Invalid JWT format")
    end
    header_encoded, payload_encoded, signature = parts
    header = JSON3.read(base64url_decode_string(header_encoded))
    payload = JSON3.read(base64url_decode_string(payload_encoded))
    verified = __NEBULA__Verify(header_encoded, payload_encoded, signature, ENV["NEBULAAUTH_SECRET"], header["alg"])
    if !verified
        error("Invalid JWT signature")
    end
    return payload
end


function __NEBULA__Sign(header_encoded::AbstractString, payload_encoded::AbstractString, secret::AbstractString, algorithm::AbstractString)
    # Implement signing logic based on the algorithm
    if algorithm == "HS256"
        return base64url_encode(hexdigest("sha256", secret, "$header_encoded.$payload_encoded"))
    else
        error("Unsupported algorithm: $algorithm")
    end
end

function __NEBULA__Verify(header_encoded::AbstractString, payload_encoded::AbstractString, signature::AbstractString, secret::AbstractString, algorithm::AbstractString)
    # Implement verification logic based on the algorithm
    if algorithm == "HS256"
        expected_signature = __NEBULA__Sign(header_encoded, payload_encoded, secret, algorithm)
        return expected_signature == signature
    else
        error("Unsupported algorithm: $algorithm")
    end
end
