using Random
using SHA

# Utils for password validation and hashing
function __ORION__HashPassword(password::String)
    generateSalt = Random.randstring(RandomDevice(), 32)
    nIterations = rand(parse(Int, ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"]):(parse(Int, ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"])*2))

    hashed = "$(password)&$(generateSalt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end
    return "sha512&$(hashed)&$(generateSalt)&$(nIterations)"
end

function __ORION__VerifyPassword(password::String, hashed::String)
    parts = split(hashed, "&")
    if length(parts) != 4
        return false
    end

    algorithm = parts[1]
    hashedPassword = parts[2]
    salt = parts[3]
    nIterations = parse(Int, parts[4])

    if algorithm != "sha512"
        return false
    end

    hashed = "$(password)&$(salt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end

    return hashed == hashedPassword
end