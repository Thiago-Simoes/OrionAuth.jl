using Random
using SHA

# Utils for password validation and hashing
function __NEBULA__HashPassword(password::String)
    # Hash the password using SHA-256
    generateSalt = Random.randstring(RandomDevice(), 32)
    nIterations = rand(parse(Int, ENV["NEBULAAUTH_MIN_PASSWORD_ITTERATIONS"]):(parse(Int, ENV["NEBULAAUTH_MIN_PASSWORD_ITTERATIONS"])*2))

    hashed = "$(password)&$(generateSalt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end
    return "sha512&$(hashed)&$(generateSalt)&$(nIterations)"
end

function __NEBULA__VerifyPassword(password::String, hashed::String)
    # Verify the password using SHA-256
    parts = split(hashed, "&")
    if length(parts) != 4
        return false
    end

    algorithm = parts[1]
    hashed_password = parts[2]
    salt = parts[3]
    nIterations = parse(Int, parts[4])

    if algorithm != "sha512"
        return false
    end

    # Recreate the hash with the provided password and compare
    hashed = "$(password)&$(salt)"
    for i in 1:nIterations
        hashed = bytes2hex(sha512(hashed))
    end

    return hashed == hashed_password
end