"""
Password reset functionality for OrionAuth.

This module provides functions to handle the complete password reset flow:
1. Request a password reset token
2. Verify token validity and expiration
3. Reset password using a valid token
"""

using Dates
using Random
using SHA

"""
    request_password_reset(email::String; send_mail::Union{Function, Nothing}=nothing) -> String

Generate a password reset token for a user and optionally send it via email.

# Arguments
- `email::String`: User's email address
- `send_mail::Union{Function, Nothing}`: Optional email sending function. If provided, must accept three arguments:
  - `recipient::String`: Email address
  - `subject::String`: Email subject
  - `body::String`: Email body (HTML)

# Returns
- `String`: The generated reset token (only for testing; in production, only send via email)

# Throws
- `error("User not found")`: If email doesn't exist in the database
- `error("send_mail function is required but not provided")`: If send_mail is required by configuration but not provided

# Configuration
Set `OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION` environment variable to control token expiration in minutes (default: 60 minutes).

# Examples
```julia
# Without email (returns token for testing)
token = request_password_reset("user@example.com")

# With email function
function my_send_mail(recipient, subject, body)
    # Send email using your preferred service
    println("Sending to: \$recipient")
    println("Subject: \$subject")
    println("Body: \$body")
end

token = request_password_reset("user@example.com", send_mail=my_send_mail)
```
"""
function request_password_reset(email::String; send_mail::Union{Function, Nothing}=nothing)
    # Find user by email
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("email" => email)))
    if isnothing(user)
        error("User not found")
    end
    
    # Generate secure random token
    token = bytes2hex(Random.rand(RandomDevice(), UInt8, 32))
    
    # Delete any existing reset tokens for this user (one active token per user)
    deleteMany(OrionAuth_PasswordReset, Dict("where" => Dict("userId" => user.id)))
    
    # Save token to database
    create(OrionAuth_PasswordReset, Dict(
        "userId" => user.id,
        "token" => token
    ))
    
    # Log the action
    @async LogAction("password_reset_requested", user.id)
    
    # Send email if function provided
    if !isnothing(send_mail)
        # Get expiration time
        expiration_minutes = parse(Int, get(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION", "60"))
        
        subject = "Password Reset Request"
        body = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello $(user.name),</p>
            <p>We received a request to reset your password. Use the following token to reset your password:</p>
            <p><strong>Token: $token</strong></p>
            <p>This token will expire in $expiration_minutes minutes.</p>
            <p>If you did not request this password reset, please ignore this email.</p>
            <br>
            <p>Best regards,<br>OrionAuth Team</p>
        </body>
        </html>
        """
        
        try
            send_mail(email, subject, body)
        catch e
            @warn "Failed to send password reset email" exception=e
            error("Failed to send password reset email: $(e)")
        end
    end
    
    return token
end

"""
    verify_reset_token(token::String) -> Union{NamedTuple, Nothing}

Verify if a password reset token is valid and not expired.

# Arguments
- `token::String`: The reset token to verify

# Returns
- `NamedTuple` with token information if valid (contains `id`, `userId`, `token`, `created_at`)
- `nothing` if token is invalid or expired

# Configuration
Set `OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION` environment variable to control token expiration in minutes (default: 60 minutes).

# Examples
```julia
token_info = verify_reset_token("abc123...")
if !isnothing(token_info)
    println("Token is valid for user: \$(token_info.userId)")
else
    println("Token is invalid or expired")
end
```
"""
function verify_reset_token(token::String)
    # Find token in database
    reset_record = findFirst(OrionAuth_PasswordReset; query=Dict("where" => Dict("token" => token)))
    
    if isnothing(reset_record)
        return nothing
    end
    
    # Check if token has expired
    expiration_minutes = parse(Int, get(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION", "60"))
    
    # Parse the timestamp
    created_at = DateTime(reset_record.created_at)
    expiration_time = created_at + Minute(expiration_minutes)
    
    if now() > expiration_time
        # Token expired, delete it
        deleteMany(OrionAuth_PasswordReset, Dict("where" => Dict("id" => reset_record.id)))
        return nothing
    end
    
    return reset_record
end

"""
    reset_password_with_token(token::String, new_password::String) -> Bool

Reset a user's password using a valid reset token.

# Arguments
- `token::String`: The reset token
- `new_password::String`: The new password (will be hashed)

# Returns
- `true` if password was successfully reset
- `false` if token is invalid or expired

# Throws
- `error("User not found")`: If the user associated with the token no longer exists

# Examples
```julia
success = reset_password_with_token("abc123...", "newSecurePassword123")
if success
    println("Password reset successful!")
else
    println("Invalid or expired token")
end
```
"""
function reset_password_with_token(token::String, new_password::String)
    # Verify token
    token_info = verify_reset_token(token)
    
    if isnothing(token_info)
        return false
    end
    
    # Find user
    user = findFirst(OrionAuth_User; query=Dict("where" => Dict("id" => token_info.userId)))
    
    if isnothing(user)
        error("User not found")
    end
    
    # Hash new password
    hashed_password = __ORION__HashPassword(new_password)
    
    # Update user's password
    update(OrionAuth_User, Dict("where" => Dict("id" => token_info.userId)), Dict("password" => hashed_password))
    
    # Delete the used token
    deleteMany(OrionAuth_PasswordReset, Dict("where" => Dict("id" => token_info.id)))
    
    # Log the action
    @async LogAction("password_reset_completed", user.id)
    
    return true
end
