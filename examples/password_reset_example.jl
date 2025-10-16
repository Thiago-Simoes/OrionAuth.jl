#!/usr/bin/env julia

"""
Example demonstrating the password reset flow in OrionAuth.jl

This script shows:
1. How to request a password reset
2. How to verify a reset token
3. How to reset a password using a token
4. Integration with email sending
"""

using OrionAuth
using OrionORM

# Initialize OrionAuth
OrionAuth.init!()

println("=== OrionAuth Password Reset Example ===\n")

# Step 1: Create a test user (in real app, user would already exist)
println("Step 1: Creating test user...")
test_email = "demo@example.com"
user, _ = signup(test_email, "Demo User", "oldPassword123")
println("✓ User created: $(user.email)\n")

# Step 2: Define an email sending function
# In production, this would integrate with your email service (SendGrid, AWS SES, etc.)
function demo_send_mail(recipient::String, subject::String, body::String)
    println("=" ^ 80)
    println("📧 Email would be sent:")
    println("To: $recipient")
    println("Subject: $subject")
    println("\nBody preview:")
    println("-" ^ 80)
    # Extract just the token from the HTML body for display
    token_match = match(r"Token: ([a-f0-9]+)", body)
    if !isnothing(token_match)
        println("Password reset token: $(token_match.captures[1])")
    end
    println("-" ^ 80)
    println("=" ^ 80)
    println()
end

# Step 3: Request password reset
println("Step 2: Requesting password reset...")
token = request_password_reset(test_email, send_mail=demo_send_mail)
println("✓ Password reset requested\n")

# Step 4: Verify the token (optional - to check if it's valid before using)
println("Step 3: Verifying reset token...")
token_info = verify_reset_token(token)
if !isnothing(token_info)
    println("✓ Token is valid")
    println("  - User ID: $(token_info.userId)")
    println("  - Created at: $(token_info.created_at)\n")
else
    println("✗ Token is invalid or expired\n")
end

# Step 5: Reset the password
println("Step 4: Resetting password with token...")
new_password = "newSecurePassword456"
success = reset_password_with_token(token, new_password)

if success
    println("✓ Password reset successful!\n")
else
    println("✗ Password reset failed (invalid or expired token)\n")
    exit(1)
end

# Step 6: Verify we can sign in with the new password
println("Step 5: Verifying new password works...")
try
    signin_user, jwt_data = signin(test_email, new_password)
    println("✓ Successfully signed in with new password")
    println("  - User: $(signin_user.name)")
    println("  - Email: $(signin_user.email)\n")
catch e
    println("✗ Failed to sign in with new password: $e\n")
    exit(1)
end

# Step 7: Verify old password no longer works
println("Step 6: Verifying old password no longer works...")
try
    signin(test_email, "oldPassword123")
    println("✗ WARNING: Old password still works (this shouldn't happen!)\n")
    exit(1)
catch e
    if occursin("Invalid password", string(e))
        println("✓ Old password correctly rejected\n")
    else
        println("✗ Unexpected error: $e\n")
        exit(1)
    end
end

# Step 8: Verify token can't be reused
println("Step 7: Verifying token can't be reused...")
second_attempt = reset_password_with_token(token, "anotherPassword")
if !second_attempt
    println("✓ Token correctly invalidated after use\n")
else
    println("✗ WARNING: Token can be reused (security issue!)\n")
    exit(1)
end

println("=" ^ 80)
println("✅ All password reset flow steps completed successfully!")
println("=" ^ 80)

# Cleanup
println("\nCleaning up test data...")
deleteMany(OrionAuth_User, Dict("where" => Dict("email" => test_email)))
println("✓ Test user removed")
