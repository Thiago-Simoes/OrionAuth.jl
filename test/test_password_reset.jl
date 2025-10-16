using Test
using Dates
using OrionAuth

@testset "Password Reset Flow" begin
    # Setup: Create a test user
    test_email = "reset-test-$(rand(1000:9999))@example.com"
    test_user, _ = signup(test_email, "Reset Tester", "oldPassword123")
    
    @testset "Request Password Reset - Without Email" begin
        token = request_password_reset(test_email)
        
        @test !isempty(token)
        @test length(token) == 64  # 32 bytes as hex = 64 characters
        
        # Verify token was saved in database
        reset_record = findFirst(OrionAuth_PasswordReset; 
            query=Dict("where" => Dict("userId" => test_user.id)))
        @test !isnothing(reset_record)
        @test reset_record.token == token
        @test reset_record.userId == test_user.id
    end
    
    @testset "Request Password Reset - With Email Function" begin
        # Track email calls
        email_sent = Ref(false)
        email_recipient = Ref("")
        email_subject = Ref("")
        email_body = Ref("")
        
        function test_send_mail(recipient, subject, body)
            email_sent[] = true
            email_recipient[] = recipient
            email_subject[] = subject
            email_body[] = body
        end
        
        token = request_password_reset(test_email, send_mail=test_send_mail)
        
        @test !isempty(token)
        @test email_sent[]
        @test email_recipient[] == test_email
        @test email_subject[] == "Password Reset Request"
        @test occursin(token, email_body[])
        @test occursin("Password Reset Request", email_body[])
        @test occursin(test_user.name, email_body[])
    end
    
    @testset "Request Password Reset - User Not Found" begin
        @test_throws ErrorException request_password_reset("nonexistent@example.com")
    end
    
    @testset "Request Password Reset - Replaces Existing Token" begin
        # Request first token
        token1 = request_password_reset(test_email)
        
        # Request second token
        token2 = request_password_reset(test_email)
        
        @test token1 != token2
        
        # Verify only one token exists
        reset_records = findMany(OrionAuth_PasswordReset; 
            query=Dict("where" => Dict("userId" => test_user.id)))
        @test length(reset_records) == 1
        @test reset_records[1].token == token2
    end
    
    @testset "Verify Reset Token - Valid Token" begin
        token = request_password_reset(test_email)
        
        token_info = verify_reset_token(token)
        
        @test !isnothing(token_info)
        @test token_info.userId == test_user.id
        @test token_info.token == token
    end
    
    @testset "Verify Reset Token - Invalid Token" begin
        result = verify_reset_token("invalid_token_12345")
        
        @test isnothing(result)
    end
    
    @testset "Verify Reset Token - Expired Token" begin
        # Set very short expiration time
        original_expiration = get(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION", nothing)
        ENV["OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION"] = "0"  # Expire immediately
        
        try
            token = request_password_reset(test_email)
            
            # Wait a moment to ensure expiration
            sleep(0.1)
            
            result = verify_reset_token(token)
            
            @test isnothing(result)
            
            # Verify token was deleted from database
            reset_record = findFirst(OrionAuth_PasswordReset; 
                query=Dict("where" => Dict("token" => token)))
            @test isnothing(reset_record)
        finally
            # Restore original expiration setting
            if isnothing(original_expiration)
                delete!(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION")
            else
                ENV["OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION"] = original_expiration
            end
        end
    end
    
    @testset "Reset Password With Token - Success" begin
        token = request_password_reset(test_email)
        new_password = "newSecurePassword456"
        
        success = reset_password_with_token(token, new_password)
        
        @test success == true
        
        # Verify password was changed
        user = findFirst(OrionAuth_User; 
            query=Dict("where" => Dict("id" => test_user.id)))
        @test OrionAuth.verify_password(user.password, new_password)
        
        # Verify old password no longer works
        @test !OrionAuth.verify_password(user.password, "oldPassword123")
        
        # Verify token was deleted after use
        reset_record = findFirst(OrionAuth_PasswordReset; 
            query=Dict("where" => Dict("token" => token)))
        @test isnothing(reset_record)
    end
    
    @testset "Reset Password With Token - Invalid Token" begin
        success = reset_password_with_token("invalid_token_98765", "newPassword")
        
        @test success == false
    end
    
    @testset "Reset Password With Token - Expired Token" begin
        # Set very short expiration
        original_expiration = get(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION", nothing)
        ENV["OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION"] = "0"
        
        try
            token = request_password_reset(test_email)
            sleep(0.1)
            
            success = reset_password_with_token(token, "newPassword")
            
            @test success == false
        finally
            if isnothing(original_expiration)
                delete!(ENV, "OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION")
            else
                ENV["OrionAuth_PASSWORD_RESET_TOKEN_EXPIRATION"] = original_expiration
            end
        end
    end
    
    @testset "Complete Password Reset Flow" begin
        # 1. User requests password reset
        original_password = "originalPass123"
        flow_test_email = "flow-test-$(rand(1000:9999))@example.com"
        flow_user, _ = signup(flow_test_email, "Flow Tester", original_password)
        
        email_calls = []
        function track_email(recipient, subject, body)
            push!(email_calls, (recipient=recipient, subject=subject, body=body))
        end
        
        # 2. Request reset with email
        token = request_password_reset(flow_test_email, send_mail=track_email)
        @test length(email_calls) == 1
        @test email_calls[1].recipient == flow_test_email
        
        # 3. Verify token is valid
        token_info = verify_reset_token(token)
        @test !isnothing(token_info)
        @test token_info.userId == flow_user.id
        
        # 4. Reset password
        new_password = "newFlowPass456"
        success = reset_password_with_token(token, new_password)
        @test success == true
        
        # 5. Verify user can sign in with new password
        signed_in_user, _ = signin(flow_test_email, new_password)
        @test signed_in_user.id == flow_user.id
        
        # 6. Verify old password doesn't work
        @test_throws ErrorException signin(flow_test_email, original_password)
        
        # 7. Verify token is consumed (can't be reused)
        second_attempt = reset_password_with_token(token, "anotherPassword")
        @test second_attempt == false
    end
    
    @testset "Email Sending Error Handling" begin
        function failing_send_mail(recipient, subject, body)
            error("Email service unavailable")
        end
        
        @test_throws ErrorException request_password_reset(
            test_email, 
            send_mail=failing_send_mail
        )
    end
end
