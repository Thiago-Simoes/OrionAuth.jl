# Test the improved context integration

using Test
using HTTP
using JSON3
using OrionAuth
using OrionORM

# Initialize OrionAuth
OrionAuth.init!()

@testset "Improved Context Integration" begin
    # Create test user
    test_user, jwt_data =
        signup("ctx_improved@test.com", "Context Improved User", "testpass123")
    test_token = JSON3.parse(jwt_data)["access_token"]

    @testset "Auto-detection with HTTP.jl" begin
        # Configure framework explicitly
        configure_framework!(:http)
        @test get_configured_framework() == :http

        # Test with simplified API - pass request
        headers = ["Authorization" => "Bearer $test_token"]
        req = HTTP.Request("GET", "/test", headers)

        # Simplified Auth with request parameter
        payload = Auth(request = req)
        @test payload["email"] == "ctx_improved@test.com"
        @test payload["sub"] == test_user.id

        # Simplified getUserData with request parameter
        user_data = getUserData(request = req)
        @test user_data["email"] == "ctx_improved@test.com"
    end

    @testset "Configuration persistence" begin
        # Reset to auto
        configure_framework!(:auto)
        @test get_configured_framework() == :auto

        # Set to http
        configure_framework!(:http)
        @test get_configured_framework() == :http

        # Reset back to auto
        configure_framework!(:auto)
    end

    @testset "Error handling with auto-conversion" begin
        configure_framework!(:http)

        # Test with missing Authorization header
        req = HTTP.Request("GET", "/test", [])

        # This should throw but catch and convert to HTTP.Response
        error_thrown = false
        try
            Auth(request = req)
        catch ex
            error_thrown = true
            # Should be converted to HTTP.Response by handle_auth_exception
            @test ex isa Exception  # Could be ResponseException or HTTP response
        end
        @test error_thrown
    end

    @testset "Permission checking with simplified API" begin
        # Ensure permissions exist
        syncRolesAndPermissions(Dict("admin" => ["read", "write", "delete"]))

        # Assign admin role
        admin_role =
            findFirst(OrionAuth_Role; query = Dict("where" => Dict("role" => "admin")))
        assignRole(test_user.id, "admin")

        # Get fresh token with permissions
        _, fresh_jwt_data = signin("ctx_improved@test.com", "testpass123")
        fresh_token = JSON3.parse(fresh_jwt_data)["access_token"]

        configure_framework!(:http)

        headers = ["Authorization" => "Bearer $fresh_token"]
        req = HTTP.Request("GET", "/test", headers)

        # Test Auth with permission requirement using simplified API
        payload = Auth("read", request = req)
        @test payload["email"] == "ctx_improved@test.com"
    end

    # Cleanup
    deleteMany(OrionAuth_UserRole, Dict("where" => Dict("userId" => test_user.id)))
    delete(test_user)
end

println("✓ Improved context integration tests passed")
