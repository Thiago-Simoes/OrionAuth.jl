# Test framework-agnostic functionality with HTTP.jl

using Test
using HTTP
using JSON3
using OrionAuth
using OrionORM

# Initialize OrionAuth
OrionAuth.init!()

@testset verbose=true "HTTP.jl Framework Integration" begin
    # Create test user for HTTP.jl tests
    test_user, jwt_data = signup("httpjl@test.com", "HTTP.jl Test User", "testpass123")
    test_token = JSON3.parse(jwt_data)["access_token"]
    
    @testset "HTTPRequestContext" begin
        # Test with valid Authorization header
        headers = ["Authorization" => "Bearer $test_token"]
        req = HTTP.Request("GET", "/test", headers)
        ctx = HTTPRequestContext(req)
        
        @test ctx isa RequestContext
        
        # Test get_headers
        req_headers = get_headers(ctx)
        @test haskey(req_headers, "Authorization")
        @test req_headers["Authorization"] == "Bearer $test_token"
        
        # Test extract_bearer_token
        token = extract_bearer_token(ctx)
        @test token == test_token
    end
    
    @testset "Auth with HTTPRequestContext" begin
        headers = ["Authorization" => "Bearer $test_token"]
        req = HTTP.Request("GET", "/test", headers)
        ctx = HTTPRequestContext(req)
        
        # Test basic authentication
        payload = Auth(ctx)
        @test payload["email"] == "httpjl@test.com"
        @test payload["sub"] == test_user.id
    end
    
    @testset "getUserData with HTTPRequestContext" begin
        headers = ["Authorization" => "Bearer $test_token"]
        req = HTTP.Request("GET", "/test", headers)
        ctx = HTTPRequestContext(req)
        
        user_data = getUserData(ctx)
        @test user_data["email"] == "httpjl@test.com"
        @test user_data["name"] == "HTTP.jl Test User"
    end
    
    @testset "Error handling with HTTP.jl" begin
        # Test missing Authorization header
        req = HTTP.Request("GET", "/test", [])
        ctx = HTTPRequestContext(req)
        
        @test_throws ResponseException extract_bearer_token(ctx)
        
        try
            extract_bearer_token(ctx)
        catch ex
            @test ex isa ResponseException
            @test ex.status == 401
            @test ex.body == "Authorization header is missing"
        end
        
        # Test invalid Authorization header format
        req = HTTP.Request("GET", "/test", ["Authorization" => "Token $test_token"])
        ctx = HTTPRequestContext(req)
        
        @test_throws ResponseException extract_bearer_token(ctx)
        
        try
            extract_bearer_token(ctx)
        catch ex
            @test ex isa ResponseException
            @test ex.status == 400
            @test ex.body == "Invalid Authorization header format"
        end
        
        # Test to_http_response conversion
        response_ex = ResponseException(403, [], "Forbidden access")
        http_response = to_http_response(response_ex)
        @test http_response isa HTTP.Response
        @test http_response.status == 403
        @test String(http_response.body) == "Forbidden access"
    end
    
    @testset "HTTP.jl Server Integration" begin
        # Assign admin role to test user
        admin_role = findFirst(OrionAuth_Role; query=Dict("where" => Dict("role" => "admin")))
        if isnothing(admin_role)
            admin_role = create(OrionAuth_Role, Dict(
                "role" => "admin",
                "description" => "Administrator role"
            ))
        end
        assignRole(test_user.id, "admin")
        
        # Create fresh token with admin permissions
        _, admin_jwt_data = signin("httpjl@test.com", "testpass123")
        admin_token = JSON3.parse(admin_jwt_data)["access_token"]
        
        # Test permission check
        headers = ["Authorization" => "Bearer $admin_token"]
        req = HTTP.Request("GET", "/test", headers)
        ctx = HTTPRequestContext(req)
        
        # Test Auth with permission requirement (should succeed with admin)
        payload = Auth(ctx, "read")
        @test payload["email"] == "httpjl@test.com"
        
        # Test with permission the user doesn't have
        headers = ["Authorization" => "Bearer $test_token"]  # Old token without admin
        req = HTTP.Request("GET", "/test", headers)
        ctx = HTTPRequestContext(req)
        
        @test_throws ResponseException Auth(ctx, "nonexistent_permission")
    end
    
    # Cleanup
    deleteMany(OrionAuth_UserRole, Dict("where" => Dict("userId" => test_user.id)))
    delete(test_user)
end

println("✓ HTTP.jl framework integration tests passed")
