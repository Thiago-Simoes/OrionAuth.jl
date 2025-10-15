# Test with Oxygen framework (when available)

using Test

# Try to load Oxygen, skip tests if not available
oxygen_available = false
try
    using Oxygen
    using HTTP
    using JSON3
    using OrionAuth
    using OrionORM
    
    global oxygen_available = true
    
    # Don't call init!() - it's already called in main test file
catch e
    @warn "Oxygen not available, skipping Oxygen framework tests" exception=e
end

if oxygen_available
    @testset verbose=true "Oxygen Framework Integration" begin
        # Create test user for Oxygen tests
        test_user, jwt_data = signup("oxygen@test.com", "Oxygen Test User", "testpass123")
        test_token = JSON3.parse(jwt_data)["access_token"]
        
        @testset "OxygenRequestContext" begin
            # Test with valid Authorization header
            headers = ["Authorization" => "Bearer $test_token"]
            req = HTTP.Request("GET", "/test", headers)
            ctx = OxygenRequestContext(req)
            
            @test ctx isa RequestContext
            
            # Test get_headers
            req_headers = get_headers(ctx)
            @test haskey(req_headers, "Authorization")
            @test req_headers["Authorization"] == "Bearer $test_token"
            
            # Test extract_bearer_token
            token = extract_bearer_token(ctx)
            @test token == test_token
        end
        
        @testset "Auth with OxygenRequestContext" begin
            headers = ["Authorization" => "Bearer $test_token"]
            req = HTTP.Request("GET", "/test", headers)
            ctx = OxygenRequestContext(req)
            
            # Test basic authentication
            payload = Auth(ctx)
            @test payload["email"] == "oxygen@test.com"
            @test payload["sub"] == test_user.id
        end
        
        @testset "getUserData with OxygenRequestContext" begin
            headers = ["Authorization" => "Bearer $test_token"]
            req = HTTP.Request("GET", "/test", headers)
            ctx = OxygenRequestContext(req)
            
            user_data = getUserData(ctx)
            @test user_data["email"] == "oxygen@test.com"
            @test user_data["name"] == "Oxygen Test User"
        end
        
        @testset "Error handling with Oxygen" begin
            # Test missing Authorization header
            req = HTTP.Request("GET", "/test", [])
            ctx = OxygenRequestContext(req)
            
            @test_throws ResponseException extract_bearer_token(ctx)
            
            try
                extract_bearer_token(ctx)
            catch ex
                @test ex isa ResponseException
                @test ex.status == 401
                @test ex.body == "Authorization header is missing"
            end
            
            # Test to_oxygen_response conversion
            response_ex = ResponseException(403, [], "Forbidden access")
            oxygen_response = to_oxygen_response(response_ex)
            @test oxygen_response isa HTTP.Response
            @test oxygen_response.status == 403
            @test String(oxygen_response.body) == "Forbidden access"
        end
        
        # Cleanup
        delete(test_user)
    end
    
    println("✓ Oxygen framework integration tests passed")
else
    @testset "Oxygen Framework Integration" begin
        @test_skip "Oxygen not available"
    end
    println("⊘ Oxygen framework tests skipped (Oxygen not installed)")
end
