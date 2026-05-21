# Test framework-agnostic core functionality

using Test
using JSON3
using OrionAuth
using OrionORM

# Don't call init!() - it's already called in main test file

@testset verbose=true "Framework-Agnostic Core" begin
    # Create test user
    test_user, jwt_data = signup("generic@test.com", "Generic Test User", "testpass123")
    test_token = JSON3.parse(jwt_data)["access_token"]

    @testset "GenericRequestContext" begin
        # Test with valid Authorization header
        ctx = GenericRequestContext(Dict("Authorization" => "Bearer $test_token"))

        @test ctx isa RequestContext

        # Test get_headers
        headers = get_headers(ctx)
        @test haskey(headers, "Authorization")
        @test headers["Authorization"] == "Bearer $test_token"

        # Test extract_bearer_token
        token = extract_bearer_token(ctx)
        @test token == test_token
    end

    @testset "Auth with GenericRequestContext" begin
        ctx = GenericRequestContext(Dict("Authorization" => "Bearer $test_token"))

        # Test basic authentication
        payload = Auth(ctx)
        @test payload["email"] == "generic@test.com"
        @test payload["sub"] == test_user.id
        @test haskey(payload, "permissions")
        @test haskey(payload, "roles")
    end

    @testset "getUserData with GenericRequestContext" begin
        ctx = GenericRequestContext(Dict("Authorization" => "Bearer $test_token"))

        user_data = getUserData(ctx)
        @test user_data["email"] == "generic@test.com"
        @test user_data["name"] == "Generic Test User"
        @test user_data["sub"] == test_user.id
    end

    @testset "ResponseException" begin
        # Test ResponseException creation
        ex = ResponseException(401, [], "Unauthorized")
        @test ex isa ResponseException
        @test ex.status == 401
        @test ex.body == "Unauthorized"
        @test ex.headers == []

        # Test with headers
        ex_with_headers =
            ResponseException(403, ["Content-Type" => "application/json"], "Forbidden")
        @test ex_with_headers.status == 403
        @test ex_with_headers.body == "Forbidden"
        @test length(ex_with_headers.headers) == 1
        @test ex_with_headers.headers[1] == ("Content-Type" => "application/json")
    end

    @testset "Error handling" begin
        # Test missing Authorization header
        ctx = GenericRequestContext(Dict{String,String}())

        @test_throws ResponseException extract_bearer_token(ctx)

        try
            extract_bearer_token(ctx)
        catch ex
            @test ex isa ResponseException
            @test ex.status == 401
            @test ex.body == "Authorization header is missing"
        end

        # Test invalid Authorization header format
        ctx = GenericRequestContext(Dict("Authorization" => "Token $test_token"))

        @test_throws ResponseException extract_bearer_token(ctx)

        try
            extract_bearer_token(ctx)
        catch ex
            @test ex isa ResponseException
            @test ex.status == 400
            @test ex.body == "Invalid Authorization header format"
        end

        # Test case-insensitive header lookup
        ctx = GenericRequestContext(Dict("authorization" => "Bearer $test_token"))
        token = extract_bearer_token(ctx)
        @test token == test_token

        ctx = GenericRequestContext(Dict("AUTHORIZATION" => "Bearer $test_token"))
        token = extract_bearer_token(ctx)
        @test token == test_token
    end

    @testset "Permission checking with GenericRequestContext" begin
        # Ensure permissions exist
        syncRolesAndPermissions(
            Dict("admin" => ["read", "write", "delete"], "user" => ["read"]),
        )

        # Assign admin role
        admin_role =
            findFirst(OrionAuth_Role; query = Dict("where" => Dict("role" => "admin")))
        assignRole(test_user.id, "admin")

        # Get fresh token with permissions
        _, fresh_jwt_data = signin("generic@test.com", "testpass123")
        fresh_token = JSON3.parse(fresh_jwt_data)["access_token"]

        ctx = GenericRequestContext(Dict("Authorization" => "Bearer $fresh_token"))

        # Test Auth with permission requirement
        payload = Auth(ctx, "read")
        @test payload["email"] == "generic@test.com"

        # Test Auth with multiple permissions
        payload = Auth(ctx, ["read", "write"])
        @test payload["email"] == "generic@test.com"

        # Test Auth with missing permission
        @test_throws ResponseException Auth(ctx, "nonexistent_permission")

        try
            Auth(ctx, "nonexistent_permission")
        catch ex
            @test ex isa ResponseException
            @test ex.status == 403
            @test occursin("Forbidden", ex.body)
        end
    end

    # Cleanup
    deleteMany(OrionAuth_UserRole, Dict("where" => Dict("userId" => test_user.id)))
    delete(test_user)
end

println("✓ Framework-agnostic core tests passed")
