###############
# test_oxygen.jl — Oxygen integration tests (Auth() only)
# Author: Mike
# Style: camelCase, Clean Code, SRP/DRY, modular
# Docs: English
###############

using Test
using JSON3
using HTTP

# Try to load Oxygen; skip tests if it's not available in this environment
const HAS_OXYGEN = try
    @eval import Oxygen
    true
catch
    @warn "Oxygen not available — skipping Oxygen tests"
    false
end

if HAS_OXYGEN
    using OrionAuth

    OrionAuth.configure_framework!(:oxygen)

    # Ensure Oxygen adapter is available from OrionAuth
    # (OrionAuth should provide `OxygenRequestContext` and `to_oxygen_response(ex)`).

    #-------------------------------------------------------------------------------
    # Route setup — real server using Oxygen
    #-------------------------------------------------------------------------------
    function setupOxygenRoutes()
        # GET /protected — must have a valid Bearer token
        Oxygen.@get "/protected" function (req::HTTP.Request)
            try
                ctx = OxygenRequestContext(req)
                Auth(ctx)  # Auth() only; throws if unauthorized
                return HTTP.Response(
                    200,
                    ["Content-Type" => "text/plain"],
                    "protected content",
                )
            catch ex
                return to_oxygen_response(ex)
            end
        end

        # GET /user — returns user payload from token
        Oxygen.@get "/user" function (req::HTTP.Request)
            try
                ctx = OxygenRequestContext(req)
                data = getUserData(ctx)  # throws if unauthorized
                return HTTP.Response(
                    200,
                    ["Content-Type" => "application/json"],
                    JSON3.write(data),
                )
            catch ex
                return to_oxygen_response(ex)
            end
        end

        # DELETE /delete-resource — requires "delete" permission
        Oxygen.@delete "/delete-resource" function (req::HTTP.Request)
            try
                ctx = OxygenRequestContext(req)
                payload = getUserData(ctx)  # validates token and returns payload
                if !checkPermission(payload["sub"], "delete")
                    # Uniform error surface via OrionAuth's ResponseException
                    throw(ResponseException(403, [], "Forbidden"))
                end
                return HTTP.Response(200, ["Content-Type" => "text/plain"], "deleted")
            catch ex
                return to_oxygen_response(ex)
            end
        end
    end

    #-------------------------------------------------------------------------------
    # Boot Oxygen (ephemeral test server)
    #-------------------------------------------------------------------------------
    const TEST_HOST = "127.0.0.1"
    const TEST_PORT = 8050  # avoid collisions with Genie (8000) and anything else

    setupOxygenRoutes()
    @async Oxygen.serve(host = TEST_HOST, port = TEST_PORT)
    sleep(0.2)  # Give the server a brief moment to start

    #-------------------------------------------------------------------------------
    # Test suite — mirrors your Genie-based route tests
    #-------------------------------------------------------------------------------
    @testset verbose=true "Oxygen Framework Integration (Auth only)" begin
        # Prepare a fresh user and token
        user, signupData =
            signup("oxygen.route@thiago.com", "Oxygen Route Tester", "testPwd")
        initialToken = JSON3.parse(signupData)["access_token"]

        base = "http://$(TEST_HOST):$(TEST_PORT)"

        # 1) /protected without Authorization → 401
        @test_throws HTTP.Exceptions.StatusError HTTP.request("GET", base * "/protected")

        # 2) /protected with bad header format → 400 or 401 (implementation may use 400 for malformed header)
        @test_throws HTTP.Exceptions.StatusError HTTP.request(
            "GET",
            base * "/protected";
            headers = ["Authorization" => "Token $initialToken"],
        )

        # 3) /protected with valid Bearer token → 200 + body
        resp = HTTP.request(
            "GET",
            base * "/protected";
            headers = ["Authorization" => "Bearer $initialToken"],
        )
        @test resp.status == 200
        @test String(resp.body) == "protected content"

        # 4) /user without Authorization → 401
        @test_throws HTTP.Exceptions.StatusError HTTP.request("GET", base * "/user")

        # 5) /user with valid token → 200 + payload
        resp = HTTP.request(
            "GET",
            base * "/user";
            headers = ["Authorization" => "Bearer $initialToken"],
        )
        @test resp.status == 200
        payload = JSON3.read(String(resp.body))
        @test payload["email"] == user.email
        @test payload["name"] == user.name
        @test payload["sub"] == user.id

        # 6) DELETE /delete-resource without 'delete' permission → 403
        @test_throws HTTP.Exceptions.StatusError HTTP.request(
            "DELETE",
            base * "/delete-resource";
            headers = ["Authorization" => "Bearer $initialToken"],
        )

        # 7) Grant admin role (inherits "delete"), then signin to refresh token with new claims, but first create role
        roles = Dict("admin" => ["delete", "create", "update", "read"], "user" => ["read"])
        syncRolesAndPermissions(roles)
        assignRole(user.id, "admin")
        _, signinData = signin("oxygen.route@thiago.com", "testPwd")
        updatedToken = JSON3.parse(signinData)["access_token"]

        # 8) DELETE /delete-resource with delete permission → 200 + body
        resp = HTTP.request(
            "DELETE",
            base * "/delete-resource";
            headers = ["Authorization" => "Bearer $updatedToken"],
        )
        @test resp.status == 200
        @test String(resp.body) == "deleted"
    end

    # Optionally: you can try to stop Oxygen here if your stack provides a stopper.
    # As of now, many CI pipelines rely on test process teardown.
end # if HAS_OXYGEN
