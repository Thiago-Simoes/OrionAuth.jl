module BenchHttpRoute
using JSON3, HTTP, OrionAuth, OrionORM, Sockets, Random, Statistics
using .Main.OrionAuthBenchUtils: writeJsonResult, getFreePort, summarizeLatencies, weirdBearer

function run(; outdir::String="bench/results", requests::Int=200)
    OrionAuth.init!()

    user, jwt = OrionAuth.signup("bench.http@ex.com","Bench HTTP","pass123")
    token = JSON3.parse(jwt)["access_token"]

    function handler(req::HTTP.Request)
        try
            ctx = OrionAuth.HTTPRequestContext(req)
            _ = OrionAuth.Auth(ctx)
            return HTTP.Response(200, "ok")
        catch ex
            if ex isa OrionAuth.ResponseException
                return HTTP.Response(ex.status, ex.body)
            else
                rethrow()
            end
        end
    end

    port = getFreePort()
    serverTask = @async HTTP.serve(handler, ip"127.0.0.1", port; verbose=false)
    sleep(0.15)

    HTTP.request("GET", "http://127.0.0.1:%d/ping" % port; headers=["Authorization" => "Bearer %s" % token])

    lat = Float64[]
    alloc = Int[]
    for i in 1:requests
        hdr = i % 5 == 0 ? ["Authorization" => weirdBearer(token)] : ["Authorization" => "Bearer %s" % token]
        t = @elapsed begin
            resp = HTTP.request("GET", "http://127.0.0.1:%d/secure" % port; headers=hdr)
            @assert resp.status == 200
        end
        push!(lat, t)
        push!(alloc, @allocated HTTP.request("GET", "http://127.0.0.1:%d/secure" % port; headers=hdr))
    end

    schedule(serverTask, InterruptException(); error=true)

    data = Dict(
        :meta => Dict(:suite=>"http_route", :requests=>requests, :port=>port),
        :latency => Dict(:summary => summarizeLatencies(lat)),
        :allocations => Dict(:mean => mean(alloc), :min => minimum(alloc), :max => maximum(alloc))
    )
    return writeJsonResult(outdir, "http_route", data)
end

end # module
