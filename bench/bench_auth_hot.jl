module BenchAuthHot
using BenchmarkTools, JSON3, HTTP, OrionAuth, OrionORM, Random, Statistics
using .Main.OrionAuthBenchUtils: writeJsonResult

function run(; outdir::String="bench/results", samples::Int=50)
    OrionAuth.init!()
    user, jwt = OrionAuth.signup("bench.hot@ex.com","Bench Hot","pass123")
    token = JSON3.parse(jwt)["access_token"]
    ctx = OrionAuth.HTTPRequestContext(HTTP.Request("GET","/hot", ["Authorization"=>"Bearer $token"]))

    for _ in 1:10; OrionAuth.Auth(ctx); end

    lat = Float64[]
    allocs = Int[]
    for _ in 1:samples
        push!(allocs, @allocated OrionAuth.Auth(ctx))
        push!(lat, @belapsed OrionAuth.Auth($ctx))
    end

    pass = "correct horse battery staple"
    hash = OrionAuth.hash_password(pass)
    verifyTime = @belapsed OrionAuth.verify_password($hash, $pass)
    verifyAlloc = @allocated OrionAuth.verify_password(hash, pass)

    data = Dict(
        :meta => Dict(:suite => "hot_path", :samples => samples),
        :auth => Dict(
            :allocations => Dict(:mean => mean(allocs), :min => minimum(allocs), :max => maximum(allocs)),
            :latency => Dict(:samples => length(lat), :mean => mean(lat), :p50 => quantile(lat,0.5), :p95 => quantile(lat,0.95), :p99 => quantile(lat,0.99))
        ),
        :password_verify => Dict(:time_s => verifyTime, :alloc => verifyAlloc)
    )
    return writeJsonResult(outdir, "auth_hot", data)
end

end # module
