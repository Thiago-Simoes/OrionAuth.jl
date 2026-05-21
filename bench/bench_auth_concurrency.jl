module BenchAuthConcurrency
using JSON3, HTTP, OrionAuth, Statistics
using .Main.OrionAuthBenchUtils: writeJsonResult

function run(; outdir::String="bench/results", threads::Int=Threads.nthreads(), seconds::Float64=3.0)
    OrionAuth.init!()
    user, jwt = OrionAuth.signup("bench.conc@ex.com","Bench Concurrency","pass123")
    token = JSON3.parse(jwt)["access_token"]
    ctx = OrionAuth.HTTPRequestContext(HTTP.Request("GET","/conc", ["Authorization"=>"Bearer $token"]))

    for _ in 1:20; OrionAuth.Auth(ctx); end

    stopAt = time() + seconds
    counts = fill(0, threads)
    Threads.@threads for tid in 1:threads
        c = 0
        while time() < stopAt
            OrionAuth.Auth(ctx)
            c += 1
        end
        counts[tid] = c
    end

    total = sum(counts)
    data = Dict(
        :meta => Dict(:suite=>"concurrency", :threads=>threads, :duration_s=>seconds),
        :throughput => Dict(:ops => total, :ops_per_sec => total / seconds, :per_thread => counts)
    )
    return writeJsonResult(outdir, "auth_concurrency", data)
end

end # module
