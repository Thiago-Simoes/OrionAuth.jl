#!/usr/bin/env julia
using Dates
if !isdir("bench"); cd(@__DIR__); cd(".."); end

import Pkg
Pkg.activate("bench")

include(joinpath("bench","utils.jl"))
using .OrionAuthBenchUtils

using OrionAuth
OrionAuth.init!()

include(joinpath("bench","bench_auth_hot.jl"))
include(joinpath("bench","bench_auth_cold.jl"))
include(joinpath("bench","bench_auth_concurrency.jl"))
include(joinpath("bench","bench_http_route.jl"))
include(joinpath("bench","bench_password_argon2.jl"))

println("→ Running OrionAuth benchmark suite…")
paths = String[]

push!(paths, BenchAuthHot.run())
push!(paths, BenchAuthCold.run())
push!(paths, BenchAuthConcurrency.run())
push!(paths, BenchHttpRoute.run())
push!(paths, BenchPasswordArgon2.run())

idxPath = OrionAuthBenchUtils.writeJsonResult("bench/results", "index",
    Dict(:generated => Dates.format(Dates.now(), dateformat"yyyy-mm-ddTHH:MM:SS"),
         :artifacts => paths))

readme = joinpath("bench","results","README.md")
isdir(dirname(readme)) || mkpath(dirname(readme))
open(readme, "w") do io
    println(io, "# OrionAuth Benchmarks — Results")
    println(io, "")
    println(io, "- Index: `$(idxPath)`")
    for p in paths
        println(io, "- $(basename(p))")
    end
    println(io, "")
    println(io, "Interpretation tips:")
    println(io, "- **auth_hot**: allocations + p50/p95/p99 of Auth(ctx)")
    println(io, "- **auth_cold**: first-call latency (cold start)")
    println(io, "- **auth_concurrency**: ops/sec across threads")
    println(io, "- **http_route**: end-to-end latency via HTTP.jl handler")
    println(io, "- **password_argon2**: Argon2 sweep (mean & p95)")
end
println("✓ Done. See bench/results/")
