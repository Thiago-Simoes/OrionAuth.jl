module BenchPasswordArgon2
using BenchmarkTools, OrionAuth, Statistics, JSON3
using .Main.OrionAuthBenchUtils: writeJsonResult

function run(; outdir::String="bench/results", passes::Vector{String}=["a"^i for i in 8:12])
    OrionAuth.init!()

    configs = Dict(
        "low" => "5",
        "medium" => "15000",
        "high" => "30000"
    )

    results = Dict{String,Any}()

    for (label, iters) in configs
        old = get(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS", nothing)
        ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"] = iters
        try
            hashTimes = Float64[]; verifyTimes = Float64[]
            for p in passes
                h = @belapsed OrionAuth.hash_password($p)
                v = @belapsed OrionAuth.verify_password($(OrionAuth.hash_password(p)), $p)
                push!(hashTimes, h); push!(verifyTimes, v)
            end
            results[label] = Dict(
                :iters => iters,
                :hash_s => Dict(:mean=>mean(hashTimes), :p95=>quantile(hashTimes,0.95)),
                :verify_s => Dict(:mean=>mean(verifyTimes), :p95=>quantile(verifyTimes,0.95))
            )
        finally
            old === nothing ? delete!(ENV, "OrionAuth_MIN_PASSWORD_ITTERATIONS") : (ENV["OrionAuth_MIN_PASSWORD_ITTERATIONS"]=old)
        end
    end

    return writeJsonResult(outdir, "password_argon2", Dict(:meta=>Dict(:suite=>"argon2_sweep"), :results=>results))
end

end # module
