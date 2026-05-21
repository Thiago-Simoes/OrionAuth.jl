module OrionAuthBenchUtils

using JSON3, Dates, Random, Sockets, Statistics, StatsBase

function getFreePort()::Int
    sock = listen(IPv4("127.0.0.1"), 0)
    port = getsockname(sock).port
    close(sock); port
end

function writeJsonResult(dir::AbstractString, name::AbstractString, data)
    isdir(dir) || mkpath(dir)
    ts = Dates.format(now(), dateformat"yyyy-mm-dd_HHMMSS")
    path = joinpath(dir, "$(name)_$(ts).json")
    open(path, "w") do io
        JSON3.write(io, data; allow_inf=true, allow_nan=true, indent=2)
    end
    return path
end

function summarizeLatencies(samples::Vector{Float64})
    q = quantile(samples, [0.5, 0.95, 0.99])
    return Dict(
        :count => length(samples),
        :mean  => mean(samples),
        :std   => std(samples),
        :p50   => q[1],
        :p95   => q[2],
        :p99   => q[3],
        :min   => minimum(samples),
        :max   => maximum(samples)
    )
end

function weirdBearer(token::AbstractString)
    b = String([rand(Bool) ? uppercase(c) : lowercase(c) for c in "Bearer"])
    pad = " " ^ rand(1:4)
    return "$b$(pad)$token"
end

end # module
