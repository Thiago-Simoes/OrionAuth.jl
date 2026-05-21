module BenchAuthCold
using Dates, JSON3
using .Main.OrionAuthBenchUtils: writeJsonResult

function run(; outdir::String="bench/results")
    code = raw"""
    using BenchmarkTools, JSON3, HTTP, OrionAuth
    OrionAuth.init!()
    user, jwt = OrionAuth.signup("bench.cold@ex.com","Bench Cold","pass123")
    token = JSON3.parse(jwt)["access_token"]
    ctx = OrionAuth.HTTPRequestContext(HTTP.Request("GET","/cold", ["Authorization"=>"Bearer $token"]))
    t = @elapsed OrionAuth.Auth(ctx)
    println(JSON3.write(Dict("cold_auth_first_call_s" => t)))
    """
    cmd = Base.julia_cmd()
    out = read(pipeline(`$cmd`, stdin=IOBuffer(code)), String)
    data = JSON3.read(out)
    return writeJsonResult(outdir, "auth_cold", Dict(:meta=>Dict(:suite=>"cold_start"), :metrics=>data))
end

end # module
