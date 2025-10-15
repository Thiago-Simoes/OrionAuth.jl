# HTTP.jl Adapter

"""
    HTTPRequestContext <: RequestContext

Adapter for HTTP.jl requests.

# Examples
```julia
using HTTP

# In an HTTP.jl handler:
HTTP.serve() do req
    ctx = HTTPRequestContext(req)
    try
        payload = Auth(ctx)
        return HTTP.Response(200, "Success")
    catch ex
        if ex isa ResponseException
            return to_http_response(ex)
        end
        rethrow()
    end
end
```
"""
struct HTTPRequestContext <: RequestContext
    request::HTTP.Request
end

"""
    get_headers(ctx::HTTPRequestContext) -> Dict{String,String}

Extract headers from HTTP.Request.

# Arguments
- `ctx::HTTPRequestContext`: HTTP request context

# Returns
- `Dict{String,String}`: Dictionary of HTTP headers
"""
function get_headers(ctx::HTTPRequestContext)
    headers = Dict{String,String}()
    for (k, v) in ctx.request.headers
        headers[k] = v
    end
    return headers
end

"""
    to_http_response(ex::ResponseException) -> HTTP.Response

Convert ResponseException to HTTP.Response.

# Arguments
- `ex::ResponseException`: The response exception to convert

# Returns
- `HTTP.Response`: HTTP response with status, headers, and body
"""
function to_http_response(ex::ResponseException)
    return HTTP.Response(ex.status, ex.headers, ex.body)
end
