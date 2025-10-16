# Oxygen Framework Adapter

"""
    OxygenRequestContext <: RequestContext

Adapter for Oxygen framework requests.

# Examples
```julia
using Oxygen

# In an Oxygen route handler:
@get "/protected" function(req)
    ctx = OxygenRequestContext(req)
    payload = Auth(ctx)
    # ... handle request
end
```
"""
struct OxygenRequestContext <: RequestContext
    request::HTTP.Request
end

"""
    get_headers(ctx::OxygenRequestContext) -> Dict{String,String}

Extract headers from Oxygen request context.

# Arguments
- `ctx::OxygenRequestContext`: Oxygen request context

# Returns
- `Dict{String,String}`: Dictionary of HTTP headers
"""
function get_headers(ctx::OxygenRequestContext)
    headers = Dict{String,String}()
    for (k, v) in ctx.request.headers
        headers[k] = v
    end
    return headers
end

"""
    to_oxygen_response(ex::ResponseException) -> HTTP.Response

Convert ResponseException to HTTP.Response for Oxygen.

# Arguments
- `ex::ResponseException`: The response exception to convert

# Returns
- `HTTP.Response`: HTTP response with status, headers, and body
"""
function to_oxygen_response(ex::ResponseException)
    return HTTP.Response(ex.status, ex.headers, ex.body)
end
