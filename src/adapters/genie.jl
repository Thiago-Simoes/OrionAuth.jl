# Genie Framework Adapter

"""
    GenieRequestContext <: RequestContext

Adapter for Genie framework requests.

# Examples
```julia
using Genie, Genie.Requests

# In a Genie route handler:
function protected_route()
    ctx = GenieRequestContext()
    payload = Auth(ctx)
    # ... handle request
end
```
"""
struct GenieRequestContext <: RequestContext
    request::Any
end

# Constructor that uses current Genie request
GenieRequestContext() = GenieRequestContext(Genie.Requests.request())

"""
    get_headers(ctx::GenieRequestContext) -> Dict{String,String}

Extract headers from Genie request context.

# Arguments
- `ctx::GenieRequestContext`: Genie request context

# Returns
- `Dict{String,String}`: Dictionary of HTTP headers
"""
get_headers(ctx::GenieRequestContext) = ctx.request.headers |> Dict

"""
    to_genie_response(ex::ResponseException)

Convert ResponseException to Genie ExceptionalResponse.

# Arguments
- `ex::ResponseException`: The response exception to convert

# Returns
- `Genie.Exceptions.ExceptionalResponse`: Genie-specific exception
"""
function to_genie_response(ex::ResponseException)
    return Genie.Exceptions.ExceptionalResponse(ex.status, ex.headers, ex.body)
end
