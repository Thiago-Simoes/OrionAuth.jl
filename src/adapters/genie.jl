# Genie Framework Adapter
# This file should only be included when Genie is available

# Use Main.Genie since Genie is typically loaded in the user's namespace, not OrionAuth's
const _genie_module = Ref{Union{Module,Nothing}}(nothing)

function _get_genie()
    if _genie_module[] === nothing
        # Try to find Genie in Main
        if isdefined(Main, :Genie)
            _genie_module[] = Main.Genie
        else
            error("Genie must be loaded in Main before using GenieRequestContext")
        end
    end
    return _genie_module[]
end

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
GenieRequestContext() = GenieRequestContext(_get_genie().Requests.request())

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
    return _get_genie().Exceptions.ExceptionalResponse(ex.status, ex.headers, ex.body)
end
