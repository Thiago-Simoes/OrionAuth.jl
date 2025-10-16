# HTTP Adapter - Framework-agnostic HTTP abstraction layer

"""
    RequestContext

Abstract type representing an HTTP request context across different frameworks.
Implementations should provide access to request headers.
"""
abstract type RequestContext end

"""
    ResponseException

Exception type for HTTP responses with status code, headers, and body.
Can be thrown to return an HTTP error response in a framework-agnostic way.

# Fields
- `status::Int`: HTTP status code (e.g., 401, 403, 404)
- `headers::Vector{Pair{String,String}}`: HTTP response headers
- `body::String`: Response body content

# Examples
```julia
# Unauthorized response
throw(ResponseException(401, [], "Unauthorized"))

# Forbidden with custom header
throw(ResponseException(403, ["Content-Type" => "application/json"], "Forbidden"))
```
"""
struct ResponseException <: Exception
    status::Int
    headers::Vector{Pair{String,String}}
    body::String
end

ResponseException(status::Int, headers::Vector, body::String) = 
    ResponseException(status, Pair{String,String}[h[1] => h[2] for h in headers], body)

# Global configuration for framework detection
const _framework_config = Ref{Union{Symbol,Nothing}}(nothing)
const _auto_detect = Ref{Bool}(true)

"""
    configure_framework!(framework::Symbol)

Configure OrionAuth to use a specific framework adapter.

# Arguments
- `framework::Symbol`: Framework to use (`:genie`, `:oxygen`, `:http`, or `:auto`)

# Examples
```julia
# Set framework explicitly
configure_framework!(:genie)

# Enable auto-detection (default)
configure_framework!(:auto)
```
"""
function configure_framework!(framework::Symbol)
    if framework == :auto
        _auto_detect[] = true
        _framework_config[] = nothing
    elseif framework in [:genie, :oxygen, :http]
        _auto_detect[] = false
        _framework_config[] = framework
    else
        error("Unsupported framework: $framework. Use :genie, :oxygen, :http, or :auto")
    end
    nothing
end

"""
    get_configured_framework() -> Symbol

Get the currently configured framework.

# Returns
- Symbol representing the framework (`:genie`, `:oxygen`, `:http`, or `:auto`)
"""
function get_configured_framework()
    if _auto_detect[]
        return :auto
    else
        return something(_framework_config[], :auto)
    end
end

"""
    create_request_context(request=nothing) -> RequestContext

Automatically create the appropriate RequestContext based on configuration or auto-detection.

# Arguments
- `request`: Optional request object (auto-detected if not provided)

# Returns
- `RequestContext`: Appropriate context for the configured/detected framework

# Examples
```julia
# Auto-detect from environment
ctx = create_request_context()

# Explicit request object
ctx = create_request_context(req)
```
"""
function create_request_context(request=nothing)
    framework = _framework_config[]
    
    # Auto-detect framework if not configured
    if _auto_detect[] || isnothing(framework)
        # Check for Genie
        if isdefined(Main, :Genie) && isdefined(Main.Genie, :Requests)
            framework = :genie
        # Check if request is HTTP.Request (Oxygen or HTTP.jl)
        elseif !isnothing(request) && isa(request, HTTP.Request)
            # For now, default to HTTP.jl for HTTP.Request
            # User can explicitly set :oxygen if needed
            framework = :http
        else
            error("Could not auto-detect framework. Please use configure_framework!(:genie|:oxygen|:http)")
        end
    end
    
    # Create appropriate context
    if framework == :genie
        if !isdefined(@__MODULE__, :GenieRequestContext)
            error("Genie adapter not loaded. Load it with: Base.include(OrionAuth, joinpath(dirname(pathof(OrionAuth)), \"adapters/genie.jl\"))")
        end
        return isnothing(request) ? GenieRequestContext() : GenieRequestContext(request)
    elseif framework == :oxygen
        if isnothing(request)
            error("Oxygen requires explicit request object. Pass it to create_request_context(req)")
        end
        return OxygenRequestContext(request)
    elseif framework == :http
        if isnothing(request)
            error("HTTP.jl requires explicit request object. Pass it to create_request_context(req)")
        end
        return HTTPRequestContext(request)
    else
        error("Unknown framework: $framework")
    end
end

"""
    handle_auth_exception(ex::ResponseException) -> Any

Convert ResponseException to the appropriate framework-specific response.

# Arguments
- `ex::ResponseException`: The exception to convert

# Returns
- Framework-specific error response

# Examples
```julia
try
    Auth()
catch ex
    if ex isa ResponseException
        return handle_auth_exception(ex)
    end
    rethrow()
end
```
"""
function handle_auth_exception(ex::ResponseException)
    framework = get_configured_framework()
    
    # Auto-detect if needed
    if framework == :auto
        if isdefined(Main, :Genie)
            framework = :genie
        else
            framework = :http  # Default fallback
        end
    end
    
    if framework == :genie
        if isdefined(@__MODULE__, :to_genie_response)
            return to_genie_response(ex)
        else
            throw(ex)  # Fallback
        end
    elseif framework == :oxygen
        return to_oxygen_response(ex)
    elseif framework == :http
        return to_http_response(ex)
    else
        throw(ex)  # Fallback
    end
end

"""
    get_headers(ctx::RequestContext) -> Dict{String,String}

Extract headers from the request context.

# Arguments
- `ctx::RequestContext`: The request context

# Returns
- `Dict{String,String}`: Dictionary of HTTP headers

# Examples
```julia
headers = get_headers(ctx)
auth_header = get(headers, "authorization", nothing)
```
"""
function get_headers end

"""
    extract_bearer_token(ctx::RequestContext) -> String

Extract JWT token from the Authorization Bearer header.

# Arguments
- `ctx::RequestContext`: The request context with headers

# Returns
- `String`: The JWT token

# Throws
- `ResponseException(401, ...)`: If Authorization header is missing
- `ResponseException(400, ...)`: If Authorization header format is invalid

# Examples
```julia
token = extract_bearer_token(ctx)
# Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```
"""
function extract_bearer_token(ctx::RequestContext)
    headers = get_headers(ctx)
    
    # Find authorization header (case-insensitive)
    auth_key = nothing
    for k in keys(headers)
        if lowercase(k) == "authorization"
            auth_key = k
            break
        end
    end
    
    if isnothing(auth_key)
        throw(ResponseException(401, [], "Authorization header is missing"))
    end
    
    auth_header = headers[auth_key]
    
    # Split using space to extract Bearer token
    parts = split(auth_header, " ")
    if length(parts) != 2 || parts[1] != "Bearer"
        throw(ResponseException(400, [], "Invalid Authorization header format"))
    end
    
    return parts[2]
end

"""
    GenericRequestContext <: RequestContext

Generic implementation of RequestContext for testing and direct use.

# Fields
- `headers::Dict{String,String}`: HTTP request headers

# Examples
```julia
ctx = GenericRequestContext(Dict("Authorization" => "Bearer token123"))
token = extract_bearer_token(ctx)
```
"""
struct GenericRequestContext <: RequestContext
    headers::Dict{String,String}
end

get_headers(ctx::GenericRequestContext) = ctx.headers
