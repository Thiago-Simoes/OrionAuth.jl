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
