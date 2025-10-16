"""
    Unauthorized() -> HTTP.Response

Create an HTTP 401 Unauthorized response.

# Returns
- `HTTP.Response`: Response with status 401

# Examples
```julia
return Unauthorized()
```
"""
function Unauthorized()
    return HTTP.Response(401, "Unauthorized")
end

"""
    Forbidden() -> HTTP.Response

Create an HTTP 403 Forbidden response.

# Returns
- `HTTP.Response`: Response with status 403

# Examples
```julia
return Forbidden()
```
"""
function Forbidden()
    return HTTP.Response(403, "Forbidden")
end

"""
    NotFound() -> HTTP.Response

Create an HTTP 404 Not Found response.

# Returns
- `HTTP.Response`: Response with status 404

# Examples
```julia
return NotFound()
```
"""
function NotFound()
    return HTTP.Response(404, "Not Found")
end