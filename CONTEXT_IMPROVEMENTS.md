# OrionAuth - Context Integration Improvements

## Summary of Improvements

This document demonstrates the improvements made to eliminate repetition and manual error handling.

## 1. Configuration System

### Via Environment Variable (.env file)
```env
ORIONAUTH_FRAMEWORK=genie  # Options: genie, oxygen, http, auto
```

### Via Code
```julia
using OrionAuth
configure_framework!(:genie)  # Set once at application startup
```

### Auto-Detection (Default)
If not configured, OrionAuth automatically detects your framework.

## 2. Simplified API Examples

### Genie.jl

**Before (Repetitive):**
```julia
route("/api/users") do
    ctx = GenieRequestContext()
    try
        payload = Auth(ctx, "admin")
        # ... handle request
    catch ex
        if ex isa ResponseException
            throw(to_genie_response(ex))
        end
        rethrow()
    end
end

route("/api/posts") do
    ctx = GenieRequestContext()  # Repeated!
    try
        payload = Auth(ctx, "write")
        # ... handle request
    catch ex
        if ex isa ResponseException
            throw(to_genie_response(ex))
        end
        rethrow()
    end
end
```

**After (DRY!):**
```julia
# Configure once (or use auto-detection)
configure_framework!(:genie)

route("/api/users") do
    payload = Auth("admin")  # That's it!
    # ... handle request
end

route("/api/posts") do
    payload = Auth("write")  # No repetition!
    # ... handle request
end
```

### HTTP.jl

**Before:**
```julia
HTTP.serve() do req
    if req.target == "/protected"
        ctx = HTTPRequestContext(req)
        try
            payload = Auth(ctx, "admin")
            return HTTP.Response(200, "OK")
        catch ex
            if ex isa ResponseException
                return to_http_response(ex)
            end
            rethrow()
        end
    end
end
```

**After:**
```julia
configure_framework!(:http)  # Once at startup

HTTP.serve() do req
    if req.target == "/protected"
        payload = Auth("admin", request=req)  # Auto-converts errors!
        return HTTP.Response(200, "OK")
    end
end
```

### Oxygen.jl

**Before:**
```julia
@get "/users" function(req)
    ctx = OxygenRequestContext(req)
    try
        payload = Auth(ctx, ["read", "write"])
        return json(get_users())
    catch ex
        if ex isa ResponseException
            return to_oxygen_response(ex)
        end
        rethrow()
    end
end
```

**After:**
```julia
configure_framework!(:oxygen)  # Once at startup

@get "/users" function(req)
    payload = Auth(["read", "write"], request=req)  # Auto-converts!
    return json(get_users())
end
```

## 3. Automatic Error Handling

Errors are automatically converted to the framework's expected format:

- **Genie**: `ResponseException` → `Genie.Exceptions.ExceptionalResponse`
- **HTTP.jl**: `ResponseException` → `HTTP.Response`
- **Oxygen**: `ResponseException` → `HTTP.Response`

No manual try/catch or error conversion needed!

## 4. Backward Compatibility

The explicit context API still works for advanced use cases:

```julia
# Explicit context (still supported)
ctx = GenieRequestContext()
payload = Auth(ctx, "admin")

# Simplified (recommended)
payload = Auth("admin")
```

## 5. Configuration Functions

```julia
# Set framework
configure_framework!(:genie)    # :oxygen, :http, or :auto
configure_framework!(:auto)     # Enable auto-detection

# Get current configuration
framework = get_configured_framework()  # Returns :genie, :oxygen, :http, or :auto

# Create context manually (advanced)
ctx = create_request_context()      # Auto-detects
ctx = create_request_context(req)   # Explicit request

# Handle errors manually (advanced)
try
    Auth()
catch ex
    if ex isa ResponseException
        return handle_auth_exception(ex)  # Auto-converts
    end
end
```

## Benefits

1. **DRY (Don't Repeat Yourself)**: No context creation in every route
2. **KISS (Keep It Simple)**: Simple API, no manual error handling
3. **SRP (Single Responsibility)**: Configuration separate from usage
4. **Extensible**: Easy to add new framework adapters
5. **Backward Compatible**: Existing code continues to work

## Migration

**No changes required!** Existing code works as-is. You can:
- Use it as-is (auto-detection works)
- Optionally add configuration for explicit framework selection
- Optionally use the simplified API in new routes

The improvements make the code cleaner without breaking existing functionality.
