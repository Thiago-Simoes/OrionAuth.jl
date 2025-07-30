function Unauthorized()
    return HTTP.Response(401, "Unauthorized")
end

function Forbidden()
    return HTTP.Response(403, "Forbidden")
end

function NotFound()
    return HTTP.Response(404, "Not Found")
end