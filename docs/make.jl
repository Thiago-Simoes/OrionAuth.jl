import Pkg
Pkg.activate(".")
using Documenter, NebulaAuth

push!(LOAD_PATH,"../src/")
makedocs(
    sitename="NebulaAuth.jl",
    modules=[NebulaAuth],
    pages = [
    "Home" => "index.md",
    "Manual" => ["manual/start.md", "manual/relationships.md", "manual/security.md"],
    "Security" => ["security/security_policy.md", "security/references.md", "security/threat_model.md", "security/vulnerability_report.md"],
    "Reference" => ["Reference/API.md"]
    ]
)
