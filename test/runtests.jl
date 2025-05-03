# Implementa os testes unitários para o módulo `ORM.jl` e suas dependências.

using Test
using Dates

using DotEnv
DotEnv.load!()

using NebulaORM

using NebulaAuth
NebulaAuth.init!()

# Define um usuário de autenticação
user = signup("th.simoes@proton.me", "Thiago Simões", "123456")
userLogging = signin(user.email, "123456")
@test userLogging !== nothing
@test userLogging.id == user.id
@test userLogging.name == user.name
@test userLogging.email == user.email



# Relationship
Model(
    :Profile,
    [
        ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
        ("userId", INTEGER(), []),
        ("bio", TEXT(), []),
        ("location", TEXT(), []),
        ("website", TEXT(), []),
        ("created_at", TEXT(), []),
        ("updated_at", TEXT(), [])
    ],
    [
        ("userId", NebulaAuth_User, "id", :belongsTo)
    ]
)

profile = create(Profile, Dict(
    "userId" => user.id,
    "bio" => "Software Engineer",
    "location" => "Brazil",
    "website" => "https://example.com",
    "created_at" => string(Dates.now()),
    "updated_at" => string(Dates.now())
))

@test profile.userId == user.id
@test profile.bio == "Software Engineer"

# # Testar busca
profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId)))
@test profile_user !== nothing
@test profile_user.id == user.id

# # Buscar o perfil do usuário
profile_user = findFirst(Profile; query=Dict("where" => Dict("userId" => user.id)))
@test profile_user !== nothing
@test profile_user.id == profile.id
@test profile_user.userId == user.id

# # Buscar pela relação
profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId), "include" => [Profile]))
@test profile_user !== nothing
@test profile_user["NebulaAuth_User"].id == user.id
@test profile_user["Profile"][1].id == profile.id


# Reset o banco de dados
conn = dbConnection()
dropTable!(conn, "NebulaAuth_User")
dropTable!(conn, "NebulaAuth_Log")
dropTable!(conn, "Profile")
