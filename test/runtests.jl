# Implementa os testes unitários para o módulo `ORM.jl` e suas dependências.

using Test
using Dates
using NebulaORM
using NebulaAuth


# Define um usuário de autenticação
user = signup("th.simoes@proton.me", "Thiago Simões", "123456")
@test userLogging = NebulaAuth.signin(user.email, "123456")
@test userLogging.email == user.email

# Relationship
# Model(
#     :Profile,
#     [
#         ("id", @INTEGER, [@PrimaryKey(), @AutoIncrement()]),
#         ("userId", @INTEGER, []),
#         ("bio", @TEXT, []),
#         ("location", @TEXT, []),
#         ("website", @TEXT, []),
#         ("created_at", @TEXT, []),
#         ("updated_at", @TEXT, [])
#     ],
#     [
#         ("userId", NebulaAuth_User, "id", :belongTo)
#     ]
# )

# @test profile = create(Profile, Dict(
#     "userId" => user.id,
#     "bio" => "Software Engineer",
#     "location" => "Brazil",
#     "website" => "https://example.com",
#     "created_at" => string(Dates.now()),
#     "updated_at" => string(Dates.now())
# ))

# @test profile.userId == user.id
# @test profile.bio == "Software Engineer"

# # Testar busca
# @test profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId)))

# # Buscar o perfil do usuário
# @test profile_user = findFirst(Profile; query=Dict("where" => Dict("userId" => user.id)))

# # Buscar pela relação
# @test profile_user = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId), "include" => [Profile]))