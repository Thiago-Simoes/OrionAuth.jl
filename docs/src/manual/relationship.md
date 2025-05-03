# Relationship

## Introduction

**Nebula.jl** is an ORM for Julia that simplifies defining models and managing relationships between them. With Nebula.jl, you can define relationships such as:

- **hasMany**: A record in one model has many related records in another model.
- **belongsTo**: A record in one model belongs to a record in another model.
- **hasOne**: A record in one model has a single related record in another model.

In addition, Nebula.jl allows you to enrich query results using the `"include"` key in a query dictionary. This way, you can return related data as part of a `Dict` (for single record queries) or a vector of `Dicts` (for multiple records).

## Creating Models with Relationships

To define models along with their relationships, use the `@Model` macro. For example:

```julia
@Model User (
    ("id", "INTEGER", [@PrimaryKey(), @AutoIncrement()]),
    ("name", "TEXT", [@NotNull()]),
    ("email", "TEXT", [@Unique(), @NotNull()])
) [
    ("posts", Post, "authorId", :hasMany)
]

@Model Post (
    ("id", "INTEGER", [@PrimaryKey(), @AutoIncrement()]),
    ("title", "TEXT", [@NotNull()]),
    ("authorId", "INTEGER", [@NotNull()])
) [
    ("authorId", User, "id", :belongsTo)
]
```

In this example:

- A **User** has many **Post** records through a **hasMany** relationship (the `authorId` field in `Post` references the `id` field in `User`).
- A **Post** belongs to a **User** via a **belongsTo** relationship (the `authorId` field in `Post` references the `id` field in `User`).

## Querying with the "include" Parameter

When using the `"include"` parameter in your queries, Nebula.jl enriches the result with related records. Depending on the relationship type, the return format will be:

- **hasMany/hasOne**: The result will include, under the key of the related model, either a vector of `Dicts` (for hasMany) or a single `Dict` (for hasOne).
- **belongsTo**: The result will include a single `Dict` with the parent record's data.

### Example 1: Query with belongsTo

```julia
result = findFirst(Post; query=Dict("where" => Dict("id" => 1), "include" => ["User"]))
```

Assuming the post with `id = 1` belongs to a user, the result will be a `Dict` similar to:

```julia
Dict(
    "id" => 1,
    "title" => "Example Post",
    "authorId" => 10,
    "User" => Dict("id" => 10, "name" => "Thalles", "email" => "thalles@example.com")
)
```

### Example 2: Query with hasMany

```julia
results = findMany(User; query=Dict("where" => Dict("name" => "Thiago"), "include" => ["Post"]))
```

Each item in `results` will be a `Dict` structured as follows:

```julia
Dict(
    "id" => 10,
    "name" => "Thiago",
    "email" => "thiago@example.com",
    "Post" => [
         Dict("id" => 1, "title" => "First Post", "authorId" => 10),
         Dict("id" => 2, "title" => "Second Post", "authorId" => 10)
    ]
)
```

## Internal Workflow

When a query is executed with the `"include"` parameter, the workflow is as follows:

1. **Main Query:**  
   The `findFirst` or `findMany` function builds an SQL query to fetch records from the base model (e.g., `User` or `Post`).

2. **Serialization:**  
   Each returned record is converted into a simple `Dict` (using a helper function like `serialize` or `convertRowToDict`).

3. **Enrichment:**  
   The ORM goes through the list of models specified in `"include"`. For each included model, it:
   - Finds the registered relationship (using `getRelationships` and `resolveModel`).
   - Executes a separate query (via `hasMany`, `hasOne`, or `belongsTo`) to fetch related records.
   - Adds the related data to the main record’s `Dict` under a key corresponding to the related model.

## Example Tests

Below is an excerpt of unit tests that demonstrate the use of relationships and the `"include"` parameter:

```julia
@testset "SimpleORM Basic CRUD Tests" begin
    # Create a user
    userData = Dict("name" => "Thiago", "email" => "thiago@example.com", "cpf" => "00000000000")
    user = create(User, userData)
    @test user.name == "Thiago"
    @test user.email == "thiago@example.com"
    @test hasproperty(user, :id)

    # Create a post related to the user
    postData = Dict("title" => "My First Post", "authorId" => user.id)
    post = create(Post, postData)
    @test post.title == "My First Post"
    @test post.authorId == user.id

    # Query with "include" to fetch the user and their posts
    result = findFirst(User; query=Dict("where" => Dict("name" => "Thiago"), "include" => ["Post"]))
    @test result["id"] == user.id
    @test typeof(result["Post"]) == Vector
    @test result["Post"][1]["title"] == "My First Post"

    # Query with belongsTo: fetch the post and include the user
    result2 = findFirst(Post; query=Dict("where" => Dict("id" => post.id), "include" => ["User"]))
    @test result2["id"] == post.id
    @test typeof(result2["User"]) == Dict
    @test result2["User"]["id"] == user.id
end
```

## Conclusion

With **Nebula.jl**, you can easily define models with relationships and perform enriched queries using the `"include"` parameter. This modular approach allows you to build complex queries without manually writing SQL, returning structured results as `Dicts` that simplify data consumption in your application.

Feel free to contribute suggestions or ask questions if you need further details!
