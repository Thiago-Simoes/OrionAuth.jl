# Defining Relationships

NebulaAuth leverages NebulaORM to create relationships between models. This manual explains how to create related models and query them.

## Creating Related Models
You can define relationships by specifying association attributes when creating a model. For example, defining a `Profile` linked to a user:

```julia
Model(
    :Profile,
    [
        ("id", INTEGER(), [PrimaryKey(), AutoIncrement()]),
        ("userId", INTEGER(), []),
        ("bio", TEXT(), []),
        ("location", TEXT(), []),
        ("website", TEXT(), []),
        ("created_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")]),
        ("updated_at", TIMESTAMP(), [Default("CURRENT_TIMESTAMP()")])
    ],
    [
        ("userId", NebulaAuth_User, "id", :belongsTo)
    ]
)
```

## Creating and Querying Relationships
After creating the models, you can create a profile for a user:
```julia
profile = create(Profile, Dict(
    "userId" => user.id,
    "bio" => "Software Engineer",
    "location" => "Brazil",
    "website" => "https://example.com"
))
```

### Query Examples
- Fetch the profile by user id:
  ```julia
  profile_user = findFirst(Profile; query=Dict("where" => Dict("userId" => user.id)))
  ```
- Include the related model when querying a user:
  ```julia
  profile_user_with_relation = findFirst(NebulaAuth_User; query=Dict("where" => Dict("id" => profile.userId), "include" => [Profile]))
  ```
This will return a user record with an embedded list of related profiles.
