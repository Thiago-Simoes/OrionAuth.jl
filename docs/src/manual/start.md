# Quickstart

## How to config ORM.jl
### Database connection
First you need configure database connection, just need to create a `.env` file in the root folder.  
  
**Containing:**
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=pass
DB_NAME=dbname
DB_PORT=3306
```

## How to perform queries
### How to create a Model
```
using ORM

@Model User (
    ("id", "INTEGER", [@PrimaryKey(), @AutoIncrement()]),
    ("name", "TEXT", [@NotNull()]),
    ("email", "TEXT", [@Unique(), @NotNull()]),
    ("cpf", "VARCHAR(11)", [@Unique(), @NotNull()]),
    ("age", "INTEGER", [])
)
```

#### Inserting data
The data should be formatted as a Dict.  
Only @NotNull fields must be provided.  
The return can be either an error or a Model Object (a User object in this example).
```
userData = Dict("name" => "Thiago", "email" => "thiago@example.com", "cpf" => "00000000000")
user = create(User, userData)
```

#### Search data
Now queries use a dictionary format:
```
foundUser = findFirst(User; query=Dict("where" => Dict("name" => "Thiago")))
```

#### Update data
```
updatedUser = update(User, Dict("where" => Dict("id" => user.id)), Dict("name" => "Thiago Updated"))
```

#### Upsert data
```
upsertUser = upsert(User, "email", "thiago@example.com",
                    Dict("name" => "Thiago Upserted", "email" => "thiago@example.com"))
```

#### Update by instance
```
foundUser.name = "Thiago Instance"
updatedInstance = update(foundUser)
```

#### Delete data
```
deleteResult = delete(foundUser)
```

#### Insert multiple records
```
records = [
    Dict("name" => "Bob", "email" => "bob@example.com", "cpf" => "11111111111"),
    Dict("name" => "Carol", "email" => "carol@example.com", "cpf" => "22222222222")
]
createdRecords = createMany(User, records)
```

#### Find multiple records
```
manyUsers = findMany(User)
```

#### Update many
```
updatedMany = updateMany(User, Dict("where" => Dict("name" => "Bob")), Dict("name" => "Bob Updated"))
```

#### Filter
```
_ = createMany(User, [
    Dict("name" => "Dan", "email" => "dan@example.com", "cpf" => "33333333333"),
    Dict("name" => "Eve", "email" => "eve@example.com", "cpf" => "44444444444")
])
filteredUsers = filter(User; name="Dan")
```

#### Delete multiple records
```
deleteManyResult = deleteMany(User, Dict("where" => "1=1"))
```

#### Update Many and Return
Updates multiple records and returns the updated records.
```julia
updatedManyAndReturn = updateManyAndReturn(User, Dict("where" => Dict("name" => "Carol")), Dict("name" => "Carol Updated"))
```

#### Pagination
Retrieve query results using limit, offset, and ordering.
```julia
# Retrieve first 2 users
page1 = findMany(User; query=Dict("limit" => 2, "offset" => 0, "orderBy" => "id"))
# Retrieve next 2 users starting from the third record
page2 = findMany(User; query=Dict("limit" => 2, "offset" => 2, "orderBy" => "id"))
# Retrieve remaining records
page3 = findMany(User; query=Dict("limit" => 2, "offset" => 4, "orderBy" => "id"))
```