# Backend API Design

Comprehensive guide to designing RESTful, GraphQL, and gRPC APIs with C#/.NET Core, ASP.NET, and Optimizely best practices (2025).

## REST API Design

### Resource-Based URLs

**Good:**
```
GET    /api/v1/users              # List users
GET    /api/v1/users/:id          # Get specific user
POST   /api/v1/users              # Create user
PUT    /api/v1/users/:id          # Update user (full)
PATCH  /api/v1/users/:id          # Update user (partial)
DELETE /api/v1/users/:id          # Delete user

GET    /api/v1/users/:id/posts    # Get user's posts
POST   /api/v1/users/:id/posts    # Create post for user
```

**Bad (Avoid):**
```
GET /api/v1/getUser?id=123        # RPC-style, not RESTful
POST /api/v1/createUser           # Verb in URL
GET /api/v1/user-posts            # Unclear relationship
```

### HTTP Status Codes (Meaningful Responses)

**Success:**
- `200 OK` - Successful GET, PUT, PATCH
- `201 Created` - Successful POST (resource created)
- `204 No Content` - Successful DELETE

**Client Errors:**
- `400 Bad Request` - Invalid input/validation error
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Authenticated but not authorized
- `404 Not Found` - Resource doesn't exist
- `409 Conflict` - Resource conflict (duplicate email)
- `422 Unprocessable Entity` - Validation error (detailed)
- `429 Too Many Requests` - Rate limit exceeded

**Server Errors:**
- `500 Internal Server Error` - Generic server error
- `502 Bad Gateway` - Upstream service error
- `503 Service Unavailable` - Temporary downtime
- `504 Gateway Timeout` - Upstream service timeout

### Request/Response Format

**ASP.NET Core Implementation:**
```csharp
// DTOs
public record CreateUserDto(
    string Email,
    string Name,
    int Age);

public record UserDto(
    Guid Id,
    string Email,
    string Name,
    int Age,
    DateTime CreatedAt,
    DateTime UpdatedAt);

// Controller
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;
    
    public UsersController(IUserService userService)
    {
        _userService = userService;
    }
    
    [HttpPost]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<UserDto>> CreateUser(
        [FromBody] CreateUserDto dto,
        CancellationToken cancellationToken)
    {
        var user = await _userService.CreateUserAsync(dto, cancellationToken);
        
        return CreatedAtAction(
            nameof(GetUser),
            new { id = user.Id, version = "1.0" },
            user);
    }
    
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserDto>> GetUser(
        Guid id,
        CancellationToken cancellationToken)
    {
        var user = await _userService.GetUserAsync(id, cancellationToken);
        
        if (user == null)
        {
            return NotFound();
        }
        
        return Ok(user);
    }
}
```

**Request:**
```http
POST /api/v1/users
Content-Type: application/json

{
  "email": "user@example.com",
  "name": "John Doe",
  "age": 30
}
```

**Success Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json
Location: /api/v1/users/12345678-1234-1234-1234-123456789012

{
  "id": "12345678-1234-1234-1234-123456789012",
  "email": "user@example.com",
  "name": "John Doe",
  "age": 30,
  "createdAt": "2025-01-09T12:00:00Z",
  "updatedAt": "2025-01-09T12:00:00Z"
}
```

**Error Response (ASP.NET Core ProblemDetails):**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{
  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "traceId": "00-1234567890abcdef1234567890abcdef-1234567890abcdef-00",
  "errors": {
    "email": [
      "Invalid email format"
    ],
    "age": [
      "Age must be between 18 and 120"
    ]
  }
}
```

### Pagination

**ASP.NET Core Implementation:**
```csharp
// Pagination DTOs
public record PaginationParams(
    int Page = 1,
    int Limit = 50);

public record PagedResponse<T>(
    IEnumerable<T> Data,
    PaginationMetadata Pagination,
    PaginationLinks Links);

public record PaginationMetadata(
    int Page,
    int Limit,
    int Total,
    int TotalPages,
    bool HasNext,
    bool HasPrev);

public record PaginationLinks(
    string First,
    string? Prev,
    string? Next,
    string Last);

// Controller
[HttpGet]
public async Task<ActionResult<PagedResponse<UserDto>>> GetUsers(
    [FromQuery] PaginationParams pagination,
    CancellationToken cancellationToken)
{
    var result = await _userService.GetUsersAsync(pagination, cancellationToken);
    
    var links = new PaginationLinks(
        First: Url.Action(nameof(GetUsers), new { page = 1, limit = pagination.Limit })!,
        Prev: result.Pagination.HasPrev ? Url.Action(nameof(GetUsers), new { page = pagination.Page - 1, limit = pagination.Limit }) : null,
        Next: result.Pagination.HasNext ? Url.Action(nameof(GetUsers), new { page = pagination.Page + 1, limit = pagination.Limit }) : null,
        Last: Url.Action(nameof(GetUsers), new { page = result.Pagination.TotalPages, limit = pagination.Limit })!
    );
    
    return Ok(new PagedResponse<UserDto>(result.Data, result.Pagination, links));
}
```

**Request:**
```http
GET /api/v1/users?page=2&limit=50
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "limit": 50,
    "total": 1234,
    "totalPages": 25,
    "hasNext": true,
    "hasPrev": true
  },
  "links": {
    "first": "/api/v1/users?page=1&limit=50",
    "prev": "/api/v1/users?page=1&limit=50",
    "next": "/api/v1/users?page=3&limit=50",
    "last": "/api/v1/users?page=25&limit=50"
  }
}
```

### Filtering and Sorting

**ASP.NET Core Implementation:**

**Using OData (for complex filtering):**
```csharp
// Program.cs
builder.Services.AddControllers()
    .AddOData(options => options
        .Select()
        .Filter()
        .OrderBy()
        .SetMaxTop(100)
        .Count());

// Controller
[ApiController]
[Route("api/v1/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]
    [EnableQuery]
    public IQueryable<UserDto> GetUsers([FromServices] AppDbContext context)
    {
        return context.Users.Select(u => new UserDto(...));
    }
}
```

**Manual Filtering and Sorting:**
```csharp
[HttpGet]
public async Task<ActionResult<IEnumerable<UserDto>>> GetUsers(
    [FromQuery] string? status,
    [FromQuery] string? role,
    [FromQuery] string? sortBy,
    [FromQuery] string? sortOrder = "asc",
    [FromQuery] int limit = 20,
    CancellationToken cancellationToken = default)
{
    var query = _userService.GetUsersQueryable();
    
    // Filtering
    if (!string.IsNullOrEmpty(status))
    {
        query = query.Where(u => u.Status == status);
    }
    
    if (!string.IsNullOrEmpty(role))
    {
        query = query.Where(u => u.Role == role);
    }
    
    // Sorting
    query = sortBy?.ToLower() switch
    {
        "createdat" => sortOrder == "desc" 
            ? query.OrderByDescending(u => u.CreatedAt)
            : query.OrderBy(u => u.CreatedAt),
        "name" => sortOrder == "desc"
            ? query.OrderByDescending(u => u.Name)
            : query.OrderBy(u => u.Name),
        _ => query.OrderBy(u => u.CreatedAt)
    };
    
    var users = await query
        .Take(limit)
        .ToListAsync(cancellationToken);
    
    return Ok(users);
}
```

**Request Examples:**
```http
GET /api/v1/users?status=active&role=admin&sortBy=createdAt&sortOrder=desc&limit=20

# Filters: status=active AND role=admin
# Sort: createdAt DESC
# Limit: 20 results
```

### API Versioning Strategies

**ASP.NET Core API Versioning (Microsoft.AspNetCore.Mvc.Versioning):**

**URL Versioning (Most Common):**
```csharp
// Program.cs
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader(),
        new QueryStringApiVersionReader("version"),
        new HeaderApiVersionReader("X-Version")
    );
});

// Controller
[ApiController]
[ApiVersion("1.0")]
[ApiVersion("2.0")]
[Route("api/v{version:apiVersion}/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]
    [MapToApiVersion("1.0")]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetUsersV1()
    {
        // V1 implementation
    }
    
    [HttpGet]
    [MapToApiVersion("2.0")]
    public async Task<ActionResult<IEnumerable<UserDtoV2>>> GetUsersV2()
    {
        // V2 implementation with different response format
    }
}
```

**Header Versioning:**
```csharp
// Accept header: application/vnd.myapi.v2+json
// Or custom header: X-API-Version: 2.0
```

**Query Parameter:**
```csharp
// /api/users?version=2.0
```

**Recommendation:** URL versioning (`/api/v1/users`) for simplicity and discoverability in ASP.NET Core

### ASP.NET Core Minimal APIs

**Minimal APIs** (introduced in .NET 6) provide a lightweight alternative to controllers for simple APIs.

**Basic Example:**
```csharp
// Program.cs
var app = builder.Build();

app.MapGet("/api/users", async (IUserService userService) =>
{
    var users = await userService.GetUsersAsync();
    return Results.Ok(users);
});

app.MapGet("/api/users/{id:guid}", async (
    Guid id,
    IUserService userService) =>
{
    var user = await userService.GetUserAsync(id);
    return user is null ? Results.NotFound() : Results.Ok(user);
});

app.MapPost("/api/users", async (
    CreateUserDto dto,
    IUserService userService) =>
{
    var user = await userService.CreateUserAsync(dto);
    return Results.Created($"/api/users/{user.Id}", user);
});

app.MapPut("/api/users/{id:guid}", async (
    Guid id,
    UpdateUserDto dto,
    IUserService userService) =>
{
    var user = await userService.UpdateUserAsync(id, dto);
    return user is null ? Results.NotFound() : Results.Ok(user);
});

app.MapDelete("/api/users/{id:guid}", async (
    Guid id,
    IUserService userService) =>
{
    var deleted = await userService.DeleteUserAsync(id);
    return deleted ? Results.NoContent() : Results.NotFound();
});

app.Run();
```

**With Validation and OpenAPI:**
```csharp
// Program.cs
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.MapPost("/api/users", async (
    CreateUserDto dto,
    IUserService userService,
    IValidator<CreateUserDto> validator) =>
{
    var validationResult = await validator.ValidateAsync(dto);
    if (!validationResult.IsValid)
    {
        return Results.ValidationProblem(validationResult.ToDictionary());
    }
    
    var user = await userService.CreateUserAsync(dto);
    return Results.Created($"/api/users/{user.Id}", user);
})
.WithName("CreateUser")
.WithOpenApi()
.Produces<UserDto>(StatusCodes.Status201Created)
.ProducesValidationProblem(StatusCodes.Status400BadRequest);

app.Run();
```

**When to Use Minimal APIs:**
- Simple CRUD APIs
- Microservices with few endpoints
- Prototyping and MVPs
- Performance-critical scenarios (slightly faster than controllers)

**When to Use Controllers:**
- Complex APIs with many endpoints
- Need advanced features (filters, model binding, etc.)
- Team prefers MVC pattern
- Large codebase with existing controller structure

## GraphQL API Design

### Schema Definition

```graphql
type User {
  id: ID!
  email: String!
  name: String!
  posts: [Post!]!
  createdAt: DateTime!
}

type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
  published: Boolean!
  createdAt: DateTime!
}

type Query {
  user(id: ID!): User
  users(limit: Int = 50, offset: Int = 0): [User!]!
  post(id: ID!): Post
  posts(authorId: ID, published: Boolean): [Post!]!
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  updateUser(id: ID!, input: UpdateUserInput!): User!
  deleteUser(id: ID!): Boolean!

  createPost(input: CreatePostInput!): Post!
  publishPost(id: ID!): Post!
}

input CreateUserInput {
  email: String!
  name: String!
  password: String!
}

input UpdateUserInput {
  email: String
  name: String
}
```

### Queries

```graphql
# Flexible data fetching - client specifies exactly what they need
query {
  user(id: "123") {
    id
    name
    email
    posts {
      id
      title
      published
    }
  }
}

# With variables
query GetUser($userId: ID!) {
  user(id: $userId) {
    id
    name
    posts(published: true) {
      title
    }
  }
}
```

### Mutations

```graphql
mutation CreateUser($input: CreateUserInput!) {
  createUser(input: $input) {
    id
    email
    name
    createdAt
  }
}

# Variables
{
  "input": {
    "email": "user@example.com",
    "name": "John Doe",
    "password": "SecurePass123!"
  }
}
```

### Resolvers (HotChocolate for .NET)

```csharp
// Program.cs - Configure HotChocolate
builder.Services
    .AddGraphQLServer()
    .AddQueryType<UserQuery>()
    .AddMutationType<UserMutation>()
    .AddType<UserType>()
    .AddType<PostType>()
    .AddDataLoader<UserDataLoader>()
    .AddFiltering()
    .AddSorting()
    .AddProjections();

// Query type
public class UserQuery
{
    public async Task<UserDto?> GetUser(
        Guid id,
        [Service] IUserService userService,
        CancellationToken cancellationToken)
    {
        return await userService.GetUserAsync(id, cancellationToken);
    }
    
    [UsePaging]
    [UseFiltering]
    [UseSorting]
    public async Task<IEnumerable<UserDto>> GetUsers(
        [Service] IUserService userService,
        CancellationToken cancellationToken)
    {
        return await userService.GetUsersAsync(cancellationToken);
    }
}

// Mutation type
public class UserMutation
{
    public async Task<UserDto> CreateUser(
        CreateUserInput input,
        [Service] IUserService userService,
        CancellationToken cancellationToken)
    {
        return await userService.CreateUserAsync(input, cancellationToken);
    }
}

// Object types
public class UserType : ObjectType<UserDto>
{
    protected override void Configure(IObjectTypeDescriptor<UserDto> descriptor)
    {
        descriptor.Field(u => u.Posts)
            .Resolve(async context =>
            {
                var user = context.Parent<UserDto>();
                var dataLoader = context.DataLoader<UserDataLoader>();
                return await dataLoader.LoadAsync(user.Id, context.RequestAborted);
            });
    }
}
```

### GraphQL Best Practices

1. **Avoid N+1 Problem** - Use DataLoader (HotChocolate)
```csharp
// DataLoader implementation
public class UserDataLoader : BatchDataLoader<Guid, IEnumerable<PostDto>>
{
    private readonly IPostService _postService;
    
    public UserDataLoader(
        IPostService postService,
        IBatchScheduler batchScheduler,
        DataLoaderOptions? options = null)
        : base(batchScheduler, options)
    {
        _postService = postService;
    }
    
    protected override async Task<IReadOnlyDictionary<Guid, IEnumerable<PostDto>>> LoadBatchAsync(
        IReadOnlyList<Guid> keys,
        CancellationToken cancellationToken)
    {
        var posts = await _postService.GetPostsByUserIdsAsync(keys, cancellationToken);
        
        return keys.ToDictionary(
            key => key,
            key => posts.Where(p => p.AuthorId == key));
    }
}

// In resolver
public class UserType : ObjectType<UserDto>
{
    protected override void Configure(IObjectTypeDescriptor<UserDto> descriptor)
    {
        descriptor.Field(u => u.Posts)
            .Resolve(async context =>
            {
                var user = context.Parent<UserDto>();
                var dataLoader = context.DataLoader<UserDataLoader>();
                return await dataLoader.LoadAsync(user.Id, context.RequestAborted);
            });
    }
}
```

2. **Pagination** - Use HotChocolate's built-in pagination
```csharp
[UsePaging]
[UseFiltering]
[UseSorting]
public IQueryable<UserDto> GetUsers([Service] AppDbContext context)
{
    return context.Users.Select(u => new UserDto(...));
}
```

3. **Error Handling** - HotChocolate error handling
```csharp
builder.Services
    .AddGraphQLServer()
    .AddErrorInterfaceType<IUserError>()
    .AddErrorFilter<CustomErrorFilter>();
```

4. **Depth Limiting** - Configure in HotChocolate
```csharp
builder.Services
    .AddGraphQLServer()
    .ModifyRequestOptions(options =>
    {
        options.MaxAllowedNodeDepth = 15;
        options.MaxAllowedExecutionTime = TimeSpan.FromSeconds(30);
    });
```

5. **Query Complexity Analysis** - Use HotChocolate complexity analyzer
```csharp
builder.Services
    .AddGraphQLServer()
    .AddQueryComplexityAnalyzer()
    .SetMaxComplexity(100);
```

## gRPC API Design

### Protocol Buffers Schema

```protobuf
syntax = "proto3";

package user;

service UserService {
  rpc GetUser (GetUserRequest) returns (User);
  rpc ListUsers (ListUsersRequest) returns (ListUsersResponse);
  rpc CreateUser (CreateUserRequest) returns (User);
  rpc UpdateUser (UpdateUserRequest) returns (User);
  rpc DeleteUser (DeleteUserRequest) returns (DeleteUserResponse);

  // Streaming
  rpc StreamUsers (StreamUsersRequest) returns (stream User);
}

message User {
  string id = 1;
  string email = 2;
  string name = 3;
  int64 created_at = 4;
}

message GetUserRequest {
  string id = 1;
}

message ListUsersRequest {
  int32 limit = 1;
  int32 offset = 2;
}

message ListUsersResponse {
  repeated User users = 1;
  int32 total = 2;
}

message CreateUserRequest {
  string email = 1;
  string name = 2;
  string password = 3;
}
```

### Implementation (.NET gRPC)

**Project Setup:**
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <Protobuf Include="Protos\user.proto" GrpcServices="Server" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Grpc.AspNetCore" Version="2.57.0" />
  </ItemGroup>
</Project>
```

**Program.cs:**
```csharp
builder.Services.AddGrpc();

var app = builder.Build();

app.MapGrpcService<UserService>();
app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client.");

app.Run();
```

**Service Implementation:**
```csharp
public class UserService : User.UserBase
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<UserService> _logger;
    
    public UserService(
        IUserRepository userRepository,
        ILogger<UserService> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }
    
    public override async Task<UserResponse> GetUser(
        GetUserRequest request,
        ServerCallContext context)
    {
        var user = await _userRepository.GetByIdAsync(
            Guid.Parse(request.Id),
            context.CancellationToken);
        
        if (user == null)
        {
            throw new RpcException(
                new Status(StatusCode.NotFound, $"User with ID {request.Id} not found"));
        }
        
        return new UserResponse
        {
            Id = user.Id.ToString(),
            Email = user.Email ?? string.Empty,
            Name = user.Name ?? string.Empty,
            CreatedAt = user.CreatedAt.ToUnixTimeSeconds()
        };
    }
    
    public override async Task<UserResponse> CreateUser(
        CreateUserRequest request,
        ServerCallContext context)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = request.Email,
            Name = request.Name,
            CreatedAt = DateTime.UtcNow
        };
        
        await _userRepository.AddAsync(user, context.CancellationToken);
        
        return new UserResponse
        {
            Id = user.Id.ToString(),
            Email = user.Email ?? string.Empty,
            Name = user.Name ?? string.Empty,
            CreatedAt = user.CreatedAt.ToUnixTimeSeconds()
        };
    }
    
    public override async Task StreamUsers(
        StreamUsersRequest request,
        IServerStreamWriter<UserResponse> responseStream,
        ServerCallContext context)
    {
        var users = await _userRepository.GetAllAsync(context.CancellationToken);
        
        foreach (var user in users)
        {
            if (context.CancellationToken.IsCancellationRequested)
                break;
                
            await responseStream.WriteAsync(new UserResponse
            {
                Id = user.Id.ToString(),
                Email = user.Email ?? string.Empty,
                Name = user.Name ?? string.Empty,
                CreatedAt = user.CreatedAt.ToUnixTimeSeconds()
            });
        }
    }
}
```

### gRPC Benefits

- **Performance:** 7-10x faster than REST (binary protocol)
- **Streaming:** Bi-directional streaming
- **Type Safety:** Strong typing via Protocol Buffers
- **Code Generation:** Auto-generate client/server code
- **Best For:** Internal microservices, high-performance systems

## API Design Decision Matrix

| Feature | REST | GraphQL | gRPC |
|---------|------|---------|------|
| **Use Case** | Public APIs, CRUD | Flexible data fetching | Microservices, performance |
| **Performance** | Moderate | Moderate | Fastest (7-10x REST) |
| **Caching** | HTTP caching built-in | Complex | No built-in caching |
| **Browser Support** | Native | Native | Requires gRPC-Web |
| **Learning Curve** | Easy | Moderate | Steep |
| **Streaming** | Limited (SSE) | Subscriptions | Bi-directional |
| **Tooling** | Excellent | Excellent | Good |
| **Documentation** | OpenAPI/Swagger | Schema introspection | Protobuf definition |

## API Security Checklist

- [ ] HTTPS/TLS only (no HTTP) - Configure in `Program.cs` with `app.UseHttpsRedirection()`
- [ ] Authentication (OAuth 2.1, JWT, API keys) - Use `Microsoft.AspNetCore.Authentication.JwtBearer`
- [ ] Authorization (RBAC, check permissions) - Use `[Authorize]` attributes and policies
- [ ] Rate limiting (prevent abuse) - Use `AspNetCoreRateLimit` or `Microsoft.AspNetCore.RateLimiting`
- [ ] Input validation (all endpoints) - Use `FluentValidation` or Data Annotations
- [ ] CORS configured properly - Use `app.UseCors()` with specific origins
- [ ] Security headers (CSP, HSTS, X-Frame-Options) - Use `NWebsec.AspNetCore.SecurityHeaders` or custom middleware
- [ ] API versioning implemented - Use `Microsoft.AspNetCore.Mvc.Versioning`
- [ ] Error messages don't leak system info - Use `ProblemDetails` and custom exception handlers
- [ ] Audit logging (who did what, when) - Use `Serilog` or `Application Insights`
- [ ] SQL injection prevention - Use parameterized queries (EF Core, Dapper)
- [ ] XSS prevention - Use output encoding and Content Security Policy
- [ ] CSRF protection - Use anti-forgery tokens for state-changing operations
- [ ] Secrets management - Use `Azure Key Vault` or `HashiCorp Vault` (never hardcode)
- [ ] API key rotation - Implement key rotation strategy
- [ ] Request size limits - Configure `RequestSizeLimit` and `MaxRequestBodySize`

## API Documentation

### OpenAPI/Swagger (ASP.NET Core)

**Setup:**
```csharp
// Program.cs
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "User API",
        Version = "1.0",
        Description = "A sample API for managing users",
        Contact = new OpenApiContact
        {
            Name = "API Support",
            Email = "support@example.com"
        }
    });
    
    // Include XML comments
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);
    
    // JWT Bearer authentication
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "User API v1");
        options.RoutePrefix = string.Empty; // Swagger UI at root
    });
}
```

**Controller with XML Documentation:**
```csharp
/// <summary>
/// Controller for managing users.
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[Produces("application/json")]
public class UsersController : ControllerBase
{
    /// <summary>
    /// Gets a list of users with pagination.
    /// </summary>
    /// <param name="page">Page number (default: 1).</param>
    /// <param name="limit">Number of items per page (default: 50).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A paginated list of users.</returns>
    /// <response code="200">Returns the list of users.</response>
    [HttpGet]
    [ProducesResponseType(typeof(PagedResponse<UserDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<PagedResponse<UserDto>>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int limit = 50,
        CancellationToken cancellationToken = default)
    {
        // Implementation
    }
}
```

**Generated OpenAPI Schema:**
```yaml
openapi: 3.0.0
info:
  title: User API
  version: 1.0
paths:
  /api/v1/users:
    get:
      summary: Gets a list of users with pagination.
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            default: 1
        - name: limit
          in: query
          schema:
            type: integer
            default: 50
      responses:
        '200':
          description: Returns the list of users.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PagedResponseOfUserDto'
components:
  schemas:
    UserDto:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
        name:
          type: string
```

## Optimizely-Specific API Design

### Optimizely Content Delivery API

**REST API for Content:**
```csharp
[ApiController]
[Route("api/content")]
public class ContentController : ControllerBase
{
    private readonly IContentLoader _contentLoader;
    
    public ContentController(IContentLoader contentLoader)
    {
        _contentLoader = contentLoader;
    }
    
    /// <summary>
    /// Gets content by ID.
    /// </summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(ContentDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult GetContent(int id)
    {
        var content = _contentLoader.Get<PageData>(new ContentReference(id));
        
        if (content == null)
        {
            return NotFound();
        }
        
        return Ok(new ContentDto
        {
            Id = content.ContentLink.ID,
            Name = content.Name,
            Url = content.LinkURL,
            Created = content.Created
        });
    }
    
    /// <summary>
    /// Gets children of a content item.
    /// </summary>
    [HttpGet("{id:int}/children")]
    public IActionResult GetChildren(int id)
    {
        var children = _contentLoader.GetChildren<PageData>(
            new ContentReference(id));
        
        var dtos = children.Select(c => new ContentDto
        {
            Id = c.ContentLink.ID,
            Name = c.Name,
            Url = c.LinkURL
        });
        
        return Ok(dtos);
    }
}
```

### Optimizely GraphQL API

**HotChocolate with Optimizely:**
```csharp
// GraphQL query type for Optimizely content
public class ContentQuery
{
    public async Task<ContentDto?> GetContent(
        int id,
        [Service] IContentLoader contentLoader,
        CancellationToken cancellationToken)
    {
        var content = contentLoader.Get<PageData>(new ContentReference(id));
        
        if (content == null)
            return null;
            
        return new ContentDto
        {
            Id = content.ContentLink.ID,
            Name = content.Name,
            Url = content.LinkURL
        };
    }
    
    [UsePaging]
    [UseFiltering]
    public IQueryable<ContentDto> GetContents(
        [Service] IContentLoader contentLoader)
    {
        var contents = contentLoader.GetChildren<PageData>(ContentReference.StartPage);
        return contents.Select(c => new ContentDto
        {
            Id = c.ContentLink.ID,
            Name = c.Name,
            Url = c.LinkURL
        }).AsQueryable();
    }
}
```

## ASP.NET Core API Best Practices

### ProblemDetails for Error Responses

```csharp
// Program.cs - Configure ProblemDetails
builder.Services.AddProblemDetails();

// Custom exception handler
app.UseExceptionHandler(exceptionHandlerApp =>
{
    exceptionHandlerApp.Run(async context =>
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        
        var exceptionHandlerFeature = context.Features.Get<IExceptionHandlerFeature>();
        var exception = exceptionHandlerFeature?.Error;
        
        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "An error occurred while processing your request.",
            Detail = exception?.Message,
            Instance = context.Request.Path
        };
        
        await context.Response.WriteAsJsonAsync(problemDetails);
    });
});
```

### Model Validation

```csharp
// Using FluentValidation
public class CreateUserDtoValidator : AbstractValidator<CreateUserDto>
{
    public CreateUserDtoValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .WithMessage("Invalid email address");
            
        RuleFor(x => x.Name)
            .NotEmpty()
            .MinimumLength(2)
            .MaximumLength(100);
            
        RuleFor(x => x.Age)
            .InclusiveBetween(18, 120);
    }
}

// Register in Program.cs
builder.Services.AddControllers()
    .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<CreateUserDtoValidator>());
```

### Response Compression

```csharp
// Program.cs
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
});

app.UseResponseCompression();
```

## Resources

### .NET API Design
- **ASP.NET Core Web API:** https://learn.microsoft.com/aspnet/core/web-api/
- **API Versioning:** https://github.com/dotnet/aspnet-api-versioning
- **OpenAPI/Swagger:** https://learn.microsoft.com/aspnet/core/tutorials/web-api-help-pages-using-swagger
- **ProblemDetails:** https://learn.microsoft.com/aspnet/core/fundamentals/error-handling#problem-details

### GraphQL (.NET)
- **HotChocolate:** https://chillicream.com/docs/hotchocolate
- **GraphQL.NET:** https://graphql-dotnet.github.io/

### gRPC (.NET)
- **.NET gRPC:** https://learn.microsoft.com/aspnet/core/grpc/
- **gRPC for .NET:** https://grpc.io/docs/languages/csharp/

### Optimizely APIs
- **Optimizely Content Delivery API:** https://docs.developers.optimizely.com/content-management-system/docs/content-delivery-api
- **Optimizely GraphQL API:** https://docs.developers.optimizely.com/content-management-system/docs/graphql-api

### General
- **REST Best Practices:** https://restfulapi.net/
- **GraphQL:** https://graphql.org/learn/
- **gRPC:** https://grpc.io/docs/
- **OpenAPI:** https://swagger.io/specification/
