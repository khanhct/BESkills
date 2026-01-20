# Backend Development Mindset

Advanced problem-solving approaches, architectural thinking, and collaboration patterns for C#/.NET backend engineers (2025).

## Problem-Solving Mindset

### Systems Thinking Approach

**Holistic Engineering** - Understanding how components interact within larger ecosystem

```
User Request
  → Azure Load Balancer / Application Gateway
  → ASP.NET Core Middleware Pipeline (auth, rate limiting, CORS)
  → Controllers / Minimal APIs (routing)
  → Application Services (business logic, CQRS handlers)
  → Domain Layer (entities, value objects, domain events)
  → Infrastructure Layer (EF Core, Repositories)
  → SQL Server (persistent storage)
  → Redis Cache (IDistributedCache)
  → Azure Service Bus / Hangfire (async processing)
  → External Services (HttpClient with Polly resilience)
```

**Questions to Ask:**
- What happens if this component fails?
- How does this scale under load?
- What are the dependencies?
- Where are the bottlenecks?
- What's the blast radius of changes?

### Breaking Down Complex Problems

**Decomposition Strategy:**

1. **Understand requirements** - What problem are we solving?
2. **Identify constraints** - Performance, budget, timeline, tech stack
3. **Break into modules** - Separate concerns (auth, data, business logic)
4. **Define interfaces** - API contracts between modules
5. **Prioritize** - Critical path first
6. **Iterate** - Build, test, refine

**Example: Building Payment System with .NET**

```
Complex: "Build payment processing"

Decomposed (.NET Architecture):
1. Domain Layer: Payment aggregate, Order aggregate, PaymentStatus value object
2. Application Layer: 
   - Commands: ProcessPaymentCommand, RefundPaymentCommand
   - Queries: GetPaymentStatusQuery
   - Handlers: MediatR handlers for CQRS
3. Infrastructure Layer:
   - Payment gateway adapters (Stripe/PayPal SDK wrappers)
   - EF Core repositories with Unit of Work pattern
   - Idempotency service (using distributed cache)
4. API Layer:
   - PaymentController with validation (FluentValidation)
   - Webhook endpoints with signature verification
5. Background Processing:
   - Hangfire jobs for reconciliation
   - Azure Service Bus for async payment processing
6. Cross-Cutting:
   - Polly policies for retry/circuit breaker
   - Serilog structured logging
   - Application Insights telemetry
```

## Trade-Off Analysis

### CAP Theorem (Choose 2 of 3)

**Consistency** - All nodes see same data at same time
**Availability** - Every request receives response
**Partition Tolerance** - System works despite network failures

**Real-World Choices:**
- **CP (Consistency + Partition Tolerance):** Banking systems, financial transactions
- **AP (Availability + Partition Tolerance):** Social media feeds, product catalogs
- **CA (Consistency + Availability):** Single-node databases (not distributed)

### PACELC Extension

**If Partition:** Choose Availability or Consistency
**Else (no partition):** Choose Latency or Consistency

**Examples:**
- **PA/EL:** Cassandra (available during partition, low latency normally)
- **PC/EC:** HBase (consistent during partition, consistent over latency)
- **PA/EC:** DynamoDB (configurable consistency vs latency)

### Performance vs Maintainability

| Optimize For | When to Choose |
|--------------|---------------|
| **Performance** | Hot paths, high-traffic endpoints, real-time systems |
| **Maintainability** | Internal tools, admin dashboards, CRUD operations |
| **Both** | Core business logic, payment processing, authentication |

**Example:**
```csharp
// Maintainable: Readable, easy to debug (EF Core)
var users = await _context.Users
    .Where(u => u.IsActive)
    .Include(u => u.Posts)
    .Include(u => u.Comments)
    .ToListAsync();

// Performant: Optimized query, reduced joins (Dapper or EF Core projection)
var users = await _context.Users
    .Where(u => u.IsActive)
    .Select(u => new UserDto
    {
        Id = u.Id,
        Email = u.Email,
        PostCount = u.Posts.Count,
        CommentCount = u.Comments.Count
    })
    .ToListAsync();

// Or with Dapper for maximum performance
var sql = @"
    SELECT u.*,
        (SELECT COUNT(*) FROM Posts WHERE UserId = u.Id) as PostCount,
        (SELECT COUNT(*) FROM Comments WHERE UserId = u.Id) as CommentCount
    FROM Users u
    WHERE u.IsActive = 1";
var users = await _connection.QueryAsync<UserDto>(sql);
```

### Technical Debt Management

**20-40% productivity increase** from addressing technical debt properly

**Debt Quadrants:**
1. **Reckless + Deliberate:** "We don't have time for design"
2. **Reckless + Inadvertent:** "What's layering?"
3. **Prudent + Deliberate:** "Ship now, refactor later" (acceptable)
4. **Prudent + Inadvertent:** "Now we know better" (acceptable)

**Prioritization:**
- High interest, high impact → Fix immediately
- High interest, low impact → Schedule in sprint
- Low interest, high impact → Tech debt backlog
- Low interest, low impact → Leave as-is

## Architectural Thinking

### Domain-Driven Design (DDD)

**Bounded Contexts** - Separate models for different domains

```
E-commerce System:

[Sales Context]          [Inventory Context]       [Shipping Context]
- Order (id, items,      - Product (id, stock,     - Shipment (id,
  total, customer)        location, reserved)       address, status)
- Customer (id, email)   - Warehouse (id, name)    - Carrier (name, API)
- Payment (status)       - StockLevel (quantity)   - Tracking (number)

Each context has its own:
- Data model
- Business rules
- Database schema
- API contracts
```

**Ubiquitous Language** - Shared vocabulary between devs and domain experts

### Clean Architecture / Onion Architecture (.NET)

```
┌─────────────────────────────────────────┐
│   Presentation Layer                    │  Controllers, Minimal APIs, DTOs
│   (ASP.NET Core)                        │
├─────────────────────────────────────────┤
│   Application Layer                     │  Use Cases, CQRS (MediatR), Application Services
│   (Business workflows)                  │
├─────────────────────────────────────────┤
│   Domain Layer                          │  Entities, Value Objects, Domain Events, Aggregates
│   (Core business logic)                 │
├─────────────────────────────────────────┤
│   Infrastructure Layer                  │  EF Core, Repositories, External Services, Email
│   (Technical concerns)                  │
└─────────────────────────────────────────┘
```

**Benefits:**
- Clear responsibilities and dependencies (dependency inversion)
- Easier testing (mock infrastructure, test domain logic)
- Flexibility to change implementations (swap EF Core for Dapper)
- Reduced coupling (domain independent of infrastructure)
- Testability (domain logic testable without database)

**Dependency Injection in .NET:**
```csharp
// Program.cs - Register layers
builder.Services.AddScoped<IUserRepository, UserRepository>(); // Infrastructure
builder.Services.AddScoped<IUserService, UserService>(); // Application
builder.Services.AddMediatR(typeof(ApplicationAssembly)); // CQRS
builder.Services.AddAutoMapper(typeof(ApplicationAssembly)); // Mapping
```

### Designing for Failure (Resilience with Polly)

**Assume everything fails eventually**

**Patterns:**
1. **Circuit Breaker** - Stop calling failing service
2. **Retry with Backoff** - Exponential delay between retries
3. **Timeout** - Don't wait forever
4. **Fallback** - Graceful degradation
5. **Bulkhead** - Isolate failures (resource pools)

**Polly - .NET Resilience Framework:**
```csharp
// Program.cs - Configure resilience policies
builder.Services.AddHttpClient<IExternalService, ExternalService>()
    .AddPolicyHandler(GetRetryPolicy())
    .AddPolicyHandler(GetCircuitBreakerPolicy())
    .AddPolicyHandler(GetTimeoutPolicy());

// Retry policy with exponential backoff
static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError()
        .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        .WaitAndRetryAsync(
            retryCount: 3,
            sleepDurationProvider: retryAttempt => 
                TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
            onRetry: (outcome, timespan, retryCount, context) =>
            {
                _logger.LogWarning(
                    "Retry {RetryCount} after {Delay}ms", 
                    retryCount, timespan.TotalMilliseconds);
            });
}

// Circuit breaker policy
static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError()
        .CircuitBreakerAsync(
            handledEventsAllowedBeforeBreaking: 5,
            durationOfBreak: TimeSpan.FromSeconds(30),
            onBreak: (result, duration) =>
            {
                _logger.LogWarning("Circuit breaker opened for {Duration}", duration);
            },
            onReset: () =>
            {
                _logger.LogInformation("Circuit breaker reset");
            });
}

// Timeout policy
static IAsyncPolicy<HttpResponseMessage> GetTimeoutPolicy()
{
    return Policy.TimeoutAsync<HttpResponseMessage>(TimeSpan.FromSeconds(10));
}

// Usage with fallback
public class ExternalService
{
    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    
    public async Task<Data> GetDataAsync(string key)
    {
        var policy = Policy<Data>
            .Handle<HttpRequestException>()
            .FallbackAsync(
                fallbackAction: async ct => await _cache.GetAsync<Data>(key),
                onFallbackAsync: async result =>
                {
                    _logger.LogWarning("Using cached data due to failure");
                });
        
        return await policy.ExecuteAsync(async () =>
        {
            var response = await _httpClient.GetAsync($"/api/data/{key}");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<Data>();
        });
    }
}
```

## Developer Mindset

### Writing Maintainable Code

**SOLID Principles:**

**S - Single Responsibility** - Class/function does one thing
```csharp
// Bad: User class handles auth + email + logging
public class User
{
    public void Authenticate() { }
    public void SendEmail() { }
    public void LogActivity() { }
}

// Good: Separate responsibilities with dependency injection
public class User
{
    public void Authenticate() { }
}

public class EmailService : IEmailService
{
    public async Task SendEmailAsync(string to, string subject, string body) { }
}

public class Logger : ILogger
{
    public void LogActivity(string activity) { }
}

// Register in DI container
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ILogger, Logger>();
```

**O - Open/Closed** - Open for extension, closed for modification
```csharp
// Good: Strategy pattern with interfaces
public interface IPaymentStrategy
{
    Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request);
}

public class StripePaymentStrategy : IPaymentStrategy
{
    public async Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request)
    {
        // Stripe implementation
    }
}

public class PayPalPaymentStrategy : IPaymentStrategy
{
    public async Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request)
    {
        // PayPal implementation
    }
}

// Payment service uses strategy (Open/Closed principle)
public class PaymentService
{
    private readonly IPaymentStrategy _strategy;
    
    public PaymentService(IPaymentStrategy strategy)
    {
        _strategy = strategy; // Injected, can be extended without modification
    }
    
    public async Task<PaymentResult> ProcessPaymentAsync(decimal amount, PaymentRequest request)
    {
        return await _strategy.ProcessAsync(amount, request);
    }
}
```

**L - Liskov Substitution** - Derived classes must be substitutable for base classes
```csharp
// Bad: Violates LSP
public class Rectangle
{
    public virtual int Width { get; set; }
    public virtual int Height { get; set; }
}

public class Square : Rectangle
{
    public override int Width 
    { 
        set { base.Width = value; base.Height = value; } // Breaks rectangle contract
    }
}

// Good: Separate interfaces
public interface IShape
{
    int Area { get; }
}

public class Rectangle : IShape { }
public class Square : IShape { }
```

**I - Interface Segregation** - Many specific interfaces better than one general
```csharp
// Bad: Fat interface
public interface IUserRepository
{
    Task<User> GetByIdAsync(Guid id);
    Task<User> GetByEmailAsync(string email);
    Task SaveAsync(User user);
    Task DeleteAsync(Guid id);
    Task SendEmailAsync(User user); // Not repository responsibility!
}

// Good: Segregated interfaces
public interface IUserRepository
{
    Task<User> GetByIdAsync(Guid id);
    Task<User> GetByEmailAsync(string email);
    Task SaveAsync(User user);
    Task DeleteAsync(Guid id);
}

public interface IUserEmailService
{
    Task SendEmailAsync(User user);
}
```

**D - Dependency Inversion** - Depend on abstractions, not concretions
```csharp
// Bad: Depends on concrete implementation
public class OrderService
{
    private readonly SqlServerOrderRepository _repository; // Concrete dependency
    
    public OrderService()
    {
        _repository = new SqlServerOrderRepository(); // Tight coupling
    }
}

// Good: Depends on abstraction
public class OrderService
{
    private readonly IOrderRepository _repository; // Abstraction
    
    public OrderService(IOrderRepository repository) // Injected dependency
    {
        _repository = repository; // Loose coupling
    }
}

// Register in DI container
builder.Services.AddScoped<IOrderRepository, SqlServerOrderRepository>();
```

### Thinking About Edge Cases

**Common Edge Cases:**
- Empty arrays/collections
- Null/undefined values
- Boundary values (min/max integers)
- Concurrent requests (race conditions)
- Network failures
- Duplicate requests (idempotency)
- Invalid input (SQL injection, XSS)

```csharp
// Good: Handle edge cases explicitly with validation
public class GetUsersQuery
{
    [Range(1, 1000, ErrorMessage = "Limit must be between 1 and 1000")]
    public int? Limit { get; set; }
}

public class UserService
{
    private readonly IUserRepository _repository;
    
    public async Task<IEnumerable<UserDto>> GetUsersAsync(GetUsersQuery query)
    {
        // Validate input (FluentValidation or Data Annotations)
        var validator = new GetUsersQueryValidator();
        var validationResult = await validator.ValidateAsync(query);
        if (!validationResult.IsValid)
        {
            throw new ValidationException(validationResult.Errors);
        }

        // Handle null with default
        var safeLimit = query.Limit ?? 50;

        // EF Core prevents SQL injection automatically (parameterized queries)
        var users = await _repository.GetAllAsync()
            .Take(safeLimit)
            .ToListAsync();

        // Handle empty results (return empty collection, not null)
        return users.Select(u => new UserDto
        {
            Id = u.Id,
            Email = u.Email,
            Name = u.Name
        });
    }
}

// Null safety with nullable reference types
public User? GetUserById(Guid id) // Returns nullable
{
    return _repository.Find(id); // Can return null
}

// Use null-conditional operators
var email = user?.Email ?? "unknown"; // Safe navigation
```

### Testing Mindset (TDD/BDD with xUnit/NUnit)

**70% happy-path tests drafted by AI, humans focus on edge cases**

**Test-Driven Development (TDD) with xUnit:**
```csharp
// 1. Write failing test
[Fact]
public async Task CreateUser_WithValidData_ReturnsUser()
{
    // Arrange
    var command = new CreateUserCommand 
    { 
        Email = "test@example.com", 
        Name = "Test User" 
    };
    var handler = new CreateUserCommandHandler(_mockRepository.Object);

    // Act
    var result = await handler.Handle(command, CancellationToken.None);

    // Assert
    Assert.NotNull(result);
    Assert.Equal(command.Email, result.Email);
}

// 2. Write minimal code to pass
// 3. Refactor
// 4. Repeat
```

**Behavior-Driven Development (BDD) with SpecFlow:**
```gherkin
Feature: User Registration
  Scenario: User registers with valid email
    Given I am on the registration page
    When I enter "test@example.com" as email
    And I enter "SecurePass123!" as password
    Then I should see "Registration successful"
    And I should receive a welcome email
```

**Integration Testing with WebApplicationFactory:**
```csharp
public class UserRegistrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    [Fact]
    public async Task POST_RegisterUser_WithValidData_Returns201()
    {
        // Arrange
        var dto = new RegisterUserDto 
        { 
            Email = "test@example.com", 
            Password = "SecurePass123!" 
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/users/register", dto);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }
}
```

**Testing Mindset Principles:**
- Test behavior, not implementation
- Use FluentAssertions for readable assertions
- Mock external dependencies (Moq/NSubstitute)
- Test edge cases: null, empty, boundaries, concurrency
- Use Theory/TestCase for parameterized tests

### Observability and Debugging Approach

**100% median ROI, $500k average return** from observability investments

**Three Questions:**
1. **Is it slow?** → Check metrics (response time, DB queries)
2. **Is it broken?** → Check logs (errors, stack traces)
3. **Where is it broken?** → Check traces (distributed systems)

```csharp
// Good: Structured logging with Serilog
_logger.LogError(
    "Payment processing failed for order {OrderId} by user {UserId} for amount {Amount}",
    order.Id,
    user.Id,
    order.Total);

// With exception details
_logger.LogError(
    exception,
    "Payment processing failed for order {OrderId}",
    order.Id);

// With scoped context (correlation ID, request ID)
using (_logger.BeginScope(new Dictionary<string, object>
{
    ["OrderId"] = order.Id,
    ["UserId"] = user.Id,
    ["CorrelationId"] = HttpContext.TraceIdentifier
}))
{
    _logger.LogInformation("Processing payment");
    // All logs in this scope include the context
}

// Application Insights telemetry
_telemetryClient.TrackEvent("PaymentProcessed", new Dictionary<string, string>
{
    ["OrderId"] = order.Id.ToString(),
    ["Amount"] = order.Total.ToString("C"),
    ["Status"] = "Success"
});

// Custom metrics
_telemetryClient.TrackMetric("PaymentProcessingTime", duration.TotalMilliseconds);
```

**Observability Stack for .NET:**
- **Serilog** - Structured logging with multiple sinks
- **Application Insights** - APM, distributed tracing, metrics
- **OpenTelemetry** - Standardized observability
- **MiniProfiler** - Real-time performance profiling
- **Health Checks** - Built-in ASP.NET Core health monitoring

## Collaboration & Communication

### API Contract Design (Treating APIs as Products)

**Principles:**
1. **Versioning** - `/api/v1/users`, `/api/v2/users`
2. **Consistency** - Same patterns across endpoints
3. **Documentation** - OpenAPI/Swagger
4. **Backward compatibility** - Don't break existing clients
5. **Clear error messages** - Help clients fix issues

```csharp
// Good: Consistent API design with ASP.NET Core
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
public class UsersController : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetUsers() { }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<UserDto>> GetUser(Guid id) { }

    [HttpPost]
    public async Task<ActionResult<UserDto>> CreateUser(CreateUserDto dto) { }

    [HttpPut("{id:guid}")]
    public async Task<ActionResult<UserDto>> UpdateUser(Guid id, UpdateUserDto dto) { }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id) { }
}

// Consistent error format with ProblemDetails
public class GlobalExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "An error occurred",
            Detail = exception.Message,
            Instance = httpContext.Request.Path,
            Extensions = new Dictionary<string, object?>
            {
                ["traceId"] = httpContext.TraceIdentifier,
                ["timestamp"] = DateTime.UtcNow
            }
        };

        httpContext.Response.StatusCode = problemDetails.Status.Value;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);
        return true;
    }
}

// Validation error response
{
  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
  "title": "Validation Error",
  "status": 400,
  "errors": {
    "email": ["Invalid email format"],
    "password": ["Password must be at least 12 characters"]
  },
  "traceId": "00-abc123-def456-789",
  "timestamp": "2025-01-09T12:00:00Z"
}
```

### Database Schema Design Discussions (.NET/EF Core)

**Key Considerations:**
- **Normalization vs Denormalization** - Trade-offs for performance
- **Indexing strategy** - Query patterns dictate indexes (EF Core migrations)
- **Migration path** - EF Core migrations, zero-downtime deployments
- **Data types** - SQL Server: NVARCHAR(255) vs NVARCHAR(MAX), INT vs BIGINT
- **Constraints** - Foreign keys, unique constraints, check constraints
- **Temporal tables** - SQL Server audit trails
- **Computed columns** - Database-level calculations

**EF Core Code-First Approach:**
```csharp
public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public bool IsActive { get; set; }
    
    // Navigation properties
    public ICollection<Order> Orders { get; set; } = new List<Order>();
}

// DbContext configuration
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<User>(entity =>
    {
        entity.HasKey(e => e.Id);
        entity.HasIndex(e => e.Email).IsUnique();
        entity.Property(e => e.Email).HasMaxLength(255).IsRequired();
        entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
        entity.HasMany(e => e.Orders)
            .WithOne(o => o.User)
            .HasForeignKey(o => o.UserId)
            .OnDelete(DeleteBehavior.Restrict);
    });
}

// Migration strategy
// 1. Add migration: dotnet ef migrations add AddUserTable
// 2. Review migration SQL
// 3. Apply: dotnet ef database update
// 4. Deploy with zero-downtime (blue-green, feature flags)
```

**Database Design Patterns:**
- **Repository Pattern** - Abstract data access
- **Unit of Work** - Transaction management
- **Specification Pattern** - Complex query building
- **CQRS** - Separate read/write models

### Code Review Mindset (Prevention-First)

**What to Look For:**
- Security vulnerabilities (SQL injection, XSS)
- Performance issues (N+1 queries, missing indexes)
- Error handling (uncaught exceptions)
- Edge cases (null checks, boundary values)
- Readability (naming, comments for complex logic)
- Tests (coverage for new code)

**Constructive Feedback:**
```csharp
// Good review comment
// "This could be vulnerable to SQL injection. EF Core uses parameterized queries automatically, 
// but if using raw SQL, use parameterized queries:
// await _context.Database.ExecuteSqlRawAsync(
//     \"SELECT * FROM Users WHERE Id = {0}\", userId);"

// "Consider using Include() to avoid N+1 queries:
// var users = await _context.Users
//     .Include(u => u.Posts)
//     .ToListAsync();"

// "This method should be async since it performs I/O:
// public async Task<User> GetUserAsync(Guid id) { }"

// Bad review comment
// "This is wrong. Fix it."
```

**Code Review Checklist for .NET:**
- ✅ Uses async/await for I/O operations
- ✅ Proper null handling (nullable reference types)
- ✅ Dependency injection instead of `new` keyword
- ✅ EF Core queries optimized (no N+1, proper projections)
- ✅ Error handling with try-catch or Result pattern
- ✅ Validation with FluentValidation or Data Annotations
- ✅ Logging with structured logging (Serilog)
- ✅ Unit tests with xUnit/NUnit
- ✅ Follows SOLID principles
- ✅ Uses appropriate design patterns

## Advanced .NET Mindset Checklist

### Architecture & Design
- [ ] Think in systems (understand dependencies, middleware pipeline)
- [ ] Apply Clean Architecture / Onion Architecture principles
- [ ] Use CQRS pattern with MediatR for complex domains
- [ ] Implement Domain-Driven Design (DDD) with bounded contexts
- [ ] Analyze trade-offs (CAP, performance vs maintainability)
- [ ] Design for failure (Polly resilience policies)

### Code Quality
- [ ] Apply SOLID principles consistently
- [ ] Use dependency injection (built-in DI container)
- [ ] Leverage nullable reference types for null safety
- [ ] Consider edge cases (null, empty, boundaries, concurrency)
- [ ] Use async/await for all I/O operations
- [ ] Implement proper error handling (exceptions, Result pattern)

### Testing & Quality Assurance
- [ ] Write tests first (TDD with xUnit/NUnit)
- [ ] Use FluentAssertions for readable test assertions
- [ ] Mock external dependencies (Moq/NSubstitute)
- [ ] Integration tests with WebApplicationFactory
- [ ] Test edge cases and error scenarios

### Observability & Monitoring
- [ ] Log with context (Serilog structured logging)
- [ ] Use Application Insights for APM and distributed tracing
- [ ] Implement health checks for dependencies
- [ ] Track custom metrics and events
- [ ] Use correlation IDs for request tracing

### API Design
- [ ] Design APIs as products (versioning with ApiVersioning)
- [ ] Use OpenAPI/Swagger for documentation
- [ ] Implement consistent error responses (ProblemDetails)
- [ ] Use DTOs for API contracts (AutoMapper/Mapster)
- [ ] Validate inputs (FluentValidation)

### Database & Persistence
- [ ] Plan database schema evolution (EF Core migrations)
- [ ] Optimize queries (avoid N+1, use projections)
- [ ] Use appropriate indexes (EF Core migrations)
- [ ] Consider read replicas for read-heavy workloads
- [ ] Implement repository pattern for testability

### Collaboration
- [ ] Give constructive code reviews
- [ ] Document complex business logic
- [ ] Use meaningful names (ubiquitous language)
- [ ] Share knowledge through pair programming
- [ ] Contribute to shared libraries and patterns

## Resources

### Architecture & Design
- **Clean Architecture (.NET):** https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html
- **Domain-Driven Design:** https://martinfowler.com/bliki/DomainDrivenDesign.html
- **CQRS Pattern:** https://learn.microsoft.com/azure/architecture/patterns/cqrs
- **MediatR:** https://github.com/jbogard/MediatR

### Resilience & Patterns
- **Polly (.NET Resilience):** https://github.com/App-vNext/Polly
- **Resilience Patterns:** https://learn.microsoft.com/azure/architecture/patterns/
- **CAP Theorem:** https://en.wikipedia.org/wiki/CAP_theorem

### Code Quality
- **SOLID Principles:** https://en.wikipedia.org/wiki/SOLID
- **.NET Coding Conventions:** https://learn.microsoft.com/dotnet/csharp/fundamentals/coding-style/coding-conventions
- **Nullable Reference Types:** https://learn.microsoft.com/dotnet/csharp/nullable-references

### Testing
- **xUnit:** https://xunit.net/
- **FluentAssertions:** https://fluentassertions.com/
- **Moq:** https://github.com/moq/moq4

### Observability
- **Serilog:** https://serilog.net/
- **Application Insights:** https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
- **OpenTelemetry .NET:** https://opentelemetry.io/docs/instrumentation/net/

### Entity Framework Core
- **EF Core Performance:** https://learn.microsoft.com/ef/core/performance/
- **EF Core Migrations:** https://learn.microsoft.com/ef/core/managing-schemas/migrations/
