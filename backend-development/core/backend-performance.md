# Backend Performance & Scalability

Performance optimization strategies, caching patterns, and scalability best practices for C#/.NET backend development (2025).

## Database Performance

### Query Optimization

#### Indexing Strategies

**Impact:** 30% disk I/O reduction, 10-100x query speedup

```sql
-- SQL Server: Create index on frequently queried columns
CREATE NONCLUSTERED INDEX idx_users_email ON Users(Email);
CREATE NONCLUSTERED INDEX idx_orders_user_id ON Orders(UserId);

-- Composite index for multi-column queries
CREATE NONCLUSTERED INDEX idx_orders_user_date 
ON Orders(UserId, CreatedAt DESC);

-- Filtered index for filtered queries (SQL Server)
CREATE NONCLUSTERED INDEX idx_active_users 
ON Users(Email) WHERE IsActive = 1;

-- Include columns for covering indexes
CREATE NONCLUSTERED INDEX idx_orders_user_date_covering
ON Orders(UserId, CreatedAt DESC)
INCLUDE (TotalAmount, Status);

-- Analyze query performance
SET STATISTICS IO ON;
SELECT * FROM Orders
WHERE UserId = 123 AND CreatedAt > '2025-01-01';
```

**Index Types (SQL Server):**
- **Clustered** - Physical order, one per table (usually PK)
- **Non-clustered** - Logical order, multiple per table
- **Columnstore** - Analytics workloads, column-based storage
- **Filtered** - Partial indexes for filtered queries
- **Covering** - Include columns to avoid key lookups

**Entity Framework Core Migrations:**
```csharp
// In DbContext OnModelCreating or migration
modelBuilder.Entity<User>()
    .HasIndex(u => u.Email)
    .HasDatabaseName("idx_users_email");

modelBuilder.Entity<Order>()
    .HasIndex(o => new { o.UserId, o.CreatedAt })
    .HasDatabaseName("idx_orders_user_date");
```

**When NOT to Index:**
- Small tables (<1000 rows)
- Frequently updated columns
- Low-cardinality columns (e.g., boolean with 2 values)

### Connection Pooling

**Impact:** 5-10x performance improvement

**Entity Framework Core** (Automatic Connection Pooling)
```csharp
// EF Core automatically uses connection pooling
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions =>
        {
            sqlOptions.MaxBatchSize(100);
            sqlOptions.CommandTimeout(30);
        }));

// Connection string with pool size
"Server=localhost;Database=MyDb;Trusted_Connection=True;Max Pool Size=100;Min Pool Size=5;Connection Timeout=30;"
```

**Dapper with Connection Pooling**
```csharp
// Dapper uses underlying connection pool
public class UserRepository
{
    private readonly IDbConnection _connection;

    public UserRepository(IDbConnection connection)
    {
        _connection = connection; // Pooled connection from DI
    }

    public async Task<User> GetByIdAsync(Guid id)
    {
        return await _connection.QueryFirstOrDefaultAsync<User>(
            "SELECT * FROM Users WHERE Id = @Id",
            new { Id = id });
    }
}

// Register pooled connection
builder.Services.AddScoped<IDbConnection>(sp =>
{
    var connection = new SqlConnection(
        builder.Configuration.GetConnectionString("DefaultConnection"));
    connection.Open();
    return connection;
});
```

**Recommended Pool Sizes:**
- **Web servers:** `connections = (core_count * 2) + effective_spindle_count`
- **Typical:** 20-30 connections per app instance
- **SQL Server:** Default max pool size is 100
- **Monitor:** Connection saturation in production (Application Insights)

### N+1 Query Problem

**Bad: N+1 queries with EF Core**
```csharp
// Fetches 1 query for posts, then N queries for authors
var posts = await _context.Posts.ToListAsync();
foreach (var post in posts)
{
    post.Author = await _context.Users.FindAsync(post.AuthorId); // N queries!
}
```

**Good: Eager loading with Include**
```csharp
// Single query with JOIN using Include
var posts = await _context.Posts
    .Include(p => p.Author)
    .ToListAsync();

// Multiple levels with ThenInclude
var posts = await _context.Posts
    .Include(p => p.Author)
        .ThenInclude(a => a.Profile)
    .Include(p => p.Comments)
    .ToListAsync();
```

**Good: Projection (Select only needed data)**
```csharp
// Project to DTO - only fetches needed columns
var posts = await _context.Posts
    .Select(p => new PostDto
    {
        Id = p.Id,
        Title = p.Title,
        AuthorName = p.Author.Name,
        CommentCount = p.Comments.Count
    })
    .ToListAsync();
```

**Good: Explicit Loading (when needed)**
```csharp
var post = await _context.Posts.FindAsync(postId);
await _context.Entry(post)
    .Collection(p => p.Comments)
    .LoadAsync();
```

**Good: Split Queries (EF Core 5+)**
```csharp
// Multiple queries but optimized
var posts = await _context.Posts
    .Include(p => p.Author)
    .AsSplitQuery() // Prevents Cartesian explosion
    .ToListAsync();
```

**Good: Compiled Queries (EF Core)**
```csharp
// Define compiled query once (reusable, faster)
private static readonly Func<AppDbContext, Guid, Task<User?>> GetUserByIdQuery =
    EF.CompileAsyncQuery((AppDbContext context, Guid id) =>
        context.Users.FirstOrDefault(u => u.Id == id));

// Use compiled query (no LINQ compilation overhead)
public async Task<User?> GetUserAsync(Guid id)
{
    return await GetUserByIdQuery(_context, id);
}

// Compiled query for complex scenarios
private static readonly Func<AppDbContext, string, IAsyncEnumerable<User>> GetUsersByEmailQuery =
    EF.CompileAsyncQuery((AppDbContext context, string email) =>
        context.Users.Where(u => u.Email.Contains(email)));

public async IAsyncEnumerable<User> GetUsersByEmailAsync(string email)
{
    await foreach (var user in GetUsersByEmailQuery(_context, email))
    {
        yield return user;
    }
}
```

## Caching Strategies

### Redis Caching

**Impact:** 90% DB load reduction, 10-100x faster response

#### Setup with StackExchange.Redis

```csharp
// Program.cs - Configure Redis
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "MyApp:";
});

// Or direct connection
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    ConnectionMultiplexer.Connect(
        builder.Configuration.GetConnectionString("Redis")));
```

#### Cache-Aside Pattern (Lazy Loading)

```csharp
public class UserService
{
    private readonly IDistributedCache _cache;
    private readonly AppDbContext _context;
    private readonly ILogger<UserService> _logger;

    public async Task<User?> GetUserAsync(Guid userId)
    {
        // Try cache first
        var cacheKey = $"user:{userId}";
        var cached = await _cache.GetStringAsync(cacheKey);
        
        if (cached != null)
        {
            _logger.LogInformation("Cache hit for user {UserId}", userId);
            return JsonSerializer.Deserialize<User>(cached);
        }

        // Cache miss - fetch from DB
        var user = await _context.Users.FindAsync(userId);
        
        if (user != null)
        {
            // Store in cache (TTL: 1 hour)
            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
            };
            await _cache.SetStringAsync(
                cacheKey, 
                JsonSerializer.Serialize(user), 
                options);
        }

        return user;
    }
}
```

#### Write-Through Pattern

```csharp
public async Task<User> UpdateUserAsync(Guid userId, UpdateUserDto dto)
{
    // Update database
    var user = await _context.Users.FindAsync(userId);
    if (user == null) throw new NotFoundException();

    user.Name = dto.Name;
    user.Email = dto.Email;
    await _context.SaveChangesAsync();

    // Update cache immediately
    var cacheKey = $"user:{userId}";
    var options = new DistributedCacheEntryOptions
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
    };
    await _cache.SetStringAsync(
        cacheKey, 
        JsonSerializer.Serialize(user), 
        options);

    return user;
}
```

#### Cache Invalidation

```csharp
public async Task DeleteUserAsync(Guid userId)
{
    // Delete from database
    var user = await _context.Users.FindAsync(userId);
    if (user != null)
    {
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
    }

    // Invalidate cache
    var cacheKey = $"user:{userId}";
    await _cache.RemoveAsync(cacheKey);
    
    // Invalidate related caches
    await _cache.RemoveAsync($"user:{userId}:posts");
}

// Pattern-based invalidation (use SCAN, not KEYS in production)
public async Task InvalidateUserCachesAsync(Guid userId)
{
    var connection = _cache.GetConnection();
    var server = connection.GetServer(connection.GetEndPoints().First());
    var pattern = $"user:{userId}:*";
    
    await foreach (var key in server.KeysAsync(pattern: pattern))
    {
        await _cache.RemoveAsync(key.ToString());
    }
}
```

#### IMemoryCache for In-Process Caching

```csharp
// For single-instance scenarios
builder.Services.AddMemoryCache();

public class UserService
{
    private readonly IMemoryCache _cache;
    
    public async Task<User?> GetUserAsync(Guid userId)
    {
        var cacheKey = $"user:{userId}";
        
        if (_cache.TryGetValue(cacheKey, out User? cachedUser))
        {
            return cachedUser;
        }

        var user = await _context.Users.FindAsync(userId);
        
        if (user != null)
        {
            _cache.Set(cacheKey, user, TimeSpan.FromHours(1));
        }
        
        return user;
    }
}
```

### Cache Layers

```
Client
  → CDN Cache (static assets, 50%+ latency reduction)
  → API Gateway Cache (public endpoints)
  → Application Cache (Redis)
  → Database Query Cache
  → Database
```

### Cache Best Practices

1. **Cache frequently accessed data** - User profiles, config, product catalogs
2. **Set appropriate TTL** - Balance freshness vs performance
3. **Invalidate on write** - Keep cache consistent
4. **Use cache keys wisely** - `resource:id:attribute` pattern
5. **Monitor hit rates** - Target >80% hit rate

## Load Balancing

### Algorithms

**Round Robin** - Distribute evenly across servers
```nginx
upstream backend {
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com;
}
```

**Least Connections** - Route to server with fewest connections
```nginx
upstream backend {
    least_conn;
    server backend1.example.com;
    server backend2.example.com;
}
```

**IP Hash** - Same client → same server (session affinity)
```nginx
upstream backend {
    ip_hash;
    server backend1.example.com;
    server backend2.example.com;
}
```

### Health Checks

**ASP.NET Core Health Checks**
```csharp
// Program.cs - Configure health checks
builder.Services.AddHealthChecks()
    .AddSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        name: "database",
        timeout: TimeSpan.FromSeconds(3))
    .AddRedis(
        builder.Configuration.GetConnectionString("Redis"),
        name: "redis")
    .AddCheck<CustomHealthCheck>("custom");

// Map health check endpoints
app.MapHealthChecks("/health");
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false // Liveness checks only
});

// Custom health check
public class CustomHealthCheck : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, 
        CancellationToken cancellationToken = default)
    {
        // Check external dependencies
        var isHealthy = await CheckExternalServiceAsync();
        
        return isHealthy
            ? HealthCheckResult.Healthy("External service is available")
            : HealthCheckResult.Unhealthy("External service is unavailable");
    }
}
```

**Response Format**
```json
{
  "status": "Healthy",
  "totalDuration": "00:00:00.1000000",
  "entries": {
    "database": {
      "status": "Healthy",
      "duration": "00:00:00.0500000"
    },
    "redis": {
      "status": "Healthy",
      "duration": "00:00:00.0300000"
    }
  }
}
```

## Asynchronous Processing

### Message Queues for Long-Running Tasks

**Hangfire (Background Jobs)**
```csharp
// Program.cs - Configure Hangfire
builder.Services.AddHangfire(config =>
    config.UseSqlServerStorage(
        builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddHangfireServer();

app.UseHangfireDashboard(); // Dashboard at /hangfire

// Fire-and-forget job
BackgroundJob.Enqueue<IEmailService>(x => 
    x.SendWelcomeEmailAsync(user.Email));

// Delayed job
BackgroundJob.Schedule<IEmailService>(x => 
    x.SendReminderEmailAsync(user.Email), 
    TimeSpan.FromHours(24));

// Recurring job
RecurringJob.AddOrUpdate<IReportService>(
    "daily-report",
    x => x.GenerateDailyReportAsync(),
    Cron.Daily);
```

**Azure Service Bus**
```csharp
// Producer - Send message
public class EmailService
{
    private readonly ServiceBusClient _client;
    
    public async Task SendWelcomeEmailAsync(string email)
    {
        var sender = _client.CreateSender("email-queue");
        var message = new ServiceBusMessage(JsonSerializer.Serialize(new
        {
            Email = email,
            Type = "welcome"
        }));
        
        await sender.SendMessageAsync(message);
    }
}

// Consumer - Process messages
public class EmailProcessor : BackgroundService
{
    private readonly ServiceBusProcessor _processor;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _processor.ProcessMessageAsync += ProcessEmailAsync;
        _processor.ProcessErrorAsync += ProcessErrorAsync;
        
        await _processor.StartProcessingAsync(stoppingToken);
    }
    
    private async Task ProcessEmailAsync(ProcessMessageEventArgs args)
    {
        var emailData = JsonSerializer.Deserialize<EmailData>(
            args.Message.Body.ToString());
        
        await _emailService.SendAsync(emailData.Email);
        await args.CompleteMessageAsync(args.Message);
    }
}
```

**Use Cases:**
- Email sending
- Image/video processing
- Report generation
- Data export
- Webhook delivery
- Long-running operations

## Response Compression

**Impact:** 60-80% size reduction, faster page loads

```csharp
// Program.cs - Enable response compression
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
    options.Providers.Add<BrotliCompressionProvider>();
    options.Providers.Add<GzipCompressionProvider>();
    options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[]
    {
        "application/json",
        "application/xml",
        "text/css",
        "application/javascript"
    });
});

builder.Services.Configure<BrotliCompressionProviderOptions>(options =>
{
    options.Level = CompressionLevel.Optimal;
});

builder.Services.Configure<GzipCompressionProviderOptions>(options =>
{
    options.Level = CompressionLevel.Optimal;
});

app.UseResponseCompression();
```

## CDN (Content Delivery Network)

**Impact:** 50%+ latency reduction for global users

### Response Caching in ASP.NET Core

```csharp
// Program.cs - Configure response caching
builder.Services.AddResponseCaching();
builder.Services.AddOutputCache(options =>
{
    options.AddBasePolicy(builder => builder
        .Expire(TimeSpan.FromMinutes(10))
        .Cache());
});

app.UseResponseCaching();
app.UseOutputCache();

// Controller-level caching
[ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
public class ProductsController : ControllerBase
{
    [HttpGet]
    [OutputCache(Duration = 3600)]
    public async Task<IActionResult> GetProducts()
    {
        var products = await _productService.GetAllAsync();
        return Ok(products);
    }
}

// Action-level caching
[HttpGet("{id}")]
[ResponseCache(
    Duration = 3600,
    VaryByQueryKeys = new[] { "id" },
    Location = ResponseCacheLocation.Any)]
public async Task<IActionResult> GetProduct(int id)
{
    var product = await _productService.GetByIdAsync(id);
    return Ok(product);
}

// Custom cache policy
[HttpGet("user-specific")]
[ResponseCache(
    Duration = 0,
    Location = ResponseCacheLocation.None,
    NoStore = true)]
public async Task<IActionResult> GetUserData()
{
    // User-specific data - no caching
    return Ok(await _userService.GetCurrentUserAsync());
}
```

### Static Files Caching

```csharp
// Program.cs - Static files with caching
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers.Append(
            "Cache-Control", 
            "public,max-age=31536000,immutable");
    }
});
```

**CDN Providers:**
- **Azure CDN** - Integrated with Azure services
- **Cloudflare** - Generous free tier, global coverage
- **AWS CloudFront** - AWS integration
- **Fastly** - Real-time purging

## Horizontal vs Vertical Scaling

### Horizontal Scaling (Scale Out)

**Pros:**
- Better fault tolerance
- Unlimited scaling potential
- Cost-effective (commodity hardware)

**Cons:**
- Complex architecture
- Data consistency challenges
- Network overhead

**When to use:** High traffic, need redundancy, stateless applications

### Vertical Scaling (Scale Up)

**Pros:**
- Simple architecture
- No code changes needed
- Easier data consistency

**Cons:**
- Hardware limits
- Single point of failure
- Expensive at high end

**When to use:** Monolithic apps, rapid scaling needed, data consistency critical

## Database Scaling Patterns

### Read Replicas

```
Primary (Write) → Replica 1 (Read)
               → Replica 2 (Read)
               → Replica 3 (Read)
```

**Implementation with EF Core:**
```csharp
// Configure multiple DbContext instances
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(primaryConnectionString), 
    ServiceLifetime.Scoped);

builder.Services.AddDbContext<ReadOnlyDbContext>(options =>
    options.UseSqlServer(replicaConnectionString), 
    ServiceLifetime.Scoped);

// Write to primary
public class UserService
{
    private readonly AppDbContext _writeContext;
    private readonly ReadOnlyDbContext _readContext;
    
    public async Task<User> CreateUserAsync(CreateUserDto dto)
    {
        var user = new User { /* ... */ };
        _writeContext.Users.Add(user);
        await _writeContext.SaveChangesAsync();
        return user;
    }
    
    public async Task<List<User>> GetAllUsersAsync()
    {
        // Read from replica
        return await _readContext.Users.ToListAsync();
    }
}
```

**SQL Server Always On Availability Groups:**
```csharp
// Connection string with ApplicationIntent=ReadOnly
var readOnlyConnection = "Server=replica-server;Database=MyDb;ApplicationIntent=ReadOnly;";
```

**Use Cases:**
- Read-heavy workloads (90%+ reads)
- Analytics queries
- Reporting dashboards
- Geographic distribution

### Database Sharding

**Horizontal Partitioning** - Split data across databases

```csharp
// Shard by user ID
public class ShardSelector
{
    private const int SHARD_COUNT = 4;
    
    public int GetShardId(Guid userId)
    {
        return Math.Abs(userId.GetHashCode()) % SHARD_COUNT;
    }
}

public class UserRepository
{
    private readonly ShardSelector _shardSelector;
    private readonly Dictionary<int, AppDbContext> _shards;
    
    public async Task<User?> GetUserAsync(Guid userId)
    {
        var shardId = _shardSelector.GetShardId(userId);
        var context = _shards[shardId];
        return await context.Users.FindAsync(userId);
    }
}

// Configure multiple DbContexts for shards
builder.Services.AddScoped<ShardSelector>();
builder.Services.AddScoped<Func<int, AppDbContext>>(sp =>
{
    var shards = new Dictionary<int, AppDbContext>();
    for (int i = 0; i < 4; i++)
    {
        var connectionString = $"Server=shard-{i};Database=MyDb;";
        shards[i] = new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>()
                .UseSqlServer(connectionString)
                .Options);
    }
    return shardId => shards[shardId];
});
```

**Sharding Strategies:**
- **Range-based:** Users 1-1M → Shard 1, 1M-2M → Shard 2
- **Hash-based:** Hash(userId) % shard_count
- **Geographic:** EU users → EU shard, US users → US shard
- **Entity-based:** Users → Shard 1, Orders → Shard 2

**SQL Server Table Partitioning:**
```sql
-- Partition by date range
CREATE PARTITION FUNCTION OrderDateRange (datetime)
AS RANGE RIGHT FOR VALUES ('2025-01-01', '2025-02-01', '2025-03-01');

CREATE PARTITION SCHEME OrderDateScheme
AS PARTITION OrderDateRange
TO (fg1, fg2, fg3, fg4);
```

## Optimizely-Specific Performance Optimizations

### Content Caching

**Optimizely Built-in Caching:**
```csharp
// Optimizely automatically caches content, but configure properly
public class OptimizedContentService
{
    private readonly IContentLoader _contentLoader;
    private readonly IContentCache _contentCache;

    public OptimizedContentService(IContentLoader contentLoader, IContentCache contentCache)
    {
        _contentLoader = contentLoader;
        _contentCache = contentCache;
    }

    // Use GetChildren with caching
    public IEnumerable<PageData> GetCachedPages(ContentReference parent)
    {
        // Optimizely caches content automatically
        return _contentLoader.GetChildren<PageData>(parent);
    }

    // Clear cache on content publish
    public void OnContentPublished(object sender, ContentEventArgs e)
    {
        _contentCache.Remove(e.ContentLink);
    }
}
```

### Content Delivery API Performance

**Headless Optimizely with Caching:**
```csharp
// Use Optimizely Content Delivery API with response caching
[ApiController]
[Route("api/content")]
public class ContentApiController : ControllerBase
{
    private readonly IContentLoader _contentLoader;

    [HttpGet("{id}")]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
    public IActionResult GetContent(int id)
    {
        var content = _contentLoader.Get<PageData>(new ContentReference(id));
        if (content == null) return NotFound();
        
        return Ok(new
        {
            Id = content.ContentLink.ID,
            Name = content.Name,
            Url = content.LinkURL
        });
    }
}
```

### Optimizely Commerce Performance

**Product Catalog Caching:**
```csharp
public class ProductService
{
    private readonly IContentLoader _contentLoader;
    private readonly IDistributedCache _cache;

    public async Task<ProductContent> GetProductAsync(int productId)
    {
        var cacheKey = $"product:{productId}";
        var cached = await _cache.GetStringAsync(cacheKey);
        
        if (cached != null)
        {
            return JsonSerializer.Deserialize<ProductContent>(cached);
        }

        var product = _contentLoader.Get<ProductContent>(new ContentReference(productId));
        
        if (product != null)
        {
            await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(product), 
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
                });
        }

        return product;
    }
}
```

**Best Practices for Optimizely:**
- Leverage Optimizely's built-in content caching
- Use Content Delivery API for headless scenarios
- Cache product catalogs and pricing
- Use read replicas for content queries
- Implement CDN for static assets and media
- Use Optimizely's output cache for rendered pages

## Performance Monitoring

### Key Metrics

**Application:**
- Response time (p50, p95, p99)
- Throughput (requests/second)
- Error rate
- CPU/memory usage

**Database:**
- Query execution time
- Connection pool saturation
- Cache hit rate
- Slow query log

**Tools:**
- **Application Insights** - Azure monitoring, APM, distributed tracing
- **Prometheus + Grafana** - Metrics and dashboards
- **New Relic / Datadog** - APM for .NET
- **Sentry** - Error tracking for .NET
- **OpenTelemetry** - Distributed tracing (.NET support)
- **PerfView / dotMemory** - Profiling tools
- **MiniProfiler** - Real-time performance profiling
- **dotnet-counters** - Performance counter monitoring
- **dotnet-trace** - Event tracing for .NET
- **BenchmarkDotNet** - Micro-benchmarking framework

**.NET Performance Tools:**
```bash
# Monitor performance counters
dotnet-counters monitor --process-id <pid> System.Runtime

# Collect trace
dotnet-trace collect --process-id <pid> --providers Microsoft-DotNETCore-SampleProfiler

# Profile with dotMemory
# Use JetBrains dotMemory for memory profiling
```

## Performance Optimization Checklist

### Database
- [ ] Indexes on frequently queried columns
- [ ] Connection pooling configured
- [ ] N+1 queries eliminated
- [ ] Slow query log monitored
- [ ] Query execution plans analyzed

### Caching
- [ ] Redis cache for hot data
- [ ] Cache TTL configured appropriately
- [ ] Cache invalidation on writes
- [ ] CDN for static assets
- [ ] >80% cache hit rate achieved

### Application
- [ ] Async processing for long tasks
- [ ] Response compression enabled (gzip/brotli)
- [ ] Load balancing configured
- [ ] Health checks implemented
- [ ] Resource limits set (CPU, memory)
- [ ] Compiled queries for frequently executed queries
- [ ] Response caching configured (OutputCache)
- [ ] Minimal APIs for high-performance endpoints

### Monitoring
- [ ] Application Insights configured (Azure)
- [ ] APM tool configured (Application Insights/New Relic/Datadog)
- [ ] Error tracking (Application Insights/Sentry)
- [ ] Performance dashboards (Application Insights/Grafana)
- [ ] Alerting on key metrics
- [ ] Distributed tracing for microservices (OpenTelemetry)
- [ ] MiniProfiler for development profiling

## Common Performance Pitfalls

1. **No caching** - Repeatedly querying same data (use Redis/IMemoryCache)
2. **Missing indexes** - Full table scans (add EF Core indexes)
3. **N+1 queries** - Fetching related data in loops (use Include/ThenInclude)
4. **Synchronous processing** - Blocking on long tasks (use async/await, Hangfire)
5. **No connection pooling** - EF Core pools by default, but monitor saturation
6. **Unbounded queries** - No Take()/Skip() on large tables
7. **No CDN** - Serving static assets from origin (use Azure CDN/Cloudflare)
8. **Not using async/await** - Blocking I/O operations
9. **Over-fetching data** - Loading entire entities instead of projections
10. **Not using compiled queries** - Recompiling LINQ queries repeatedly (use EF.CompileAsyncQuery)
11. **No response compression** - Not compressing responses (enable Brotli/Gzip)
12. **Synchronous I/O in async methods** - Using .Result or .Wait() (use async/await throughout)
13. **Not using Minimal APIs** - Overhead of MVC for simple endpoints (use Minimal APIs for performance)
14. **Optimizely-specific: Not leveraging content caching** - Optimizely has built-in content caching
15. **Optimizely-specific: Not using content delivery API** - Use Optimizely Content Delivery API for headless scenarios

## Resources

### .NET Performance
- **ASP.NET Core Performance:** https://learn.microsoft.com/aspnet/core/performance/
- **Entity Framework Core Performance:** https://learn.microsoft.com/ef/core/performance/
- **.NET Performance Best Practices:** https://learn.microsoft.com/dotnet/fundamentals/performance/

### SQL Server
- **SQL Server Performance:** https://learn.microsoft.com/sql/relational-databases/performance/
- **Query Tuning:** https://learn.microsoft.com/sql/relational-databases/performance/query-tuning/

### Caching & Messaging
- **Redis Best Practices:** https://redis.io/docs/management/optimization/
- **StackExchange.Redis:** https://github.com/StackExchange/StackExchange.Redis
- **Azure Service Bus:** https://learn.microsoft.com/azure/service-bus-messaging/
- **Hangfire:** https://www.hangfire.io/

### Monitoring
- **Application Insights:** https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
- **OpenTelemetry .NET:** https://opentelemetry.io/docs/instrumentation/net/

### Optimizely Performance
- **Optimizely Performance Best Practices:** https://docs.developers.optimizely.com/content-management-system/docs/performance
- **Optimizely Content Delivery API:** https://docs.developers.optimizely.com/content-management-system/docs/content-delivery-api

### General
- **Web Performance:** https://web.dev/performance/
- **Database Indexing:** https://use-the-index-luke.com/
- **.NET Performance Blog:** https://devblogs.microsoft.com/dotnet/tag/performance/