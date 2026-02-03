# Backend Architecture Patterns

Microservices, event-driven architecture, and scalability patterns for C#/.NET Core, ASP.NET, and Optimizely (2025).

## Monolith vs Microservices

### Monolithic Architecture

```
┌─────────────────────────────────┐
│      Single Application         │
│                                 │
│  ┌─────────┐  ┌──────────┐    │
│  │  Users  │  │ Products │    │
│  └─────────┘  └──────────┘    │
│  ┌─────────┐  ┌──────────┐    │
│  │ Orders  │  │ Payments │    │
│  └─────────┘  └──────────┘    │
│                                 │
│     Single Database             │
└─────────────────────────────────┘
```

**Pros:**
- Simple to develop and deploy
- Easy local testing
- Single codebase
- Strong consistency (ACID transactions)

**Cons:**
- Tight coupling
- Scaling limitations
- Deployment risk (all-or-nothing)
- Tech stack lock-in

**When to Use:** Startups, MVPs, small teams, unclear domain boundaries

### Microservices Architecture

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  User    │   │ Product  │   │  Order   │   │ Payment  │
│ Service  │   │ Service  │   │ Service  │   │ Service  │
└────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
     │              │              │              │
  ┌──▼──┐        ┌──▼──┐        ┌──▼──┐        ┌──▼──┐
  │  DB │        │  DB │        │  DB │        │  DB │
  └─────┘        └─────┘        └─────┘        └─────┘
```

**Pros:**
- Independent deployment
- Technology flexibility
- Fault isolation
- Easier scaling (scale services independently)

**Cons:**
- Complex deployment
- Distributed system challenges (network latency, partial failures)
- Data consistency (eventual consistency)
- Operational overhead

**When to Use:** Large teams, clear domain boundaries, need independent scaling, tech diversity

## Microservices Patterns

### Database per Service Pattern

**Concept:** Each service owns its database

```
User Service → User DB (SQL Server)
Product Service → Product DB (SQL Server / MongoDB)
Order Service → Order DB (SQL Server)
```

**Benefits:**
- Service independence
- Technology choice per service
- Fault isolation

**Challenges:**
- No joins across services
- Distributed transactions
- Data duplication

### API Gateway Pattern

```
Client
  │
  ▼
┌─────────────────┐
│  API Gateway    │  - Authentication
│  (Ocelot/YARP/  │  - Rate limiting
│   Azure APIM)   │  - Request routing
└────────┬────────┘  - Load balancing
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
  User    Product   Order   Payment
 Service  Service  Service  Service
```

**Responsibilities:**
- Request routing
- Authentication/authorization
- Rate limiting
- Request/response transformation
- Caching
- Load balancing

**Implementation (Ocelot):**
```json
{
  "Routes": [
    {
      "DownstreamPathTemplate": "/api/users/{everything}",
      "DownstreamScheme": "https",
      "DownstreamHostAndPorts": [
        {
          "Host": "user-service",
          "Port": 5001
        }
      ],
      "UpstreamPathTemplate": "/api/users/{everything}",
      "UpstreamHttpMethod": [ "GET", "POST", "PUT", "DELETE" ],
      "RateLimitOptions": {
        "EnableRateLimiting": true,
        "Period": "1m",
        "Limit": 100
      },
      "AuthenticationOptions": {
        "AuthenticationProviderKey": "Bearer"
      }
    }
  ],
  "GlobalConfiguration": {
    "BaseUrl": "https://api.example.com"
  }
}
```

**Implementation (YARP - Yet Another Reverse Proxy):**
```csharp
// Program.cs
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

// appsettings.json
{
  "ReverseProxy": {
    "Routes": {
      "user-route": {
        "ClusterId": "user-cluster",
        "Match": {
          "Path": "/api/users/{**catch-all}"
        }
      }
    },
    "Clusters": {
      "user-cluster": {
        "Destinations": {
          "destination1": {
            "Address": "https://user-service:5001"
          }
        }
      }
    }
  }
}
```

### Service Discovery

**Concept:** Services find each other dynamically

**Using Consul.NET:**
```csharp
using Consul;

// Register service
var consulClient = new ConsulClient();

var registration = new AgentServiceRegistration
{
    ID = "user-service-1",
    Name = "user-service",
    Address = "192.168.1.10",
    Port = 5001,
    Check = new AgentServiceCheck
    {
        HTTP = "https://192.168.1.10:5001/health",
        Interval = TimeSpan.FromSeconds(10)
    }
};

await consulClient.Agent.ServiceRegister(registration);

// Discover service
var services = await consulClient.Catalog.Service("product-service");
var productServiceUrl = $"https://{services.Response[0].ServiceAddress}:{services.Response[0].ServicePort}";
```

**Using Steeltoe (Spring Cloud for .NET):**
```csharp
// Program.cs
builder.Services.AddServiceDiscovery(options =>
{
    options.UseConsul(options =>
    {
        options.Host = "localhost";
        options.Port = 8500;
    });
});

// Service registration
builder.Services.AddHealthChecks();
builder.Services.AddSingleton<IHostedService, ConsulHostedService>();
```

**Using Azure Service Discovery:**
```csharp
// Azure Service Fabric or Azure Container Apps
// Services automatically discover each other via service names
var httpClient = new HttpClient();
var response = await httpClient.GetAsync("http://product-service/api/products");
```

### Circuit Breaker Pattern

**Concept:** Stop calling failing service, prevent cascade failures

**Using Polly (Standard .NET Resilience Library):**
```csharp
using Polly;
using Polly.CircuitBreaker;

// Circuit breaker policy
var circuitBreakerPolicy = Policy
    .Handle<HttpRequestException>()
    .Or<TaskCanceledException>()
    .CircuitBreakerAsync(
        handledEventsAllowedBeforeBreaking: 5,
        durationOfBreak: TimeSpan.FromSeconds(30),
        onBreak: (exception, duration) =>
        {
            _logger.LogWarning($"Circuit breaker opened for {duration}");
        },
        onReset: () =>
        {
            _logger.LogInformation("Circuit breaker reset");
        }
    );

// Fallback policy
var fallbackPolicy = Policy<string>
    .Handle<BrokenCircuitException>()
    .Or<HttpRequestException>()
    .FallbackAsync("fallback-response", onFallbackAsync: (result) =>
    {
        _logger.LogWarning("Using fallback response");
        return Task.CompletedTask;
    });

// Combined policy
var policy = Policy.WrapAsync(fallbackPolicy, circuitBreakerPolicy);

// Usage
var result = await policy.ExecuteAsync(async () =>
{
    var response = await _httpClient.GetAsync("https://external-service/api/data");
    return await response.Content.ReadAsStringAsync();
});
```

**Using Polly with HttpClientFactory:**
```csharp
// Program.cs
builder.Services.AddHttpClient<IProductService, ProductService>()
    .AddPolicyHandler(GetRetryPolicy())
    .AddPolicyHandler(GetCircuitBreakerPolicy());

static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy()
{
    return HttpPolicyExtensions
        .HandleTransientHttpError()
        .CircuitBreakerAsync(
            handledEventsAllowedBeforeBreaking: 5,
            durationOfBreak: TimeSpan.FromSeconds(30)
        );
}
```

**States:**
- **Closed:** Normal operation, requests go through
- **Open:** Too many failures, requests fail immediately
- **Half-Open:** Testing if service recovered

### Saga Pattern (Distributed Transactions)

**Choreography-Based Saga:**
```
Order Service: Create Order → Publish "OrderCreated"
                                    ↓
Payment Service: Reserve Payment → Publish "PaymentReserved"
                                    ↓
Inventory Service: Reserve Stock → Publish "StockReserved"
                                    ↓
Shipping Service: Create Shipment → Publish "ShipmentCreated"

If any step fails → Compensating transactions (rollback)
```

**Orchestration-Based Saga:**
```
Saga Orchestrator
    ↓ Create Order
Order Service
    ↓ Reserve Payment
Payment Service
    ↓ Reserve Stock
Inventory Service
    ↓ Create Shipment
Shipping Service
```

## Event-Driven Architecture

**Impact:** 85% organizations recognize business value

### Event Sourcing

**Concept:** Store events, not current state

```csharp
// Traditional: Store current state
public class Account
{
    public string UserId { get; set; }
    public decimal Balance { get; set; }
}

// Event Sourcing: Store events
public abstract class DomainEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string UserId { get; set; }
}

public class AccountCreatedEvent : DomainEvent
{
    public string AccountId { get; set; }
}

public class MoneyDepositedEvent : DomainEvent
{
    public decimal Amount { get; set; }
}

public class MoneyWithdrawnEvent : DomainEvent
{
    public decimal Amount { get; set; }
}

// Reconstruct state by replaying events
public class AccountAggregate
{
    public string UserId { get; private set; }
    public decimal Balance { get; private set; }

    public void Apply(AccountCreatedEvent evt)
    {
        UserId = evt.UserId;
        Balance = 0;
    }

    public void Apply(MoneyDepositedEvent evt)
    {
        Balance += evt.Amount;
    }

    public void Apply(MoneyWithdrawnEvent evt)
    {
        Balance -= evt.Amount;
    }

    public static AccountAggregate Replay(IEnumerable<DomainEvent> events)
    {
        var account = new AccountAggregate();
        foreach (var evt in events)
        {
            account.Apply((dynamic)evt);
        }
        return account;
    }
}
```

**Using EventStore (Event Sourcing Database):**
```csharp
using EventStore.Client;

var client = new EventStoreClient(EventStoreClientSettings.Create("esdb://localhost:2113"));

// Append events
var eventData = new EventData(
    Uuid.NewUuid(),
    "AccountCreated",
    JsonSerializer.SerializeToUtf8Bytes(new AccountCreatedEvent { UserId = "123" })
);

await client.AppendToStreamAsync(
    "account-123",
    StreamState.Any,
    new[] { eventData }
);

// Read events
var events = await client.ReadStreamAsync(
    Direction.Forwards,
    "account-123",
    StreamPosition.Start
).ToListAsync();
```

**Benefits:**
- Complete audit trail
- Temporal queries (state at any point in time)
- Event replay for debugging
- Flexible projections

### Message Broker Patterns

**Kafka (Event Streaming) with Confluent.Kafka:**
```csharp
using Confluent.Kafka;

// Producer
var config = new ProducerConfig
{
    BootstrapServers = "kafka:9092",
    ClientId = "order-service"
};

using var producer = new ProducerBuilder<string, string>(config).Build();

var orderEvent = new
{
    Type = "OrderCreated",
    OrderId = order.Id,
    UserId = order.UserId,
    Total = order.Total
};

await producer.ProduceAsync("order-events", new Message<string, string>
{
    Key = order.Id,
    Value = JsonSerializer.Serialize(orderEvent)
});

// Consumer
var consumerConfig = new ConsumerConfig
{
    BootstrapServers = "kafka:9092",
    GroupId = "inventory-service",
    AutoOffsetReset = AutoOffsetReset.Earliest
};

using var consumer = new ConsumerBuilder<string, string>(consumerConfig).Build();
consumer.Subscribe("order-events");

while (true)
{
    var result = consumer.Consume(TimeSpan.FromSeconds(1));
    if (result != null)
    {
        var orderEvent = JsonSerializer.Deserialize<OrderCreatedEvent>(result.Message.Value);
        if (orderEvent?.Type == "OrderCreated")
        {
            await ReserveInventory(orderEvent.OrderId);
        }
    }
}
```

**Azure Event Hubs (Kafka-compatible):**
```csharp
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;

// Producer
await using var producerClient = new EventHubProducerClient(
    connectionString,
    eventHubName
);

var eventData = new EventData(JsonSerializer.Serialize(orderEvent));
await producerClient.SendAsync(new[] { eventData });

// Consumer
await using var consumerClient = new EventHubConsumerClient(
    EventHubConsumerClient.DefaultConsumerGroupName,
    connectionString,
    eventHubName
);

await foreach (PartitionEvent partitionEvent in consumerClient.ReadEventsAsync())
{
    var orderEvent = JsonSerializer.Deserialize<OrderCreatedEvent>(
        partitionEvent.Data.EventBody.ToArray()
    );
    await ReserveInventory(orderEvent.OrderId);
}
```

**RabbitMQ (Task Queues) with RabbitMQ.Client:**
```csharp
using RabbitMQ.Client;

// Producer
var factory = new ConnectionFactory { HostName = "localhost" };
using var connection = factory.CreateConnection();
using var channel = connection.CreateModel();

channel.QueueDeclare(queue: "email-queue", durable: true, exclusive: false, autoDelete: false);

var emailData = new
{
    To = user.Email,
    Subject = "Welcome!",
    Body = "Thank you for signing up"
};

var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(emailData));
channel.BasicPublish(exchange: "", routingKey: "email-queue", basicProperties: null, body: body);

// Consumer
var factory = new ConnectionFactory { HostName = "localhost" };
using var connection = factory.CreateConnection();
using var channel = connection.CreateModel();

channel.QueueDeclare(queue: "email-queue", durable: true, exclusive: false, autoDelete: false);

var consumer = new EventingBasicConsumer(channel);
consumer.Received += async (model, ea) =>
{
    var body = ea.Body.ToArray();
    var emailData = JsonSerializer.Deserialize<EmailData>(Encoding.UTF8.GetString(body));
    await SendEmail(emailData);
    channel.BasicAck(deliveryTag: ea.DeliveryTag, multiple: false);
};

channel.BasicConsume(queue: "email-queue", autoAck: false, consumer: consumer);
```

**Azure Service Bus:**
```csharp
using Azure.Messaging.ServiceBus;

// Producer
await using var client = new ServiceBusClient(connectionString);
await using var sender = client.CreateSender("email-queue");

var message = new ServiceBusMessage(JsonSerializer.Serialize(emailData));
await sender.SendMessageAsync(message);

// Consumer
await using var client = new ServiceBusClient(connectionString);
await using var processor = client.CreateProcessor("email-queue", new ServiceBusProcessorOptions());

processor.ProcessMessageAsync += async args =>
{
    var emailData = JsonSerializer.Deserialize<EmailData>(args.Message.Body.ToString());
    await SendEmail(emailData);
    await args.CompleteMessageAsync(args.Message);
};

await processor.StartProcessingAsync();
```

## CQRS (Command Query Responsibility Segregation)

**Concept:** Separate read and write models

```
Write Side (Commands):           Read Side (Queries):
CreateOrder                      GetOrderById
UpdateOrder                      GetUserOrders
  ↓                                ↑
┌─────────┐                    ┌─────────┐
│ Write   │ → Events →         │  Read   │
│  DB     │    (sync)          │  DB     │
│(SQL     │                    │(SQL     │
│ Server) │                    │ Server/ │
│         │                    │ MongoDB)│
└─────────┘                    └─────────┘
```

**Benefits:**
- Optimized read models
- Scalable (scale reads independently)
- Flexible (different DB for reads/writes)

**Implementation with MediatR (CQRS Pattern):**
```csharp
// Command (Write)
public class CreateOrderCommand : IRequest<Guid>
{
    public string UserId { get; set; }
    public List<OrderItem> Items { get; set; }
}

public class CreateOrderHandler : IRequestHandler<CreateOrderCommand, Guid>
{
    private readonly IOrderRepository _repository;
    private readonly IMediator _mediator;

    public CreateOrderHandler(IOrderRepository repository, IMediator mediator)
    {
        _repository = repository;
        _mediator = mediator;
    }

    public async Task<Guid> Handle(CreateOrderCommand request, CancellationToken cancellationToken)
    {
        var order = new Order
        {
            UserId = request.UserId,
            Items = request.Items
        };

        await _repository.AddAsync(order);
        await _mediator.Publish(new OrderCreatedEvent(order.Id, order.UserId, order.Total));
        
        return order.Id;
    }
}

// Query (Read)
public class GetOrderQuery : IRequest<OrderDto>
{
    public Guid OrderId { get; set; }
}

public class GetOrderHandler : IRequestHandler<GetOrderQuery, OrderDto>
{
    private readonly IOrderReadRepository _readRepository;

    public GetOrderHandler(IOrderReadRepository readRepository)
    {
        _readRepository = readRepository;
    }

    public async Task<OrderDto> Handle(GetOrderQuery request, CancellationToken cancellationToken)
    {
        // Read from optimized read model (denormalized, indexed)
        return await _readRepository.GetByIdAsync(request.OrderId);
    }
}

// Program.cs - Register MediatR
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(Assembly.GetExecutingAssembly()));
```

**Using MediatR with ASP.NET Core:**
```csharp
// Controller
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    private readonly IMediator _mediator;

    public OrdersController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpPost]
    public async Task<ActionResult<Guid>> CreateOrder(CreateOrderCommand command)
    {
        var orderId = await _mediator.Send(command);
        return Ok(orderId);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<OrderDto>> GetOrder(Guid id)
    {
        var order = await _mediator.Send(new GetOrderQuery { OrderId = id });
        return Ok(order);
    }
}
```

## Scalability Patterns

### Horizontal Scaling (Scale Out)

```
Load Balancer
    ↓
┌───┴───┬───────┬───────┐
│ App 1 │ App 2 │ App 3 │ ... App N
└───┬───┴───┬───┴───┬───┘
    └───────┴───────┘
         ↓
    Shared Database
    (with read replicas)
```

### Database Sharding

**Range-Based Sharding:**
```
Users 1-1M     → Shard 1
Users 1M-2M    → Shard 2
Users 2M-3M    → Shard 3
```

**Hash-Based Sharding:**
```csharp
public class ShardingService
{
    private readonly Dictionary<int, IDbContext> _shards;
    private const int SHARD_COUNT = 4;

    public ShardingService(Dictionary<int, IDbContext> shards)
    {
        _shards = shards;
    }

    private int GetShardId(string userId)
    {
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(userId));
        var hashInt = BitConverter.ToInt32(hash, 0);
        return Math.Abs(hashInt) % SHARD_COUNT;
    }

    public async Task<User> GetUserAsync(string userId)
    {
        var shardId = GetShardId(userId);
        var dbContext = _shards[shardId];
        return await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
    }
}
```

**SQL Server Sharding with Elastic Database Tools:**
```csharp
// Using Azure SQL Database Elastic Scale
var shardMapManager = ShardMapManagerFactory.GetSqlShardMapManager(
    connectionString,
    ShardMapManagerLoadPolicy.Lazy
);

var shardMap = shardMapManager.GetRangeShardMap<int>("UserShardMap");
var shard = shardMap.GetMappingForKey(userId);
var connection = shard.OpenConnection();
```

### Caching Layers

```
Client
  → CDN (Azure CDN / Cloudflare - static assets)
  → API Gateway Cache (Azure API Management - public endpoints)
  → Application Cache (Redis via IDistributedCache - user sessions, hot data)
  → Memory Cache (IMemoryCache - in-process cache)
  → Database Query Cache (EF Core Query Cache)
  → Database (SQL Server with Query Store)
```

**Implementation with .NET:**
```csharp
// Program.cs - Register caching
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = "localhost:6379";
});

builder.Services.AddMemoryCache();

// Using IDistributedCache (Redis)
public class ProductService
{
    private readonly IDistributedCache _cache;
    private readonly IProductRepository _repository;

    public ProductService(IDistributedCache cache, IProductRepository repository)
    {
        _cache = cache;
        _repository = repository;
    }

    public async Task<Product> GetProductAsync(int id)
    {
        var cacheKey = $"product:{id}";
        var cached = await _cache.GetStringAsync(cacheKey);
        
        if (cached != null)
        {
            return JsonSerializer.Deserialize<Product>(cached);
        }

        var product = await _repository.GetByIdAsync(id);
        await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(product), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30)
        });

        return product;
    }
}

// Using IMemoryCache (in-process)
public class ProductService
{
    private readonly IMemoryCache _cache;
    private readonly IProductRepository _repository;

    public ProductService(IMemoryCache cache, IProductRepository repository)
    {
        _cache = cache;
        _repository = repository;
    }

    public async Task<Product> GetProductAsync(int id)
    {
        if (!_cache.TryGetValue($"product:{id}", out Product product))
        {
            product = await _repository.GetByIdAsync(id);
            _cache.Set($"product:{id}", product, TimeSpan.FromMinutes(10));
        }
        return product;
    }
}
```

## Optimizely-Specific Architecture Patterns

### Optimizely CMS Architecture

**Traditional Optimizely (Monolithic):**
```
┌─────────────────────────────────┐
│   Optimizely CMS Application   │
│                                 │
│  ┌──────────┐  ┌─────────────┐ │
│  │ Content  │  │ Commerce    │ │
│  │  Blocks  │  │  Products   │ │
│  └──────────┘  └─────────────┘ │
│  ┌──────────┐  ┌─────────────┐ │
│  │  Pages   │  │  Personal-  │ │
│  │          │  │  ization   │ │
│  └──────────┘  └─────────────┘ │
│                                 │
│     SQL Server Database         │
└─────────────────────────────────┘
```

**Headless Optimizely (API-First):**
```
Client Apps (React, Vue, Mobile)
    ↓
┌─────────────────┐
│  Optimizely     │  - Content API
│  Content Cloud  │  - GraphQL API
│  (Headless)     │  - REST API
└────────┬────────┘
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
  Content  Commerce  Personal-  Search
  Service  Service   ization    Service
```

**Optimizely with Microservices:**
```csharp
// Optimizely Content Service
public class ContentService
{
    private readonly IContentRepository _contentRepository;
    
    public async Task<ContentDto> GetContentAsync(string contentId)
    {
        var content = await _contentRepository.GetByIdAsync(contentId);
        return MapToDto(content);
    }
}

// Separate Commerce Service
public class CommerceService
{
    public async Task<ProductDto> GetProductAsync(string productId)
    {
        // Independent service, can scale separately
    }
}
```

### Optimizely Content Personalization

```csharp
// Using Optimizely Content Cloud Personalization
public class PersonalizedContentService
{
    private readonly IContentLoader _contentLoader;
    private readonly IContentPersonalizationService _personalization;

    public async Task<ContentArea> GetPersonalizedContentAsync(string contentId, VisitorContext visitor)
    {
        var content = await _contentLoader.GetAsync<PageData>(contentId);
        var personalizedBlocks = await _personalization.GetPersonalizedContentAsync(
            content.ContentArea,
            visitor
        );
        return personalizedBlocks;
    }
}
```

### Optimizely Commerce Integration

```csharp
// Optimizely Commerce with Event-Driven Architecture
public class OrderService
{
    private readonly IOrderRepository _orderRepository;
    private readonly IEventPublisher _eventPublisher;

    public async Task<Order> CreateOrderAsync(CreateOrderRequest request)
    {
        var order = new Order
        {
            OrderNumber = GenerateOrderNumber(),
            CustomerId = request.CustomerId,
            Items = request.Items
        };

        await _orderRepository.AddAsync(order);
        
        // Publish event for other services (inventory, shipping, etc.)
        await _eventPublisher.PublishAsync(new OrderCreatedEvent
        {
            OrderId = order.Id,
            CustomerId = order.CustomerId,
            Total = order.Total
        });

        return order;
    }
}
```

## Architecture Decision Matrix

| Pattern | When to Use | Complexity | Benefits | .NET/Optimizely Tools |
|---------|-------------|------------|----------|----------------------|
| **Monolith** | Small team, MVP, unclear boundaries | Low | Simple, fast development | ASP.NET Core MVC, Optimizely CMS |
| **Microservices** | Large team, clear domains, need scaling | High | Independent deployment, fault isolation | ASP.NET Core Web API, gRPC, YARP |
| **Event-Driven** | Async workflows, audit trail needed | Moderate | Decoupling, scalability | Azure Service Bus, RabbitMQ, Kafka |
| **CQRS** | Different read/write patterns | High | Optimized queries, scalability | MediatR, Entity Framework Core |
| **Serverless** | Spiky traffic, event-driven | Low | Auto-scaling, pay-per-use | Azure Functions, AWS Lambda (.NET) |
| **Headless CMS** | Multi-channel, API-first | Moderate | Content reuse, flexibility | Optimizely Content Cloud |

## Anti-Patterns to Avoid

1. **Distributed Monolith** - Microservices that all depend on each other
2. **Chatty Services** - Too many inter-service calls (network overhead)
3. **Shared Database** - Microservices sharing same DB (tight coupling)
4. **Over-Engineering** - Using microservices for small apps
5. **No Circuit Breakers** - Cascade failures in distributed systems

## Architecture Checklist

- [ ] Clear service boundaries (domain-driven design)
- [ ] Database per service (no shared databases)
- [ ] API Gateway for client requests (Ocelot/YARP/Azure APIM)
- [ ] Service discovery configured (Consul/Steeltoe/Azure Service Discovery)
- [ ] Circuit breakers for resilience (Polly)
- [ ] Event-driven communication (Azure Service Bus/RabbitMQ/Kafka)
- [ ] CQRS for read-heavy systems (MediatR)
- [ ] Distributed tracing (OpenTelemetry/Application Insights)
- [ ] Health checks for all services (ASP.NET Core Health Checks)
- [ ] Horizontal scaling capability
- [ ] Caching strategy (Redis/IMemoryCache)
- [ ] Logging and monitoring (Serilog/Application Insights)
- [ ] Dependency injection configured (built-in DI container)
- [ ] Async/await for I/O operations
- [ ] Optimizely-specific: Content personalization configured
- [ ] Optimizely-specific: Multi-site/multi-language support

## Resources

### .NET & ASP.NET Core Architecture
- **.NET Microservices Architecture:** https://learn.microsoft.com/dotnet/architecture/microservices/
- **ASP.NET Core Architecture:** https://learn.microsoft.com/aspnet/core/fundamentals/
- **Polly (Resilience Library):** https://github.com/App-vNext/Polly
- **MediatR (CQRS/Mediator):** https://github.com/jbogard/MediatR
- **Ocelot API Gateway:** https://github.com/ThreeMammals/Ocelot
- **YARP (Yet Another Reverse Proxy):** https://microsoft.github.io/reverse-proxy/

### Event-Driven & Messaging
- **Azure Service Bus:** https://learn.microsoft.com/azure/service-bus-messaging/
- **RabbitMQ .NET Client:** https://www.rabbitmq.com/dotnet.html
- **Confluent Kafka .NET:** https://github.com/confluentinc/confluent-kafka-dotnet
- **MassTransit (Message Bus):** https://masstransit.io/

### Optimizely
- **Optimizely Documentation:** https://docs.developers.optimizely.com/
- **Optimizely Content Cloud:** https://www.optimizely.com/products/content-cloud/
- **Optimizely Developer Portal:** https://world.optimizely.com/
- **Optimizely Architecture Best Practices:** https://docs.developers.optimizely.com/content-management-system/docs/architecture

### General Architecture Patterns
- **Microservices Patterns:** https://microservices.io/patterns/
- **Martin Fowler - Microservices:** https://martinfowler.com/articles/microservices.html
- **Event-Driven Architecture:** https://learn.microsoft.com/azure/architecture/guide/architecture-styles/event-driven
- **CQRS Pattern:** https://learn.microsoft.com/azure/architecture/patterns/cqrs
