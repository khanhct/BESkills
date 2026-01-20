# Backend Technologies

Core technologies, frameworks, databases, and message queues for modern C#/.NET backend development (2025).

## Programming Languages & Frameworks

### C# / .NET Core
**Market Position:** .NET 8+ adoption surge - cross-platform, high-performance, enterprise-grade

**Best For:**
- Enterprise applications and line-of-business systems
- High-performance APIs and microservices
- Cross-platform development (Windows, Linux, macOS)
- Cloud-native applications (Azure, AWS, GCP)
- Real-time applications (SignalR)

**Popular Frameworks:**
- **ASP.NET Core** - Modern, cross-platform, high-performance web framework
- **Minimal APIs** - Lightweight, fast, perfect for microservices
- **gRPC** - High-performance RPC framework for microservices
- **SignalR** - Real-time web functionality (WebSockets, Server-Sent Events)

**When to Choose:** Enterprise development, cross-platform needs, high performance requirements, Microsoft ecosystem integration

### ASP.NET Core MVC
**Market Position:** Industry standard for full-featured web applications

**Best For:**
- Full-stack web applications
- Traditional MVC architecture
- Server-side rendering
- Form-heavy applications
- Content management systems

**Key Features:**
- Model-View-Controller pattern
- Tag Helpers and View Components
- Built-in dependency injection
- Middleware pipeline
- Razor templating engine

**When to Choose:** Full-featured web apps, MVC pattern preference, server-side rendering needed

### ASP.NET Core Web API
**Market Position:** Preferred framework for RESTful APIs in .NET ecosystem

**Best For:**
- RESTful API development
- Microservices architectures
- Mobile backend services
- SPA (Single Page Application) backends
- API-first development

**Key Features:**
- Attribute-based routing
- Model binding and validation
- Content negotiation (JSON, XML)
- OpenAPI/Swagger integration
- Built-in CORS support

**When to Choose:** API development, microservices, mobile backends, SPA backends

### Optimizely (Episerver)
**Market Position:** Leading enterprise CMS and digital experience platform

**Best For:**
- Content management systems (CMS)
- Digital commerce platforms
- Personalization and experimentation
- Multi-site management
- Enterprise content workflows

**Key Features:**
- Headless and traditional CMS modes
- Content personalization (Optimizely Content Cloud)
- A/B testing and experimentation (Optimizely Web Experimentation)
- Commerce integration (Optimizely Commerce)
- Multi-language and multi-site support
- Visual page editing

**When to Choose:** CMS requirements, content-driven sites, e-commerce integration, personalization needs, enterprise content management

## Databases

### Relational (SQL)

#### SQL Server
**Market Position:** Industry standard for enterprise .NET applications

**Strengths:**
- ACID compliance, data integrity
- Excellent .NET integration (native support)
- Advanced security features (Always Encrypted, Row-Level Security)
- JSON support, full-text search
- Columnstore indexes for analytics
- Temporal tables for audit trails
- In-Memory OLTP for high-performance scenarios

**Use Cases:**
- Enterprise applications
- Financial applications
- E-commerce platforms
- Complex reporting and analytics
- Multi-tenant SaaS applications

**When to Choose:** Enterprise .NET applications, Microsoft ecosystem, advanced security needs, complex reporting, cross-platform .NET applications

### NoSQL

#### MongoDB
**Market Position:** Leading document database

**Strengths:**
- Flexible/evolving schemas
- Horizontal scaling (sharding built-in)
- Aggregation pipeline (powerful data processing)
- GridFS for large files

**Use Cases:**
- Content management systems
- Real-time analytics
- IoT data collection
- Catalogs with varied attributes

**When to Choose:** Schema flexibility needed, rapid iteration, horizontal scaling required

### Caching & In-Memory

#### Redis
**Market Position:** Industry standard for caching and session storage

**Capabilities:**
- In-memory key-value store
- Pub/sub messaging
- Sorted sets (leaderboards)
- Geospatial indexes
- Streams (event sourcing)

**Performance:** 10-100x faster than disk-based databases

**Use Cases:**
- Session storage (via IDistributedCache)
- Rate limiting
- Real-time leaderboards
- Distributed caching (90% DB load reduction)
- Pub/sub messaging
- Distributed locks

**When to Choose:** Need sub-millisecond latency, caching layer, session management, distributed systems

**.NET Integration:**
- **StackExchange.Redis** - High-performance .NET client
- **Microsoft.Extensions.Caching.StackExchangeRedis** - Built-in caching abstraction

## ORMs & Database Tools

### Modern ORMs (.NET)

**Entity Framework Core**
- Industry standard .NET ORM
- Code-first and database-first approaches
- Migrations, change tracking, LINQ support
- Excellent Visual Studio integration
- Best for: Rapid development, complex domain models, enterprise applications

**Dapper**
- Micro-ORM, lightweight and fast
- Minimal overhead, close to raw SQL performance
- Simple mapping, no change tracking
- Best for: Performance-critical applications, microservices, simple CRUD operations

**EF Core + Dapper Hybrid**
- Use EF Core for complex queries and migrations
- Use Dapper for high-performance read operations
- Best for: Applications needing both productivity and performance

**NHibernate**
- Mature, feature-complete ORM
- Advanced mapping capabilities
- Best for: Legacy applications, complex mapping scenarios

**Optimizely Content Repository**
- Built-in content management ORM
- Content types, properties, relationships
- Versioning and publishing workflows
- Best for: Optimizely CMS applications

## Essential .NET Libraries & Tools

### CQRS & Mediator Pattern
**MediatR**
- Implements mediator pattern for CQRS
- Request/response and notification handlers
- Reduces coupling between components
- Best for: Clean architecture, CQRS patterns, decoupled handlers

### Object Mapping
**AutoMapper**
- Convention-based object-to-object mapping
- Reduces boilerplate mapping code
- Projection support for EF Core
- Best for: DTO mapping, view model mapping

**Mapster**
- High-performance alternative to AutoMapper
- Faster compilation and runtime performance
- Best for: Performance-critical mapping scenarios

### Validation
**FluentValidation**
- Fluent, strongly-typed validation library
- Separates validation logic from models
- Excellent ASP.NET Core integration
- Best for: Complex validation rules, reusable validators

**Data Annotations**
- Built-in .NET validation attributes
- Simple, declarative validation
- Best for: Simple validation scenarios

### HTTP Clients
**HttpClient / IHttpClientFactory**
- Built-in HTTP client with factory pattern
- Handles connection pooling and lifetime
- Best for: REST API calls, external service integration

**Refit**
- Type-safe REST client library
- Generates HTTP clients from interfaces
- Best for: Strongly-typed API clients

### Logging & Monitoring
**Serilog**
- Structured logging framework
- Multiple sinks (file, console, cloud)
- Best for: Production logging, structured logging

**Application Insights**
- Azure monitoring and telemetry
- Performance monitoring, dependency tracking
- Best for: Azure-hosted applications, production monitoring

### Testing
**xUnit**
- Modern .NET testing framework
- Best for: Unit and integration testing

**Moq / NSubstitute**
- Mocking frameworks for unit tests
- Best for: Isolated unit testing

**FluentAssertions**
- Expressive assertion library
- Best for: Readable test assertions

## Message Queues & Event Streaming

### Azure Service Bus
**Best For:** Cloud-native .NET applications, Azure ecosystem

**Strengths:**
- Fully managed cloud service
- Queues, topics, and subscriptions
- Dead-letter queues, message sessions
- Built-in retry policies and duplicate detection
- Excellent .NET SDK integration
- Geo-replication support

**Use Cases:**
- Azure-hosted applications
- Microservices communication
- Background job processing
- Event-driven architectures

**When to Choose:** Azure cloud deployment, managed service preference, enterprise messaging needs

### RabbitMQ
**Best For:** On-premises or cross-cloud message queues

**Strengths:**
- Flexible routing (direct, topic, fanout, headers)
- Message acknowledgment and durability
- Dead letter exchanges
- Wide protocol support (AMQP, MQTT, STOMP)
- Excellent .NET client libraries (RabbitMQ.Client)

**Use Cases:**
- Background job processing
- Microservices communication
- Email/notification queues
- Cross-platform messaging

**When to Choose:** On-premises deployment, complex routing, moderate throughput, cross-cloud needs

### Azure Event Hubs / Apache Kafka
**Best For:** Event streaming, millions messages/second

**Strengths:**
- Distributed, fault-tolerant
- High throughput (millions msg/sec)
- Message replay (retention-based)
- Stream processing capabilities
- Azure Event Hubs: Fully managed, Kafka-compatible API

**Use Cases:**
- Real-time analytics
- Event sourcing
- Log aggregation
- IoT data ingestion
- Large-scale event processing

**When to Choose:** Event streaming, high throughput, event replay needed, real-time analytics, IoT scenarios

### Hangfire / Quartz.NET
**Best For:** Background job processing in .NET applications

**Strengths:**
- Built-in dashboard (Hangfire)
- Cron-based scheduling (Quartz.NET)
- Persistent job storage
- Retry mechanisms
- Best for: Background tasks, scheduled jobs, recurring tasks

**When to Choose:** Background job processing, scheduled tasks, simple queue needs

## Framework Comparisons

### ASP.NET Core Frameworks

| Framework | Performance | Learning Curve | Use Case |
|-----------|------------|----------------|----------|
| Minimal APIs | High | Easy | Simple APIs, microservices |
| ASP.NET Core Web API | High | Moderate | RESTful APIs, microservices |
| ASP.NET Core MVC | Moderate | Moderate | Full-stack web apps, traditional MVC |
| Optimizely CMS | Moderate | Steep | Content management, enterprise CMS |

### .NET Performance Characteristics

| Technology | Throughput | Latency | Best For |
|-----------|------------|---------|----------|
| ASP.NET Core Minimal APIs | Very High | Low | High-performance APIs |
| ASP.NET Core Web API | High | Low | Standard REST APIs |
| gRPC | Very High | Very Low | Microservices, inter-service communication |
| SignalR | High | Very Low | Real-time applications |
| Entity Framework Core | Moderate | Moderate | Rapid development, complex queries |
| Dapper | High | Low | Performance-critical data access |

## Technology Selection Flowchart

```
Start → Need CMS/Content Management?
       → Yes → Optimizely CMS + ASP.NET Core
       → No → Need real-time features?
              → Yes → ASP.NET Core + SignalR
              → No → Need microservices?
                     → Yes → ASP.NET Core Minimal APIs + gRPC
                     → No → Need full-stack web app?
                            → Yes → ASP.NET Core MVC
                            → No → ASP.NET Core Web API (default)

Database Selection:
Relational database needed? → Yes → SQL Server (default for .NET)
                            → No → Continue with NoSQL

NoSQL needed? → Yes → MongoDB (via MongoDB.Driver)
              → No → Continue with SQL

Caching needed? → Always use Redis (via StackExchange.Redis)

Message Queue:
Azure deployment? → Yes → Azure Service Bus
                  → No → Millions msg/sec? → Yes → Azure Event Hubs / Kafka
                                         → No → RabbitMQ

Background Jobs:
Simple scheduled tasks? → Hangfire / Quartz.NET
Complex workflows? → Azure Service Bus / RabbitMQ
```

## Common Pitfalls

1. **Choosing NoSQL for relational data** - Use SQL Server if data has clear relationships
2. **Not using connection pooling** - EF Core uses connection pooling by default, but configure properly for high-load scenarios
3. **Ignoring indexes** - Add indexes to frequently queried columns (30% I/O reduction), use EF Core migrations
4. **Over-engineering with microservices** - Start with monolith, split when needed (.NET supports both architectures)
5. **Not caching** - Use Redis (via StackExchange.Redis) or IMemoryCache for 90% DB load reduction
6. **N+1 queries with EF Core** - Use `.Include()`, `.ThenInclude()`, or projection to avoid N+1 problems
7. **Not using async/await** - Always use async methods for I/O operations (database, HTTP calls)
8. **Ignoring dependency injection** - Leverage built-in DI container for testability and maintainability
9. **Over-fetching data** - Use DTOs and projections instead of returning full entities
10. **Not configuring CORS properly** - Configure CORS middleware correctly for cross-origin requests

## Resources

### .NET & ASP.NET Core
- **ASP.NET Core Documentation:** https://learn.microsoft.com/aspnet/core/
- **.NET Documentation:** https://learn.microsoft.com/dotnet/
- **Entity Framework Core:** https://learn.microsoft.com/ef/core/
- **Dapper:** https://github.com/DapperLib/Dapper
- **SignalR:** https://learn.microsoft.com/aspnet/core/signalr/introduction

### Optimizely
- **Optimizely Documentation:** https://docs.developers.optimizely.com/
- **Optimizely Content Cloud:** https://www.optimizely.com/products/content-cloud/
- **Optimizely Developer Portal:** https://world.optimizely.com/

### Databases
- **SQL Server:** https://learn.microsoft.com/sql/
- **MongoDB .NET Driver:** https://www.mongodb.com/docs/drivers/csharp/

### Caching & Messaging
- **Redis (.NET):** https://redis.io/docs/clients/dotnet/
- **StackExchange.Redis:** https://github.com/StackExchange/StackExchange.Redis
- **Azure Service Bus:** https://learn.microsoft.com/azure/service-bus-messaging/
- **RabbitMQ .NET Client:** https://www.rabbitmq.com/dotnet.html
- **Hangfire:** https://www.hangfire.io/
- **Quartz.NET:** https://www.quartz-scheduler.net/
