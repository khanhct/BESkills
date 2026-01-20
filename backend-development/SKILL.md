---
name: backend-development
description: Build robust backend systems with C#/.NET Core, ASP.NET Core (MVC, Web API, Minimal APIs), Optimizely CMS/Commerce, databases (SQL Server, MongoDB, Redis), APIs (REST, GraphQL, gRPC), authentication (OAuth 2.1, JWT, ASP.NET Core Identity), testing strategies (xUnit, NUnit, Moq), security best practices (OWASP Top 10), performance optimization, scalability patterns (microservices, caching, sharding), DevOps practices (Docker, Kubernetes, CI/CD), and monitoring (Application Insights, OpenTelemetry). Use when designing APIs, implementing authentication, optimizing database queries, setting up CI/CD pipelines, handling security vulnerabilities, building microservices, or developing production-ready backend systems.
license: MIT
version: 1.0.0
---

# Backend Development Skill

Production-ready backend development with modern technologies, best practices, and proven patterns.

## When to Use

- Designing RESTful, GraphQL, or gRPC APIs
- Building authentication/authorization systems
- Optimizing database queries and schemas
- Implementing caching and performance optimization
- OWASP Top 10 security mitigation
- Designing scalable microservices
- Testing strategies (unit, integration, E2E)
- CI/CD pipelines and deployment
- Monitoring and debugging production systems

## Technology Selection Guide

**Languages:** C# (.NET 8+) - Cross-platform, high-performance, enterprise-grade
**Frameworks:** ASP.NET Core MVC (full-stack), ASP.NET Core Web API (REST APIs), Minimal APIs (microservices), Optimizely (CMS/Commerce)
**Databases:** SQL Server (ACID, enterprise), MongoDB (flexible schema), Redis (caching, sessions)
**APIs:** REST (ASP.NET Core Web API), GraphQL (HotChocolate), gRPC (.NET gRPC)
**ORMs:** Entity Framework Core (rapid development), Dapper (high performance)
**Message Queues:** Azure Service Bus, RabbitMQ, Kafka (via Confluent.Kafka), MassTransit

See: `references/backend-technologies.md` for detailed comparisons

## Reference Navigation

**Core Technologies:**
- `backend-technologies.md` - Languages, frameworks, databases, message queues, ORMs
- `backend-api-design.md` - REST, GraphQL, gRPC patterns and best practices

**Security & Authentication:**
- `backend-security.md` - OWASP Top 10 2025, security best practices, input validation
- `backend-authentication.md` - OAuth 2.1, JWT, RBAC, MFA, session management

**Performance & Architecture:**
- `backend-performance.md` - Caching, query optimization, load balancing, scaling
- `backend-architecture.md` - Microservices, event-driven, CQRS, saga patterns

**Quality & Operations:**
- `backend-testing.md` - Testing strategies, frameworks, tools, CI/CD testing
- `backend-code-quality.md` - SOLID principles, design patterns, clean code
- `backend-devops.md` - Docker, Kubernetes, deployment strategies, monitoring
- `backend-debugging.md` - Debugging strategies, profiling, logging, production debugging
- `backend-mindset.md` - Problem-solving, architectural thinking, collaboration

## Key Best Practices (2025)

**Security:** ASP.NET Core Identity with Argon2id/BCrypt passwords, parameterized queries via EF Core (98% SQL injection reduction), OAuth 2.1 + PKCE, rate limiting (AspNetCoreRateLimit), security headers (NWebsec), Azure Key Vault for secrets

**Performance:** Redis caching via StackExchange.Redis (90% DB load reduction), SQL Server indexing (30% I/O reduction), CDN (50%+ latency cut), EF Core connection pooling, compiled queries for hot paths

**Testing:** 70-20-10 pyramid (unit-integration-E2E), xUnit/NUnit for unit tests, Moq/NSubstitute for mocking, WebApplicationFactory for integration tests, FluentAssertions for readable assertions, 83% migrations fail without tests

**DevOps:** Blue-green/canary deployments, feature flags (90% fewer failures), Kubernetes 84% adoption, Application Insights/Prometheus/Grafana monitoring, OpenTelemetry tracing, Azure DevOps/GitHub Actions CI/CD

## Quick Decision Matrix

| Need | Choose |
|------|--------|
| Fast development | ASP.NET Core Web API + EF Core |
| Full-stack web app | ASP.NET Core MVC |
| Simple APIs/microservices | ASP.NET Core Minimal APIs |
| CMS/Content management | Optimizely CMS + ASP.NET Core |
| E-commerce platform | Optimizely Commerce |
| ACID transactions | SQL Server |
| Flexible schema | MongoDB |
| Caching/Sessions | Redis (StackExchange.Redis) |
| Internal microservices | .NET gRPC |
| Public APIs | GraphQL (HotChocolate) / REST (Web API) |
| Real-time features | SignalR |
| Message queues (Azure) | Azure Service Bus |
| Message queues (self-hosted) | RabbitMQ |
| Event streaming | Kafka (Confluent.Kafka) / Azure Event Hubs |
| Background jobs | Hangfire / Quartz.NET |

## Implementation Checklist

**API:** Choose style (REST/GraphQL/gRPC) → Design schema → Validate input (FluentValidation) → Add auth (ASP.NET Core Identity/JWT) → Rate limiting → OpenAPI/Swagger docs → ProblemDetails error handling

**Database:** Choose DB (SQL Server/MongoDB) → Design schema → Create indexes (EF Core migrations) → Connection pooling (EF Core default) → Migration strategy → Backup/restore → Test performance (EF Core compiled queries)

**Security:** OWASP Top 10 → Parameterized queries (EF Core/Dapper) → OAuth 2.1 + JWT → Security headers (NWebsec) → Rate limiting (AspNetCoreRateLimit) → Input validation (FluentValidation) → ASP.NET Core Identity with Argon2id passwords → Azure Key Vault for secrets

**Testing:** Unit 70% (xUnit/NUnit) → Integration 20% (WebApplicationFactory) → E2E 10% → Load tests → EF Core migration tests → Contract tests (microservices)

**Deployment:** Docker → CI/CD (Azure DevOps/GitHub Actions) → Blue-green/canary → Feature flags → Application Insights monitoring → Serilog logging → Health checks (ASP.NET Core health checks)

## Resources

### .NET & ASP.NET Core
- **ASP.NET Core Documentation:** https://learn.microsoft.com/aspnet/core/
- **.NET Documentation:** https://learn.microsoft.com/dotnet/
- **Entity Framework Core:** https://learn.microsoft.com/ef/core/
- **ASP.NET Core Web API:** https://learn.microsoft.com/aspnet/core/web-api/

### Optimizely
- **Optimizely Documentation:** https://docs.developers.optimizely.com/
- **Optimizely Content Cloud:** https://docs.developers.optimizely.com/content-management-system/
- **Optimizely Commerce:** https://docs.developers.optimizely.com/commerce/

### Security & Authentication
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **OAuth 2.1:** https://oauth.net/2.1/
- **ASP.NET Core Security:** https://learn.microsoft.com/aspnet/core/security/

### Testing
- **xUnit:** https://xunit.net/
- **NUnit:** https://nunit.org/
- **Moq:** https://github.com/moq/moq4

### Monitoring & Observability
- **Application Insights:** https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
- **OpenTelemetry:** https://opentelemetry.io/
- **Serilog:** https://serilog.net/

### GraphQL & gRPC
- **HotChocolate (GraphQL):** https://chillicream.com/docs/hotchocolate
- **.NET gRPC:** https://learn.microsoft.com/aspnet/core/grpc/
