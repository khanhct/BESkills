# Backend DevOps Practices

CI/CD pipelines, containerization, deployment strategies, and monitoring for C#/.NET backend applications (2025).

## Deployment Strategies

### Blue-Green Deployment

**Concept:** Two identical environments (Blue = current, Green = new)

```
Production Traffic → Blue (v1.0)
                     Green (v2.0) ← Deploy & Test

Switch:
Production Traffic → Green (v2.0)
                     Blue (v1.0) ← Instant rollback available
```

**Pros:**
- Zero downtime
- Instant rollback
- Full environment testing before switch

**Cons:**
- Requires double infrastructure
- Database migrations complex

### Canary Deployment

**Concept:** Gradual rollout (1% → 5% → 25% → 100%)

```bash
# Kubernetes canary deployment
kubectl set image deployment/api api=myapp:v2
kubectl rollout pause deployment/api  # Pause at initial replicas

# Monitor metrics, then continue
kubectl rollout resume deployment/api
```

**Pros:**
- Risk mitigation
- Early issue detection
- Real user feedback

**Cons:**
- Requires monitoring
- Longer deployment time

### Feature Flags (Progressive Delivery)

**Impact:** 90% fewer deployment failures when combined with canary

**Azure App Configuration / Feature Management**
```csharp
// Program.cs - Configure feature flags
builder.Services.AddAzureAppConfiguration();
builder.Services.AddFeatureManagement();

// In controller or service
public class CheckoutController : ControllerBase
{
    private readonly IFeatureManager _featureManager;
    
    public CheckoutController(IFeatureManager featureManager)
    {
        _featureManager = featureManager;
    }
    
    [HttpPost("checkout")]
    public async Task<IActionResult> Checkout(CheckoutRequest request)
    {
        var useNewCheckout = await _featureManager.IsEnabledAsync("NewCheckoutFlow");
        
        if (useNewCheckout)
        {
            return await NewCheckoutFlowAsync(request);
        }
        else
        {
            return await OldCheckoutFlowAsync(request);
        }
    }
}
```

**LaunchDarkly for .NET**
```csharp
// Program.cs
builder.Services.AddSingleton<ILdClient>(sp =>
{
    var config = LaunchDarkly.Sdk.Server.Configuration.Builder(apiKey)
        .Build();
    return new LdClient(config);
});

// Usage
public class CheckoutService
{
    private readonly ILdClient _ldClient;
    
    public async Task<IActionResult> CheckoutAsync(CheckoutRequest request, User user)
    {
        var context = Context.Builder(user.Id)
            .Set("email", user.Email)
            .Build();
        
        var showNewCheckout = _ldClient.BoolVariation("new-checkout", context, false);
        
        return showNewCheckout 
            ? await NewCheckoutFlowAsync(request)
            : await OldCheckoutFlowAsync(request);
    }
}
```

**Use Cases:**
- Gradual feature rollout
- A/B testing
- Kill switch for problematic features
- Decouple deployment from release
- Environment-specific feature toggles

## Containerization with Docker

### Multi-Stage Builds for .NET (Optimize Image Size)

```dockerfile
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy csproj and restore dependencies
COPY ["MyApi/MyApi.csproj", "MyApi/"]
RUN dotnet restore "MyApi/MyApi.csproj"

# Copy everything else and build
COPY . .
WORKDIR "/src/MyApi"
RUN dotnet build "MyApi.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "MyApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Production stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Copy published app
COPY --from=publish /app/publish .

# Security: Run as non-root
RUN addgroup --system --gid 1001 dotnetuser && \
    adduser --system --uid 1001 --ingroup dotnetuser dotnetuser
USER dotnetuser

EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "MyApi.dll"]
```

**Benefits:**
- Smaller image size (50-90% reduction) - ~200MB vs ~1GB
- Faster deployments
- Reduced attack surface
- No SDK in production image

**Optimized .NET Dockerfile (with trimming)**
```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["MyApi/MyApi.csproj", "MyApi/"]
RUN dotnet restore "MyApi/MyApi.csproj"
COPY . .
WORKDIR "/src/MyApi"
RUN dotnet publish "MyApi.csproj" \
    -c Release \
    -o /app/publish \
    /p:PublishTrimmed=true \
    /p:TrimMode=link \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "MyApi.dll"]
```

### Docker Compose (Local Development)

```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ConnectionStrings__DefaultConnection=Server=db;Database=MyAppDb;User Id=sa;Password=YourStrong@Passw0rd;TrustServerCertificate=True
      - ConnectionStrings__Redis=redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./src:/app/src  # Hot reload for development

  db:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      - ACCEPT_EULA=Y
      - SA_PASSWORD=YourStrong@Passw0rd
      - MSSQL_PID=Developer
    ports:
      - "1433:1433"
    volumes:
      - sqlserver-data:/var/opt/mssql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  sqlserver-data:
  redis-data:
```

**Docker Compose Override for Development**
```yaml
# docker-compose.override.yml
version: '3.8'

services:
  api:
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_HTTPS_PORT=5001
    volumes:
      - ./src:/app/src
      - ~/.aspnet/https:/https:ro
```

## Kubernetes Orchestration

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: myregistry/api:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: ConnectionStrings__DefaultConnection
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: connection-string
        - name: ApplicationInsights__ConnectionString
          valueFrom:
            secretKeyRef:
              name: appinsights-secret
              key: connection-string
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
```

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-deployment
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## CI/CD Pipelines

### GitHub Actions for .NET

```yaml
name: .NET CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '8.0.x'

      - name: Restore dependencies
        run: dotnet restore

      - name: Build
        run: dotnet build --no-restore --configuration Release

      - name: Run tests
        run: dotnet test --no-build --configuration Release --verbosity normal --collect:"XPlat Code Coverage"

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./**/coverage.cobertura.xml

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '8.0.x'

      - name: Run Snyk scan
        uses: snyk/actions/dotnet@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: Check for vulnerabilities
        run: dotnet list package --vulnerable --include-transitive

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan Docker image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}

  build-docker:
    needs: [build-and-test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.sha }}
            ghcr.io/${{ github.repository }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  deploy:
    needs: [build-docker, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Configure kubectl
        uses: azure/setup-kubectl@v3

      - name: Set up Kubeconfig
        uses: azure/k8s-set-context@v3
        with:
          kubeconfig: ${{ secrets.KUBE_CONFIG }}

      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/api api=ghcr.io/${{ github.repository }}:${{ github.sha }}
          kubectl rollout status deployment/api
```

### Azure DevOps Pipeline for .NET

```yaml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'windows-latest'

variables:
  buildConfiguration: 'Release'
  dockerRegistry: 'myregistry.azurecr.io'
  imageRepository: 'myapi'

stages:
- stage: Build
  displayName: 'Build and Test'
  jobs:
  - job: Build
    displayName: 'Build .NET Application'
    steps:
    - task: UseDotNet@2
      inputs:
        packageType: 'sdk'
        version: '8.x'
    
    - task: DotNetCoreCLI@2
      displayName: 'Restore'
      inputs:
        command: 'restore'
    
    - task: DotNetCoreCLI@2
      displayName: 'Build'
      inputs:
        command: 'build'
        arguments: '--configuration $(buildConfiguration)'
    
    - task: DotNetCoreCLI@2
      displayName: 'Test'
      inputs:
        command: 'test'
        arguments: '--configuration $(buildConfiguration) --collect:"XPlat Code Coverage"'
    
    - task: PublishCodeCoverageResults@1
      displayName: 'Publish Code Coverage'
      inputs:
        codeCoverageTool: 'Cobertura'
        summaryFileLocation: '$(Agent.TempDirectory)/**/coverage.cobertura.xml'

- stage: Docker
  displayName: 'Build and Push Docker Image'
  dependsOn: Build
  jobs:
  - job: Docker
    steps:
    - task: Docker@2
      displayName: 'Build and push image'
      inputs:
        command: buildAndPush
        repository: $(imageRepository)
        dockerfile: '**/Dockerfile'
        containerRegistry: $(dockerRegistry)
        tags: |
          $(Build.BuildId)
          latest

- stage: Deploy
  displayName: 'Deploy to Azure'
  dependsOn: Docker
  jobs:
  - deployment: Deploy
    displayName: 'Deploy to Azure Container Apps'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: AzureContainerApps@1
            inputs:
              azureSubscription: 'Azure-Service-Connection'
              containerAppName: 'myapi'
              imageToDeploy: '$(dockerRegistry)/$(imageRepository):$(Build.BuildId)'
```

## Monitoring & Observability

### Three Pillars of Observability for .NET

**1. Metrics (Application Insights / Prometheus)**

**Application Insights (Azure)**
```csharp
// Program.cs - Configure Application Insights
builder.Services.AddApplicationInsightsTelemetry(options =>
{
    options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
    options.EnableAdaptiveSampling = true;
    options.EnableDependencyTrackingTelemetryModule = true;
});

// Custom metrics
public class OrderService
{
    private readonly TelemetryClient _telemetryClient;
    
    public async Task<Order> CreateOrderAsync(CreateOrderDto dto)
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            var order = await _repository.CreateAsync(dto);
            
            _telemetryClient.TrackEvent("OrderCreated", new Dictionary<string, string>
            {
                ["OrderId"] = order.Id.ToString(),
                ["UserId"] = order.UserId.ToString(),
                ["Amount"] = order.Total.ToString("C")
            });
            
            _telemetryClient.TrackMetric("OrderCreationTime", stopwatch.ElapsedMilliseconds);
            
            return order;
        }
        catch (Exception ex)
        {
            _telemetryClient.TrackException(ex);
            throw;
        }
    }
}
```

**Prometheus for .NET**
```csharp
// Install: prometheus-net.AspNetCore
builder.Services.AddPrometheusMetrics();

// Custom metrics
public class MetricsMiddleware
{
    private static readonly Counter RequestCounter = Metrics
        .CreateCounter("http_requests_total", "Total HTTP requests",
            new CounterConfiguration
            {
                LabelNames = new[] { "method", "route", "status" }
            });
    
    private static readonly Histogram RequestDuration = Metrics
        .CreateHistogram("http_request_duration_seconds", "HTTP request duration",
            new HistogramConfiguration
            {
                LabelNames = new[] { "method", "route" },
                Buckets = new[] { 0.1, 0.5, 1, 2, 5 }
            });
    
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var stopwatch = Stopwatch.StartNew();
        
        await next(context);
        
        stopwatch.Stop();
        RequestCounter.WithLabels(
            context.Request.Method,
            context.Request.Path.Value ?? "",
            context.Response.StatusCode.ToString())
            .Inc();
        
        RequestDuration.WithLabels(
            context.Request.Method,
            context.Request.Path.Value ?? "")
            .Observe(stopwatch.Elapsed.TotalSeconds);
    }
}

// Metrics endpoint
app.MapPrometheusScrapingEndpoint("/metrics");
```

**2. Logs (Serilog + Application Insights)**

```csharp
// Program.cs - Configure Serilog
builder.Host.UseSerilog((context, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithMachineName()
        .Enrich.WithEnvironmentName()
        .WriteTo.Console()
        .WriteTo.ApplicationInsights(
            context.Configuration["ApplicationInsights:ConnectionString"],
            TelemetryConverter.Traces)
        .WriteTo.File(
            path: "logs/app-.log",
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30);
});

// Structured logging
_logger.LogInformation(
    "User {UserId} created order {OrderId} for amount {Amount}",
    user.Id,
    order.Id,
    order.Total);

// With scoped context
using (_logger.BeginScope(new Dictionary<string, object>
{
    ["OrderId"] = order.Id,
    ["UserId"] = user.Id,
    ["CorrelationId"] = HttpContext.TraceIdentifier
}))
{
    _logger.LogInformation("Processing order");
}
```

**3. Traces (OpenTelemetry for .NET)**

```csharp
// Program.cs - Configure OpenTelemetry
builder.Services.AddOpenTelemetry()
    .WithTracing(builder =>
    {
        builder
            .AddAspNetCoreInstrumentation()
            .AddEntityFrameworkCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddSource("MyApp")
            .AddJaegerExporter(options =>
            {
                options.AgentHost = "localhost";
                options.AgentPort = 6831;
            })
            .AddAzureMonitorTraceExporter(options =>
            {
                options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
            });
    })
    .WithMetrics(builder =>
    {
        builder
            .AddAspNetCoreInstrumentation()
            .AddRuntimeInstrumentation()
            .AddPrometheusExporter();
    });

// Custom spans
using var activity = ActivitySource.StartActivity("ProcessPayment");
activity?.SetTag("order.id", order.Id);
activity?.SetTag("payment.amount", order.Total);
```

### Health Checks (ASP.NET Core)

```csharp
// Program.cs - Configure health checks
builder.Services.AddHealthChecks()
    .AddSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        name: "database",
        timeout: TimeSpan.FromSeconds(3),
        tags: new[] { "db", "sql", "ready" })
    .AddRedis(
        builder.Configuration.GetConnectionString("Redis"),
        name: "redis",
        tags: new[] { "cache", "ready" })
    .AddCheck<ExternalApiHealthCheck>(
        "external-api",
        tags: new[] { "external", "ready" })
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "live" });

// Map health check endpoints
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live")
});

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});

// Custom health check
public class ExternalApiHealthCheck : IHealthCheck
{
    private readonly HttpClient _httpClient;
    
    public ExternalApiHealthCheck(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient();
    }
    
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync(
                "https://api.external.com/health",
                cancellationToken);
            
            return response.IsSuccessStatusCode
                ? HealthCheckResult.Healthy("External API is responding")
                : HealthCheckResult.Unhealthy("External API is not responding");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("External API check failed", ex);
        }
    }
}

// Response format
{
  "status": "Healthy",
  "totalDuration": "00:00:00.1000000",
  "entries": {
    "database": {
      "status": "Healthy",
      "duration": "00:00:00.0500000",
      "description": null
    },
    "redis": {
      "status": "Healthy",
      "duration": "00:00:00.0300000"
    }
  }
}
```

## Secrets Management

### Azure Key Vault (Recommended for Azure)

```csharp
// Program.cs - Configure Azure Key Vault
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{builder.Configuration["KeyVault:VaultName"]}.vault.azure.net/"),
    new DefaultAzureCredential());

// Access secrets in configuration
var dbPassword = builder.Configuration["DatabasePassword"];
var apiKey = builder.Configuration["ExternalApiKey"];

// Or inject IConfiguration
public class OrderService
{
    private readonly IConfiguration _configuration;
    
    public OrderService(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public async Task ProcessOrderAsync()
    {
        var apiKey = _configuration["ExternalApiKey"];
        // Use API key
    }
}
```

**Azure Key Vault with Managed Identity**
```csharp
// For Azure-hosted apps, use Managed Identity
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{vaultName}.vault.azure.net/"),
    new DefaultAzureCredential(new DefaultAzureCredentialOptions
    {
        ManagedIdentityClientId = builder.Configuration["ManagedIdentityClientId"]
    }));
```

### HashiCorp Vault

```bash
# Store secret
vault kv put secret/myapp/db password=super-secret

# Retrieve secret
vault kv get -field=password secret/myapp/db
```

**Vault Integration in .NET**
```csharp
// Install: VaultSharp
var vaultClient = new VaultClient(vaultAddress, vaultToken);
var secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync("secret/myapp/db");
var password = secret.Data.Data["password"].ToString();
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque
stringData:
  connection-string: "Server=db;Database=MyAppDb;User Id=sa;Password=YourStrong@Passw0rd;TrustServerCertificate=True"
---
# Reference in deployment
env:
- name: ConnectionStrings__DefaultConnection
  valueFrom:
    secretKeyRef:
      name: db-secret
      key: connection-string
```

### Environment Variables (Development)

```csharp
// appsettings.Development.json (gitignored)
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyAppDb;..."
  },
  "ApplicationInsights": {
    "ConnectionString": "..."
  }
}

// Use User Secrets for local development
// dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=..."
```

## Infrastructure as Code

### Azure Bicep (Recommended for Azure)

```bicep
// main.bicep
@description('The name of the App Service plan')
param appServicePlanName string = 'myapp-plan'

@description('The name of the App Service')
param appServiceName string = 'myapp-api'

@description('The name of the SQL Server')
param sqlServerName string = 'myapp-sql'

@description('The name of the SQL Database')
param sqlDatabaseName string = 'MyAppDb'

@description('SQL administrator login')
param sqlAdministratorLogin string

@description('SQL administrator password')
@secure()
param sqlAdministratorLoginPassword string

// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: appServicePlanName
  location: resourceGroup().location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
}

// App Service
resource appService 'Microsoft.Web/sites@2022-03-01' = {
  name: appServiceName
  location: resourceGroup().location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|8.0'
      alwaysOn: true
    }
    httpsOnly: true
  }
}

// SQL Server
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: sqlServerName
  location: resourceGroup().location
  properties: {
    administratorLogin: sqlAdministratorLogin
    administratorLoginPassword: sqlAdministratorLoginPassword
  }
}

// SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2021-11-01' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: resourceGroup().location
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

// Redis Cache
resource redisCache 'Microsoft.Cache/redis@2022-05-01' = {
  name: 'myapp-redis'
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 0
    }
  }
}
```

### Terraform (Multi-Cloud)

```hcl
# Azure SQL Database
resource "azurerm_sql_server" "main" {
  name                         = "myapp-sql"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = var.sql_admin_login
  administrator_login_password = var.sql_admin_password
}

resource "azurerm_sql_database" "main" {
  name                = "MyAppDb"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_sql_server.main.name
  edition             = "Basic"
}

# Azure App Service
resource "azurerm_app_service_plan" "main" {
  name                = "myapp-plan"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Basic"
    size = "B1"
  }
}

resource "azurerm_app_service" "main" {
  name                = "myapp-api"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  app_service_plan_id = azurerm_app_service_plan.main.id

  site_config {
    linux_fx_version = "DOTNETCORE|8.0"
    always_on        = true
  }

  app_settings = {
    "ASPNETCORE_ENVIRONMENT" = "Production"
  }
}

# Azure Redis Cache
resource "azurerm_redis_cache" "main" {
  name                = "myapp-redis"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = 0
  family              = "C"
  sku_name            = "Basic"
}
```

## DevOps Checklist for .NET

### CI/CD
- [ ] CI/CD pipeline configured (GitHub Actions/Azure DevOps)
- [ ] .NET SDK setup in pipeline
- [ ] Automated testing (xUnit/NUnit) in CI
- [ ] Code coverage reporting (Coverlet)
- [ ] Security scanning (Snyk, Trivy)

### Containerization
- [ ] Docker multi-stage builds implemented
- [ ] .NET runtime optimization (trimming, AOT)
- [ ] Docker Compose for local development
- [ ] Container registry configured (Azure Container Registry/GitHub Container Registry)

### Deployment
- [ ] Kubernetes deployment manifests created (or Azure Container Apps)
- [ ] Blue-green or canary deployment strategy
- [ ] Deployment slots (Azure App Service)
- [ ] Feature flags configured (Azure App Configuration/LaunchDarkly)
- [ ] Zero-downtime deployments

### Monitoring & Observability
- [ ] Health checks (ASP.NET Core health checks)
- [ ] Application Insights configured
- [ ] Structured logging (Serilog)
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Custom metrics and events tracked
- [ ] Alerting configured

### Security & Configuration
- [ ] Secrets management (Azure Key Vault)
- [ ] Environment-specific configuration
- [ ] User Secrets for local development
- [ ] Secure connection strings

### Infrastructure
- [ ] Infrastructure as Code (Bicep/Terraform)
- [ ] Autoscaling configured (Kubernetes HPA/Azure App Service scaling)
- [ ] Backup and disaster recovery plan
- [ ] Database migration strategy (EF Core migrations)
- [ ] CDN configured (Azure CDN)

### Performance
- [ ] Response caching configured
- [ ] Output caching enabled
- [ ] Connection pooling optimized
- [ ] Resource limits set (CPU, memory)

## Resources

### .NET Deployment
- **ASP.NET Core Deployment:** https://learn.microsoft.com/aspnet/core/host-and-deploy/
- **.NET Docker Images:** https://hub.docker.com/_/microsoft-dotnet
- **Azure App Service:** https://learn.microsoft.com/azure/app-service/

### CI/CD
- **GitHub Actions for .NET:** https://docs.github.com/actions/guides/building-and-testing-net
- **Azure DevOps Pipelines:** https://learn.microsoft.com/azure/devops/pipelines/

### Monitoring & Observability
- **Application Insights:** https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
- **Serilog:** https://serilog.net/
- **OpenTelemetry .NET:** https://opentelemetry.io/docs/instrumentation/net/
- **Prometheus .NET:** https://github.com/prometheus-net/prometheus-net

### Containerization
- **Docker:** https://docs.docker.com/
- **Kubernetes:** https://kubernetes.io/docs/
- **Azure Container Apps:** https://learn.microsoft.com/azure/container-apps/

### Infrastructure as Code
- **Azure Bicep:** https://learn.microsoft.com/azure/azure-resource-manager/bicep/
- **Terraform Azure Provider:** https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs

### Feature Management
- **Azure App Configuration:** https://learn.microsoft.com/azure/azure-app-configuration/
- **Feature Management .NET:** https://github.com/Azure/AppConfiguration-DotnetProvider
