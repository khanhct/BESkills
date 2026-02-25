# Backend Testing Strategies

Comprehensive testing approaches, frameworks, and quality assurance practices for C#/.NET backend development (2025).

## Test Pyramid (70-20-10 Rule)

```
        /\
       /E2E\     10% - End-to-End Tests
      /------\
     /Integr.\ 20% - Integration Tests
    /----------\
   /   Unit     \ 70% - Unit Tests
  /--------------\
```

**Rationale:**
- Unit tests: Fast, cheap, isolate bugs quickly
- Integration tests: Verify component interactions
- E2E tests: Expensive, slow, but validate real user flows

## Unit Testing

### Testing Frameworks (.NET)

**xUnit** (Recommended)
- Modern, extensible testing framework
- Built-in parallel test execution
- Theory support for parameterized tests
- Best for: New projects, modern .NET development

**NUnit**
- Mature, feature-rich framework
- Excellent Visual Studio integration
- Strong attribute-based configuration
- Best for: Legacy projects, teams familiar with NUnit

**MSTest**
- Built-in Visual Studio support
- Integrated with Azure DevOps
- Best for: Microsoft ecosystem, Azure-hosted projects

### Framework Comparison

| Framework | Parallel Execution | Theory Support | CI/CD Integration | Best For |
|-----------|-------------------|----------------|-------------------|----------|
| xUnit | Built-in | Yes | Excellent | Modern projects |
| NUnit | Configurable | Yes | Excellent | Legacy projects |
| MSTest | Built-in | Limited | Excellent | Azure projects |

### Best Practices with xUnit

```csharp
// Good: Test single responsibility
public class UserServiceTests
{
    [Fact]
    public async Task CreateUser_WithValidData_ReturnsUser()
    {
        // Arrange
        var userData = new CreateUserDto 
        { 
            Email = "test@example.com", 
            Name = "Test" 
        };
        var userService = new UserService(_mockRepository.Object);

        // Act
        var user = await userService.CreateUserAsync(userData);

        // Assert
        Assert.Equal(userData.Email, user.Email);
        Assert.Equal(userData.Name, user.Name);
        Assert.NotEqual(Guid.Empty, user.Id);
    }

    [Fact]
    public async Task CreateUser_WithDuplicateEmail_ThrowsException()
    {
        // Arrange
        var userData = new CreateUserDto 
        { 
            Email = "existing@example.com", 
            Name = "Test" 
        };
        _mockRepository
            .Setup(r => r.GetByEmailAsync("existing@example.com"))
            .ReturnsAsync(new User { Email = "existing@example.com" });
        var userService = new UserService(_mockRepository.Object);

        // Act & Assert
        await Assert.ThrowsAsync<DuplicateEmailException>(
            () => userService.CreateUserAsync(userData));
    }

    [Fact]
    public async Task CreateUser_WithPassword_HashesPassword()
    {
        // Arrange
        var userData = new CreateUserDto 
        { 
            Email = "test@example.com", 
            Password = "plain123" 
        };
        var userService = new UserService(_mockRepository.Object);

        // Act
        var user = await userService.CreateUserAsync(userData);

        // Assert
        Assert.NotEqual("plain123", user.PasswordHash);
        Assert.True(user.PasswordHash.StartsWith("$argon2id$"));
    }
}
```

### Best Practices with NUnit

```csharp
[TestFixture]
public class UserServiceTests
{
    [Test]
    public async Task CreateUser_WithValidData_ReturnsUser()
    {
        // Arrange
        var userData = new CreateUserDto 
        { 
            Email = "test@example.com", 
            Name = "Test" 
        };
        var userService = new UserService(_mockRepository.Object);

        // Act
        var user = await userService.CreateUserAsync(userData);

        // Assert
        Assert.That(user.Email, Is.EqualTo(userData.Email));
        Assert.That(user.Name, Is.EqualTo(userData.Name));
        Assert.That(user.Id, Is.Not.EqualTo(Guid.Empty));
    }

    [TestCase("invalid-email")]
    [TestCase("")]
    [TestCase(null)]
    public async Task CreateUser_WithInvalidEmail_ThrowsException(string email)
    {
        // Arrange
        var userData = new CreateUserDto { Email = email };
        var userService = new UserService(_mockRepository.Object);

        // Act & Assert
        Assert.ThrowsAsync<ValidationException>(
            () => userService.CreateUserAsync(userData));
    }
}
```

### Mocking Frameworks

**Moq** (Most Popular)
```csharp
// Mock external dependencies
var mockEmailService = new Mock<IEmailService>();
mockEmailService
    .Setup(x => x.SendWelcomeEmailAsync(It.IsAny<string>()))
    .Returns(Task.CompletedTask);

var userService = new UserService(mockRepository.Object, mockEmailService.Object);

await userService.CreateUserAsync(new CreateUserDto { Email = "test@example.com" });

mockEmailService.Verify(
    x => x.SendWelcomeEmailAsync("test@example.com"), 
    Times.Once);
```

**NSubstitute** (Alternative)
```csharp
var emailService = Substitute.For<IEmailService>();
emailService.SendWelcomeEmailAsync(Arg.Any<string>()).Returns(Task.CompletedTask);

var userService = new UserService(mockRepository.Object, emailService);

await userService.CreateUserAsync(new CreateUserDto { Email = "test@example.com" });

await emailService.Received(1).SendWelcomeEmailAsync("test@example.com");
```

**FakeItEasy** (Alternative)
```csharp
var emailService = A.Fake<IEmailService>();
A.CallTo(() => emailService.SendWelcomeEmailAsync(A<string>._))
    .Returns(Task.CompletedTask);
```

## Integration Testing

### API Integration Tests with WebApplicationFactory

```csharp
public class UsersControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public UsersControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Replace real database with in-memory or test database
                services.RemoveAll(typeof(DbContextOptions<AppDbContext>));
                services.AddDbContext<AppDbContext>(options =>
                {
                    options.UseInMemoryDatabase("TestDb");
                });
            });
        });
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task POST_Users_WithValidData_Returns201()
    {
        // Arrange
        var userDto = new CreateUserDto 
        { 
            Email = "test@example.com", 
            Name = "Test User" 
        };
        var content = new StringContent(
            JsonSerializer.Serialize(userDto), 
            Encoding.UTF8, 
            "application/json");

        // Act
        var response = await _client.PostAsync("/api/users", content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        var user = JsonSerializer.Deserialize<UserDto>(responseBody, new JsonSerializerOptions 
        { 
            PropertyNameCaseInsensitive = true 
        });
        
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal("Test User", user.Name);

        // Verify database persistence
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var dbUser = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == "test@example.com");
        Assert.NotNull(dbUser);
    }

    [Fact]
    public async Task POST_Users_WithInvalidEmail_Returns400()
    {
        // Arrange
        var userDto = new CreateUserDto 
        { 
            Email = "invalid-email", 
            Name = "Test" 
        };
        var content = new StringContent(
            JsonSerializer.Serialize(userDto), 
            Encoding.UTF8, 
            "application/json");

        // Act
        var response = await _client.PostAsync("/api/users", content);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.Contains("Invalid email format", responseBody);
    }
}
```

### Database Testing with TestContainers (.NET)

```csharp
using Testcontainers.SqlServer;

public class DatabaseIntegrationTests : IAsyncLifetime
{
    private readonly SqlServerContainer _container;
    private readonly AppDbContext _dbContext;

    public DatabaseIntegrationTests()
    {
        _container = new SqlServerBuilder()
            .WithImage("mcr.microsoft.com/mssql/server:2022-latest")
            .WithPassword("YourStrong@Passw0rd")
            .Build();
    }

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer(_container.GetConnectionString())
            .Options;
        
        _dbContext = new AppDbContext(options);
        await _dbContext.Database.EnsureCreatedAsync();
    }

    [Fact]
    public async Task SaveUser_WithValidData_PersistsToDatabase()
    {
        // Arrange
        var user = new User 
        { 
            Email = "test@example.com", 
            Name = "Test User" 
        };

        // Act
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        // Assert
        var savedUser = await _dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == "test@example.com");
        Assert.NotNull(savedUser);
        Assert.Equal("Test User", savedUser.Name);
    }

    public async Task DisposeAsync()
    {
        await _dbContext.DisposeAsync();
        await _container.DisposeAsync();
    }
}
```

### Entity Framework Core Testing

```csharp
public class UserRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly UserRepository _repository;

    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        
        _context = new AppDbContext(options);
        _repository = new UserRepository(_context);
    }

    [Fact]
    public async Task GetByIdAsync_WithValidId_ReturnsUser()
    {
        // Arrange
        var user = new User { Email = "test@example.com", Name = "Test" };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetByIdAsync(user.Id);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test@example.com", result.Email);
    }

    public void Dispose()
    {
        _context?.Dispose();
    }
}
```

## Contract Testing (Microservices)

### Pact.NET (Consumer-Driven Contracts)

```csharp
using PactNet;
using PactNet.Matchers;

public class AuthServiceContractTests : IDisposable
{
    private readonly IPactBuilderV3 _pactBuilder;

    public AuthServiceContractTests()
    {
        var pact = Pact.V3("UserService", "AuthService", new PactConfig
        {
            PactDir = "../../../pacts",
            LogLevel = PactLogLevel.Information
        });
        
        _pactBuilder = pact.WithHttpInteractions();
    }

    [Fact]
    public async Task ValidateToken_WithValidToken_ReturnsValidResponse()
    {
        // Arrange
        _pactBuilder
            .UponReceiving("a request to validate token")
            .Given("user token exists")
            .WithRequest(HttpMethod.Post, "/auth/validate")
            .WithHeader("Content-Type", "application/json")
            .WithJsonBody(new
            {
                token = Match.Regex("valid-token-123", "^[a-zA-Z0-9-]+$")
            })
            .WillRespond()
            .WithStatus(System.Net.HttpStatusCode.OK)
            .WithHeader("Content-Type", "application/json")
            .WithJsonBody(new
            {
                valid = Match.Type(true),
                userId = Match.Type("123")
            });

        await _pactBuilder.VerifyAsync(async ctx =>
        {
            // Act
            var authClient = new AuthServiceClient(ctx.MockServerUri.ToString());
            var response = await authClient.ValidateTokenAsync("valid-token-123");

            // Assert
            Assert.True(response.Valid);
            Assert.Equal("123", response.UserId);
        });
    }

    public void Dispose()
    {
        _pactBuilder?.Dispose();
    }
}
```

## Load Testing

### Tools Comparison

**NBomber** (.NET Native Load Testing)
```csharp
using NBomber.CSharp;

var scenario = Scenario.Create("load_users_api", async context =>
{
    var response = await httpClient.GetAsync("https://api.example.com/users");
    
    return response.IsSuccessStatusCode 
        ? Response.Ok() 
        : Response.Fail();
})
.WithLoadSimulations(
    Simulation.InjectPerSec(rate: 100, during: TimeSpan.FromMinutes(2)), // Ramp up
    Simulation.InjectPerSec(rate: 100, during: TimeSpan.FromMinutes(5)), // Stay
    Simulation.InjectPerSec(rate: 0, during: TimeSpan.FromMinutes(2))    // Ramp down
)
.WithWarmUpDuration(TimeSpan.FromSeconds(10))
.WithDuration(TimeSpan.FromMinutes(10));

NBomberRunner
    .RegisterScenarios(scenario)
    .WithReportFormats(ReportFormat.Html, ReportFormat.Csv)
    .Run();
```

**k6** (Cross-platform, JavaScript-based)
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
  },
};

export default function () {
  const res = http.get('https://api.example.com/users');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
  sleep(1);
}
```

**Gatling** (JVM-based, Advanced Scenarios)
**JMeter** (GUI-based, Traditional)
**Azure Load Testing** (Cloud-native, Azure-hosted)

### Performance Thresholds

- **Response time:** p95 < 500ms, p99 < 1s
- **Throughput:** 1000+ req/sec (target based on SLA)
- **Error rate:** < 1%
- **Concurrent users:** Test at 2x expected peak

## E2E Testing

### Playwright for .NET (Modern, Multi-Browser)

```csharp
using Microsoft.Playwright;

public class UserRegistrationTests : IClassFixture<PlaywrightFixture>
{
    private readonly PlaywrightFixture _fixture;

    public UserRegistrationTests(PlaywrightFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task User_CanRegisterAndLogin()
    {
        // Arrange
        var page = await _fixture.Browser.NewPageAsync();

        // Act - Navigate to registration page
        await page.GotoAsync("https://app.example.com/register");

        // Fill registration form
        await page.FillAsync("input[name='email']", "test@example.com");
        await page.FillAsync("input[name='password']", "SecurePass123!");
        await page.ClickAsync("button[type='submit']");

        // Assert - Verify redirect to dashboard
        await page.WaitForURLAsync("**/dashboard");
        var heading = await page.Locator("h1").TextContentAsync();
        Assert.Contains("Welcome", heading);

        // Verify API call was made
        var response = await page.WaitForResponseAsync("/api/users");
        Assert.Equal(201, response.Status);
    }
}

public class PlaywrightFixture : IAsyncLifetime
{
    public IBrowser Browser { get; private set; }
    private IPlaywright _playwright;

    public async Task InitializeAsync()
    {
        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });
    }

    public async Task DisposeAsync()
    {
        await Browser?.DisposeAsync();
        _playwright?.Dispose();
    }
}
```

### ASP.NET Core Integration Testing

```csharp
public class UserRegistrationE2ETests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public UserRegistrationE2ETests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task RegisterUser_ThenLogin_ReturnsToken()
    {
        // Register
        var registerDto = new RegisterDto 
        { 
            Email = "test@example.com", 
            Password = "SecurePass123!" 
        };
        var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerDto);
        registerResponse.EnsureSuccessStatusCode();

        // Login
        var loginDto = new LoginDto 
        { 
            Email = "test@example.com", 
            Password = "SecurePass123!" 
        };
        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginDto);
        loginResponse.EnsureSuccessStatusCode();

        var token = await loginResponse.Content.ReadFromJsonAsync<AuthTokenDto>();
        Assert.NotNull(token);
        Assert.NotEmpty(token.AccessToken);
    }
}
```

## Database Migration Testing

**Critical:** 83% migrations fail without proper testing

### Entity Framework Core Migrations Testing

```csharp
public class MigrationTests : IClassFixture<MigrationTestFixture>
{
    private readonly MigrationTestFixture _fixture;

    public MigrationTests(MigrationTestFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Migrate_FromV1ToV2_WithoutDataLoss()
    {
        // Arrange - Insert test data in v1 schema
        using var v1Context = _fixture.CreateV1Context();
        v1Context.Users.Add(new User 
        { 
            Id = Guid.NewGuid(),
            Email = "test@example.com", 
            Name = "Test User" 
        });
        await v1Context.SaveChangesAsync();

        // Act - Run migration
        await _fixture.MigrateToVersionAsync("V2_AddCreatedAt");

        // Assert - Verify v2 schema
        using var v2Context = _fixture.CreateV2Context();
        var user = await v2Context.Users
            .FirstOrDefaultAsync(u => u.Email == "test@example.com");
        
        Assert.NotNull(user);
        Assert.Equal("Test User", user.Name);
        Assert.NotEqual(default(DateTime), user.CreatedAt);
    }

    [Fact]
    public async Task Rollback_FromV2ToV1_Successfully()
    {
        // Arrange
        await _fixture.MigrateToVersionAsync("V2_AddCreatedAt");
        
        // Act
        await _fixture.RollbackMigrationAsync("V2_AddCreatedAt");

        // Assert - Verify v1 schema restored
        using var context = _fixture.CreateContext();
        var columns = await context.Database
            .ExecuteSqlRawAsync(@"
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'Users'
            ");
        
        // Verify CreatedAt column doesn't exist
        Assert.DoesNotContain("CreatedAt", columns.ToString());
    }
}

public class MigrationTestFixture : IDisposable
{
    private readonly string _connectionString;
    private readonly DbContextOptions<AppDbContext> _options;

    public MigrationTestFixture()
    {
        _connectionString = "Server=(localdb)\\mssqllocaldb;Database=MigrationTest;Trusted_Connection=True;";
        _options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer(_connectionString)
            .Options;
    }

    public AppDbContext CreateContext() => new AppDbContext(_options);

    public async Task MigrateToVersionAsync(string migrationName)
    {
        using var context = CreateContext();
        await context.Database.MigrateAsync();
    }

    public async Task RollbackMigrationAsync(string migrationName)
    {
        using var context = CreateContext();
        var migrations = await context.Database.GetPendingMigrationsAsync();
        // Rollback logic
    }

    public void Dispose()
    {
        using var context = CreateContext();
        context.Database.EnsureDeleted();
    }
}
```

## Security Testing

### SAST (Static Application Security Testing)

```bash
# SonarQube for code quality + security (.NET)
dotnet sonarscanner begin \
  /k:"my-backend" \
  /d:sonar.host.url="http://localhost:9000" \
  /d:sonar.cs.opencover.reportsPaths="coverage.opencover.xml"

dotnet build
dotnet test --collect:"XPlat Code Coverage"

dotnet sonarscanner end

# Security Code Scan (SCS) for .NET
dotnet tool install -g security-scan
security-scan --project ./src/MyApi.csproj

# Semgrep for security patterns
semgrep --config auto src/
```

### DAST (Dynamic Application Security Testing)

```bash
# OWASP ZAP for runtime security scanning
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://api.example.com \
  -r zap-report.html

# OWASP ZAP .NET API
dotnet add package OWASP.ZAP.NetStandard
```

### Dependency Scanning (SCA)

```bash
# .NET Security Scanner
dotnet list package --vulnerable

# NuGet Security Audit
dotnet add package NuGetAudit

# Snyk for .NET
snyk test --file=MyApi.csproj
snyk monitor  # Continuous monitoring

# WhiteSource Bolt / Mend (formerly WhiteSource)
# Integrated with Azure DevOps and GitHub Actions
```

### Security Testing Libraries

```csharp
// OWASP Security Headers Testing
[Fact]
public async Task API_ReturnsSecurityHeaders()
{
    var response = await _client.GetAsync("/api/users");
    
    Assert.True(response.Headers.Contains("X-Content-Type-Options"));
    Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").First());
    Assert.True(response.Headers.Contains("X-Frame-Options"));
    Assert.True(response.Headers.Contains("Strict-Transport-Security"));
}
```

## Code Coverage

### Target Metrics (SonarQube Standards)

- **Overall coverage:** 80%+
- **Critical paths:** 100% (authentication, payment, data integrity)
- **New code:** 90%+

### Implementation with .NET

```bash
# Coverlet for code coverage
dotnet add package coverlet.msbuild
dotnet add package coverlet.collector

# Run tests with coverage
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover

# ReportGenerator for HTML reports
dotnet tool install -g dotnet-reportgenerator-globaltool
reportgenerator \
  -reports:"**/coverage.opencover.xml" \
  -targetdir:"coverage-report" \
  -reporttypes:Html

# With xUnit
dotnet test --collect:"XPlat Code Coverage" --settings:coverlet.runsettings

# Coverage thresholds in .csproj
<PropertyGroup>
  <Threshold>80</Threshold>
  <ThresholdType>line</ThresholdType>
  <ThresholdStat>total</ThresholdStat>
</PropertyGroup>
```

### coverlet.runsettings Configuration

```xml
<?xml version="1.0" encoding="utf-8" ?>
<RunSettings>
  <DataCollectionRunSettings>
    <DataCollectors>
      <DataCollector friendlyName="XPlat code coverage">
        <Configuration>
          <Format>opencover,cobertura</Format>
          <Exclude>[*.Tests]*</Exclude>
          <ExcludeByAttribute>Obsolete,GeneratedCodeAttribute,CompilerGeneratedAttribute</ExcludeByAttribute>
          <IncludeDirectory>../src</IncludeDirectory>
        </Configuration>
      </DataCollector>
    </DataCollectors>
  </DataCollectionRunSettings>
</RunSettings>
```

## CI/CD Testing Pipeline

### GitHub Actions (.NET)

```yaml
name: .NET Test Pipeline

on: [push, pull_request]

jobs:
  test:
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
        run: dotnet build --no-restore

      - name: Unit Tests
        run: dotnet test --no-build --verbosity normal --collect:"XPlat Code Coverage"

      - name: Integration Tests
        run: dotnet test tests/IntegrationTests/ --no-build --verbosity normal

      - name: E2E Tests
        run: dotnet test tests/E2ETests/ --no-build --verbosity normal

      - name: Security Scan
        run: |
          dotnet list package --vulnerable
          snyk test --file=src/MyApi.csproj || true

      - name: Generate Coverage Report
        run: |
          dotnet tool install -g dotnet-reportgenerator-globaltool
          reportgenerator -reports:"**/coverage.opencover.xml" -targetdir:"coverage-report" -reporttypes:Html

      - name: Upload Coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./**/coverage.opencover.xml
```

### Azure DevOps Pipeline (.NET)

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

stages:
- stage: Test
  displayName: 'Test Stage'
  jobs:
  - job: UnitTests
    displayName: 'Unit Tests'
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
        arguments: '--configuration $(buildConfiguration) --collect:"XPlat Code Coverage" --logger trx --results-directory $(Agent.TempDirectory)/TestResults'
    
    - task: PublishTestResults@2
      displayName: 'Publish Test Results'
      inputs:
        testResultsFormat: 'VSTest'
        testResultsFiles: '$(Agent.TempDirectory)/TestResults/**/*.trx'
    
    - task: PublishCodeCoverageResults@1
      displayName: 'Publish Code Coverage'
      inputs:
        codeCoverageTool: 'Cobertura'
        summaryFileLocation: '$(Agent.TempDirectory)/TestResults/**/coverage.cobertura.xml'
```

## Testing Best Practices

1. **Arrange-Act-Assert (AAA) Pattern**
   ```csharp
   [Fact]
   public void TestMethod()
   {
       // Arrange
       var service = new UserService();
       
       // Act
       var result = service.DoSomething();
       
       // Assert
       Assert.NotNull(result);
   }
   ```

2. **One assertion per test** (when practical)
   - Use `Assert.Multiple()` for multiple assertions when needed

3. **Descriptive test names** - `CreateUser_WithInvalidEmail_ThrowsValidationException`
   - Format: `MethodName_Scenario_ExpectedBehavior`

4. **Test edge cases** - Empty inputs, boundary values, null, default values
   ```csharp
   [Theory]
   [InlineData(null)]
   [InlineData("")]
   [InlineData("   ")]
   public void ValidateEmail_WithInvalidInput_ThrowsException(string email)
   {
       // Test implementation
   }
   ```

5. **Clean test data** - Use `IDisposable` or `IAsyncLifetime` for cleanup
   ```csharp
   public class TestFixture : IDisposable
   {
       public void Dispose()
       {
           // Cleanup test data
       }
   }
   ```

6. **Fast tests** - Unit tests < 10ms, Integration < 100ms
   - Use in-memory databases for integration tests when possible
   - Mock external dependencies

7. **Deterministic** - No flaky tests, avoid `Thread.Sleep()`, use `Task.Delay()` with timeouts
   ```csharp
   await Assert.ThrowsAsync<TimeoutException>(
       async () => await WaitForConditionAsync(TimeSpan.FromSeconds(5)));
   ```

8. **Independent** - Tests don't depend on execution order
   - Use `[Collection]` attribute for tests that share state
   - Use `IClassFixture<T>` for shared test context

9. **Use Test Data Builders** - Fluent API for creating test objects
   ```csharp
   var user = new UserBuilder()
       .WithEmail("test@example.com")
       .WithName("Test User")
       .Build();
   ```

10. **Async/Await Best Practices**
    ```csharp
    [Fact]
    public async Task AsyncMethod_ReturnsExpectedResult()
    {
        var result = await service.GetDataAsync();
        Assert.NotNull(result);
    }
    ```

11. **Use FluentAssertions for Readable Assertions**
    ```csharp
    result.Should().NotBeNull();
    result.Email.Should().Be("test@example.com");
    result.Should().BeEquivalentTo(expectedUser);
    ```

## Testing Checklist

- [ ] Unit tests cover 70% of codebase (xUnit/NUnit)
- [ ] Integration tests for all API endpoints (WebApplicationFactory)
- [ ] Contract tests for microservices (Pact.NET)
- [ ] Load tests configured (NBomber/k6)
- [ ] E2E tests for critical user flows (Playwright)
- [ ] Database migration tests (EF Core migrations)
- [ ] Security scanning in CI/CD (SAST, DAST, SCA)
- [ ] Code coverage reports automated (Coverlet)
- [ ] Tests run on every PR (GitHub Actions/Azure DevOps)
- [ ] Flaky tests eliminated
- [ ] Test data builders implemented
- [ ] Mocking framework configured (Moq/NSubstitute)
- [ ] Test fixtures properly disposed
- [ ] Async tests properly implemented

## Resources

### Testing Frameworks
- **xUnit:** https://xunit.net/
- **NUnit:** https://nunit.org/
- **MSTest:** https://learn.microsoft.com/dotnet/core/testing/unit-testing-with-mstest

### Mocking Frameworks
- **Moq:** https://github.com/moq/moq4
- **NSubstitute:** https://nsubstitute.github.io/
- **FakeItEasy:** https://fakeiteasy.github.io/

### Assertion Libraries
- **FluentAssertions:** https://fluentassertions.com/
- **Shouldly:** https://github.com/shouldly/shouldly

### Integration Testing
- **WebApplicationFactory:** https://learn.microsoft.com/aspnet/core/test/integration-tests
- **TestContainers .NET:** https://dotnet.testcontainers.org/
- **Testcontainers SQL Server:** https://dotnet.testcontainers.org/api/sql-server/

### Load Testing
- **NBomber:** https://nbomber.com/
- **k6:** https://k6.io/docs/
- **Azure Load Testing:** https://azure.microsoft.com/services/load-testing/

### E2E Testing
- **Playwright .NET:** https://playwright.dev/dotnet/
- **Selenium WebDriver:** https://www.selenium.dev/documentation/webdriver/

### Contract Testing
- **Pact.NET:** https://docs.pact.io/implementation-guides/dotnet
- **Pact Broker:** https://docs.pact.io/pact_broker

### Code Coverage
- **Coverlet:** https://github.com/coverlet-coverage/coverlet
- **ReportGenerator:** https://github.com/danielpalme/ReportGenerator
- **Codecov:** https://codecov.io/

### Security Testing
- **OWASP ZAP:** https://www.zaproxy.org/
- **Snyk:** https://snyk.io/
- **SonarQube:** https://www.sonarqube.org/
