# Backend Security

Security best practices, OWASP Top 10 mitigation, and modern security standards (2025).

## OWASP Top 10 (2025 RC1)

### New Entries (2025)
- **Supply Chain Failures** - Vulnerable dependencies, compromised packages
- **Mishandling of Exceptional Conditions** - Improper error handling exposing system info

### Top Vulnerabilities & Mitigation

#### 1. Broken Access Control
**Risk:** Users access unauthorized resources (28% of vulnerabilities)

**Mitigation:**
- Implement RBAC (Role-Based Access Control) with ASP.NET Core Authorization
- Deny by default, explicitly allow (policy-based authorization)
- Log access control failures (403/401, permission denials)
- Enforce authorization on backend (never client-side)
- Use JWT with proper claims and audience/issuer validation

```csharp
// Good: Server-side authorization check in ASP.NET Core
[Authorize(Roles = "Admin")]
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        // Additional resource-based authorization if needed
        var result = await _userService.DeleteAsync(id, User);
        if (!result)
        {
            return Forbid(); // Logs can capture this
        }

        return NoContent();
    }
}

// Program.cs - JWT + policy-based authorization
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));
});
```

#### 2. Cryptographic Failures
**Risk:** Sensitive data exposure, weak encryption

**Mitigation:**
- Use Argon2id for password hashing (replaces bcrypt as of 2025)
- TLS 1.3 for data in transit
- Encrypt sensitive data at rest (AES-256)
- Use `RandomNumberGenerator` for tokens, not `Random` / `Guid.NewGuid()` alone
- Never store passwords in plain text

```csharp
// Good: Argon2id password hashing in .NET (using Isopoh.Cryptography.Argon2)
public static class PasswordHasher
{
    public static string HashPassword(string password)
    {
        var config = new Argon2Config
        {
            Type = Argon2Type.Id,
            TimeCost = 4,
            MemoryCost = 1024 * 64, // 64 MB
            Lanes = 4,
            Threads = Environment.ProcessorCount,
            Password = Encoding.UTF8.GetBytes(password),
            Salt = RandomNumberGenerator.GetBytes(16)
        };

        using var argon2 = new Argon2(config);
        return argon2.Hash().EncodedString;
    }

    public static bool Verify(string hash, string password)
    {
        return Argon2.Verify(hash, password);
    }
}

// Token generation (sessions, reset links, etc.)
public static string GenerateSecureToken(int size = 32)
{
    var bytes = RandomNumberGenerator.GetBytes(size);
    return Convert.ToBase64String(bytes);
}
```

#### 3. Injection Attacks
**Risk:** SQL injection, NoSQL injection, command injection (6x increase 2020-2024)

**Mitigation (98% vulnerability reduction):**
- Use parameterized queries ALWAYS
- Input validation with allow-lists
- Escape special characters
- Use ORMs properly (avoid raw queries)

```csharp
// Bad: Vulnerable to SQL injection
var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
using var badCommand = new SqlCommand(sql, connection);

// Good: Parameterized query with ADO.NET
var goodSql = "SELECT * FROM Users WHERE Email = @email";
using var command = new SqlCommand(goodSql, connection);
command.Parameters.AddWithValue("@email", email);

using var reader = await command.ExecuteReaderAsync();

// Good: EF Core with LINQ (parameterization handled automatically)
var user = await dbContext.Users
    .SingleOrDefaultAsync(u => u.Email == email);
```

#### 4. Insecure Design
**Risk:** Flawed architecture, missing security controls

**Mitigation:**
- Threat modeling during design phase
- Security requirements from start
- Principle of least privilege
- Defense in depth (multiple security layers)

#### 5. Security Misconfiguration
**Risk:** Default credentials, verbose errors, unnecessary features enabled

**Mitigation:**
- Remove default accounts
- Disable directory listing
- Use security headers (CSP, HSTS, X-Frame-Options)
- Minimize attack surface
- Regular security audits

```csharp
// Security hardening for ASP.NET Core (Program.cs)
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts(); // Strict-Transport-Security
}

app.UseHttpsRedirection();

// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"] =
        "geolocation=(), microphone=(), camera=()";

    await next();
});
```

#### 6. Vulnerable Components
**Risk:** Outdated dependencies with known vulnerabilities

**Mitigation:**
- Regular dependency updates
- Use Dependabot/Renovate for automated updates
- Monitor CVE databases
- Software composition analysis (SCA) in CI/CD
- Lock file integrity checks

**.NET-Specific Tools:**
```bash
# Check for vulnerable NuGet packages
dotnet list package --vulnerable --include-transitive

# Update packages
dotnet list package --outdated
dotnet add package <PackageName> --version <LatestVersion>

# Use .NET security advisories
# https://github.com/dotnet/announcements/security
```

**NuGet Package Security:**
- Enable package source mapping in `NuGet.config`
- Use signed packages from trusted sources
- Verify package integrity with `nuget verify`
- Use `dotnet restore --no-cache` in CI/CD for reproducible builds

**Automated Scanning:**
- **OWASP Dependency-Check** - Scans .NET dependencies
- **Snyk** - .NET vulnerability scanning
- **WhiteSource** - .NET SCA tool
- **GitHub Dependabot** - Automated PRs for .NET packages

#### 7. Authentication Failures
**Risk:** Weak passwords, session hijacking, credential stuffing

**Mitigation:**
- MFA mandatory for admin accounts
- Rate limiting on login endpoints (10 attempts/minute)
- Strong password policies (12+ chars, complexity)
- Session timeout (15 mins idle, 8 hours absolute)
- FIDO2/WebAuthn for passwordless auth

**.NET Implementation:**
```csharp
// ASP.NET Core Identity with security settings
builder.Services.AddIdentity<User, Role>(options =>
{
    // Password policy
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // Account lockout
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    
    // Sign-in settings
    options.SignIn.RequireConfirmedEmail = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// Rate limiting for login endpoint
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("LoginPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(15)
            }));
});

// Apply to login endpoint
app.MapPost("/api/auth/login", Login)
   .RequireRateLimiting("LoginPolicy");
```

#### 8. Software & Data Integrity Failures
**Risk:** CI/CD pipeline compromise, unsigned updates

**Mitigation:**
- Code signing for releases
- Verify integrity of packages (lock files)
- Secure CI/CD pipelines (immutable builds)
- Checksum verification

#### 9. Logging & Monitoring Failures
**Risk:** Breaches undetected, insufficient audit trail

**Mitigation:**
- Log authentication events (success/failure)
- Log access control failures
- Centralized logging (ELK Stack, Splunk)
- Alerting on suspicious patterns
- Log rotation and retention policies

#### 10. Server-Side Request Forgery (SSRF)
**Risk:** Server makes malicious requests to internal resources

**Mitigation:**
- Validate and sanitize URLs
- Allow-list for remote resources
- Network segmentation
- Disable unnecessary protocols (file://, gopher://)

**.NET Implementation:**
```csharp
// Bad: Vulnerable to SSRF
public async Task<IActionResult> FetchUrl(string url)
{
    using var client = new HttpClient();
    var response = await client.GetAsync(url); // Dangerous!
    return Ok(await response.Content.ReadAsStringAsync());
}

// Good: SSRF protection
public class SafeHttpClient
{
    private static readonly HashSet<string> AllowedSchemes = new() { "https", "http" };
    private static readonly HashSet<string> BlockedHosts = new() 
    { 
        "localhost", "127.0.0.1", "0.0.0.0", 
        "169.254.169.254", // AWS metadata
        "10.0.0.0", "172.16.0.0", "192.168.0.0" // Private IPs
    };

    public static bool IsUrlSafe(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (!AllowedSchemes.Contains(uri.Scheme.ToLower()))
            return false;

        var host = uri.Host.ToLower();
        if (BlockedHosts.Contains(host))
            return false;

        // Check for private IP ranges
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();
            
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                // Check private IP ranges
                if (bytes[0] == 10 || 
                    (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                    (bytes[0] == 192 && bytes[1] == 168))
                    return false;
            }
        }

        return true;
    }
}

// Usage
public async Task<IActionResult> FetchUrl(string url)
{
    if (!SafeHttpClient.IsUrlSafe(url))
        return BadRequest("Invalid or unsafe URL");

    using var client = new HttpClient();
    client.Timeout = TimeSpan.FromSeconds(10); // Prevent long-running requests
    var response = await client.GetAsync(url);
    return Ok(await response.Content.ReadAsStringAsync());
}
```

## Input Validation (Prevents 70%+ Vulnerabilities)

### Validation Strategies

**1. Type Validation**
```csharp
// Use Data Annotations with ASP.NET Core
public class CreateUserDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = default!;

    [Required]
    [MinLength(12)]
    [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
        ErrorMessage = "Password must contain upper, lower, and digit.")]
    public string Password { get; set; } = default!;

    [Range(18, 120)]
    public int Age { get; set; }
}

// FluentValidation example
public class CreateUserDtoValidator : AbstractValidator<CreateUserDto>
{
    public CreateUserDtoValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Password)
            .MinimumLength(12)
            .Matches("[A-Z]").WithMessage("Password must contain uppercase.")
            .Matches("[a-z]").WithMessage("Password must contain lowercase.")
            .Matches("\\d").WithMessage("Password must contain a digit.");
        RuleFor(x => x.Age).InclusiveBetween(18, 120);
    }
}
```

**2. Sanitization**
```csharp
// Sanitize HTML input in .NET using Ganss.Xss
var sanitizer = new HtmlSanitizer();
sanitizer.AllowedSchemes.Add("data");

string clean = sanitizer.Sanitize(userInput);
```

**3. Allow-lists (Preferred over Deny-lists)**
```csharp
// Good: Allow-list approach for patch/update operations
var allowedFields = new[] { "Name", "Email", "Age" };

var sanitized = new Dictionary<string, object?>();
foreach (var kvp in inputDictionary)
{
    if (allowedFields.Contains(kvp.Key))
    {
        sanitized[kvp.Key] = kvp.Value;
    }
}

// Or better: use dedicated DTOs instead of dynamic objects
```

## Rate Limiting

### Token Bucket Algorithm (Industry Standard)

```csharp
// ASP.NET Core rate limiting (built-in in .NET 7+)
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("ApiPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(15),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));
});

app.UseRateLimiter();

app.MapGroup("/api")
   .RequireRateLimiting("ApiPolicy");
```

### API-Specific Limits

- **Authentication:** 10 attempts/15 min
- **Public APIs:** 100 requests/15 min
- **Authenticated APIs:** 1000 requests/15 min
- **Admin endpoints:** 50 requests/15 min

## Security Headers

```csharp
// Essential security headers (2025) in ASP.NET Core
app.Use(async (context, next) =>
{
    context.Response.Headers["Strict-Transport-Security"] =
        "max-age=31536000; includeSubDomains";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"] =
        "geolocation=(), microphone=(), camera=()";

    await next();
});
```

## Secrets Management

### Best Practices

1. **Never commit secrets** - Use .env files (gitignored)
2. **Environment-specific** - Different secrets per environment
3. **Rotation policy** - Rotate secrets every 90 days
4. **Encryption at rest** - Encrypt secrets in secret managers
5. **Least privilege** - Minimal permissions per secret

### Tools

- **HashiCorp Vault** - Multi-cloud, dynamic secrets
- **AWS Secrets Manager** - Managed service, auto-rotation
- **Azure Key Vault** - Integrated with Azure services
- **Pulumi ESC** - Unified secrets orchestration (2025 trend)

```csharp
// Good: Secrets from configuration/environment in .NET
var builder = WebApplication.CreateBuilder(args);

// Azure Key Vault integration
if (builder.Environment.IsProduction())
{
    var keyVaultUrl = builder.Configuration["AzureKeyVault:Url"];
    var clientId = builder.Configuration["AzureKeyVault:ClientId"];
    var clientSecret = builder.Configuration["AzureKeyVault:ClientSecret"];
    
    builder.Configuration.AddAzureKeyVault(
        new Uri(keyVaultUrl!),
        new Azure.Identity.ClientSecretCredential(
            builder.Configuration["AzureKeyVault:TenantId"]!,
            clientId!,
            clientSecret!
        ),
        new Azure.Extensions.AspNetCore.Configuration.Secrets.KeyVaultSecretManager()
    );
}

// Or use Managed Identity (recommended for Azure)
// builder.Configuration.AddAzureKeyVault(
//     new Uri(keyVaultUrl!),
//     new DefaultAzureCredential()
// );

// Access secrets
var dbPassword = builder.Configuration["Database:Password"];
if (string.IsNullOrWhiteSpace(dbPassword))
{
    throw new InvalidOperationException("Database password not configured.");
}

// Use IOptions pattern for type-safe configuration
builder.Services.Configure<DatabaseOptions>(
    builder.Configuration.GetSection("Database"));
```

**Secrets Management Best Practices:**
- Use **Azure Key Vault** for Azure deployments
- Use **AWS Secrets Manager** for AWS deployments
- Use **HashiCorp Vault** for on-premises or multi-cloud
- Never store secrets in `appsettings.json` (use User Secrets for local dev)
- Use **Managed Identity** when possible (no credentials needed)
- Rotate secrets regularly (90 days)
- Use separate key vaults per environment

## API Security Checklist

- [ ] Use HTTPS/TLS 1.3 only
- [ ] Implement OAuth 2.1 + JWT for authentication
- [ ] Rate limiting on all endpoints (ASP.NET Core Rate Limiting)
- [ ] Input validation on all inputs (FluentValidation or Data Annotations)
- [ ] Parameterized queries (prevent SQL injection - EF Core/Dapper)
- [ ] Security headers configured (middleware or NWebSec)
- [ ] CORS properly configured (not `*` in production)
- [ ] API versioning implemented
- [ ] Error messages don't leak system info (custom exception handlers)
- [ ] Logging authentication events (Serilog + Application Insights)
- [ ] MFA for admin accounts (ASP.NET Core Identity + TOTP)
- [ ] Regular security audits (quarterly)
- [ ] Dependency scanning (dotnet list package --vulnerable)
- [ ] Secrets stored in Key Vault (not in configuration files)
- [ ] CSRF protection enabled (Antiforgery middleware)
- [ ] Content Security Policy (CSP) headers configured
- [ ] API keys rotated regularly (if used)
- [ ] Health checks don't expose sensitive information

## Common Security Pitfalls

1. **Client-side validation only** - Always validate on server (use FluentValidation or Data Annotations)
2. **Using `Random`/`Guid.NewGuid()` for tokens** - Use `RandomNumberGenerator` for cryptographic operations
3. **Storing passwords with weak algorithms (e.g., bcrypt with low cost, SHA-256)** - Use Argon2id (2025 standard) or strong PBKDF2 (ASP.NET Core Identity uses PBKDF2 by default)
4. **Trusting user input** - Validate and sanitize everything (use HtmlSanitizer for HTML input)
5. **Weak CORS configuration** - Don't use `*` in production, specify exact origins
6. **Insufficient logging** - Log all authentication/authorization events (use Serilog with structured logging)
7. **No rate limiting** - Implement on all public endpoints (ASP.NET Core Rate Limiting in .NET 7+)
8. **Storing secrets in appsettings.json** - Use Azure Key Vault, User Secrets, or environment variables
9. **Not using HTTPS in production** - Always enforce HTTPS redirection
10. **Weak JWT validation** - Always validate issuer, audience, and signing key
11. **Missing CSRF protection** - Enable Antiforgery middleware for state-changing operations
12. **Exposing stack traces** - Use custom exception handlers in production
13. **SQL injection with raw queries** - Always use parameterized queries or EF Core LINQ
14. **No dependency scanning** - Regularly check for vulnerable NuGet packages
15. **Optimizely-specific: Not securing content APIs** - Implement proper authorization for Optimizely Content API endpoints

## Optimizely-Specific Security Considerations

### Content Security
- **Access Control:** Implement proper authorization for content editing and publishing
- **API Security:** Secure Optimizely Content API endpoints with JWT authentication
- **User Management:** Use Optimizely's built-in user management with proper role assignments
- **Content Versioning:** Leverage Optimizely's versioning for audit trails and rollback capabilities

```csharp
// Optimizely authorization example
[Authorize(Roles = "WebEditors, Administrators")]
public class ContentController : ControllerBase
{
    private readonly IContentLoader _contentLoader;
    private readonly IContentRepository _contentRepository;

    public ContentController(IContentLoader contentLoader, IContentRepository contentRepository)
    {
        _contentLoader = contentLoader;
        _contentRepository = contentRepository;
    }

    [HttpPost("publish/{contentId}")]
    public async Task<IActionResult> PublishContent(int contentId)
    {
        // Additional authorization check
        var content = _contentLoader.Get<PageData>(contentId);
        if (!User.HasClaim("CanPublish", content.ContentTypeID.ToString()))
        {
            return Forbid();
        }

        // Publish content
        _contentRepository.Publish(content, PublishAction.Publish);
        return Ok();
    }
}
```

### Commerce Security
- **Payment Data:** Never store credit card data (use PCI-compliant payment processors)
- **Order Data:** Encrypt sensitive order information at rest
- **API Keys:** Rotate Optimizely Commerce API keys regularly
- **Access Control:** Implement proper role-based access for commerce operations

## .NET Security Libraries & Tools

### Security Libraries
- **NWebSec** - Security headers middleware for ASP.NET Core
- **HtmlSanitizer (Ganss.Xss)** - HTML sanitization library
- **Fido2NetLib** - FIDO2/WebAuthn implementation for .NET
- **Isopoh.Cryptography.Argon2** - Argon2 password hashing
- **Microsoft.AspNetCore.Identity** - Built-in authentication and authorization

### Security Tools
- **dotnet list package --vulnerable** - Check for vulnerable NuGet packages
- **OWASP Dependency-Check** - Dependency vulnerability scanning
- **Snyk** - .NET security scanning
- **Azure Security Center** - Security monitoring for Azure deployments
- **Application Insights** - Security event logging and monitoring

## Resources

### General Security
- **OWASP Top 10 (2025):** https://owasp.org/www-project-top-ten/
- **OWASP Cheat Sheets:** https://cheatsheetseries.owasp.org/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **NIST Guidelines:** https://www.nist.gov/cybersecurity

### .NET Security
- **ASP.NET Core Security:** https://learn.microsoft.com/aspnet/core/security/
- **.NET Security Best Practices:** https://learn.microsoft.com/dotnet/standard/security/
- **Azure Key Vault:** https://learn.microsoft.com/azure/key-vault/
- **ASP.NET Core Identity:** https://learn.microsoft.com/aspnet/core/security/authentication/identity

### Optimizely Security
- **Optimizely Security Documentation:** https://docs.developers.optimizely.com/content-management-system/docs/security
- **Optimizely Content API Security:** https://docs.developers.optimizely.com/content-management-system/docs/content-delivery-api
