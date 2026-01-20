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
- Regular dependency updates (npm audit, pip-audit)
- Use Dependabot/Renovate for automated updates
- Monitor CVE databases
- Software composition analysis (SCA) in CI/CD
- Lock file integrity checks

```bash
# Check for vulnerabilities
npm audit fix
pip-audit --fix
```

#### 7. Authentication Failures
**Risk:** Weak passwords, session hijacking, credential stuffing

**Mitigation:**
- MFA mandatory for admin accounts
- Rate limiting on login endpoints (10 attempts/minute)
- Strong password policies (12+ chars, complexity)
- Session timeout (15 mins idle, 8 hours absolute)
- FIDO2/WebAuthn for passwordless auth

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

// Add Azure Key Vault or other providers as needed
// builder.Configuration.AddAzureKeyVault(...);

var dbPassword = builder.Configuration["Database:Password"];
if (string.IsNullOrWhiteSpace(dbPassword))
{
    throw new InvalidOperationException("Database password not configured.");
}
```

## API Security Checklist

- [ ] Use HTTPS/TLS 1.3 only
- [ ] Implement OAuth 2.1 + JWT for authentication
- [ ] Rate limiting on all endpoints
- [ ] Input validation on all inputs
- [ ] Parameterized queries (prevent SQL injection)
- [ ] Security headers configured
- [ ] CORS properly configured (not `*` in production)
- [ ] API versioning implemented
- [ ] Error messages don't leak system info
- [ ] Logging authentication events
- [ ] MFA for admin accounts
- [ ] Regular security audits (quarterly)

## Common Security Pitfalls

1. **Client-side validation only** - Always validate on server
2. **Using `Random`/`Guid.NewGuid()` for tokens** - Use `RandomNumberGenerator`
3. **Storing passwords with weak algorithms (e.g., bcrypt with low cost, SHA-256)** - Use Argon2id (2025 standard) or strong PBKDF2
4. **Trusting user input** - Validate and sanitize everything
5. **Weak CORS configuration** - Don't use `*` in production
6. **Insufficient logging** - Log all authentication/authorization events
7. **No rate limiting** - Implement on all public endpoints

## Resources

- **OWASP Top 10 (2025):** https://owasp.org/www-project-top-ten/
- **OWASP Cheat Sheets:** https://cheatsheetseries.owasp.org/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **NIST Guidelines:** https://www.nist.gov/cybersecurity
