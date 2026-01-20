# Backend Authentication & Authorization

Modern authentication patterns for C#/.NET including OAuth 2.1, JWT, RBAC, and MFA using ASP.NET Core Identity and Microsoft authentication libraries (2025 standards).

## OAuth 2.1 (2025 Standard)

### Key Changes from OAuth 2.0

**Mandatory:**
- PKCE (Proof Key for Code Exchange) for all clients
- Exact redirect URI matching
- State parameter for CSRF protection

**Deprecated:**
- Implicit grant flow (security risk)
- Resource owner password credentials grant
- Bearer token in query strings

### Authorization Code Flow with PKCE

**Using ASP.NET Core Identity with External Providers:**
```csharp
// Program.cs - Configure OAuth 2.1 with PKCE
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "OpenIdConnect";
})
.AddCookie()
.AddOpenIdConnect("OpenIdConnect", options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"];
    options.ClientId = builder.Configuration["Authentication:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true; // PKCE enabled by default in .NET 8+
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";
});

// Custom PKCE implementation (if needed)
public class PkceHelper
{
    public static (string CodeVerifier, string CodeChallenge) GeneratePkceCodes()
    {
        // Generate code verifier (43-128 characters, URL-safe base64)
        var codeVerifierBytes = RandomNumberGenerator.GetBytes(32);
        var codeVerifier = Convert.ToBase64String(codeVerifierBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        
        // Generate code challenge (SHA256 hash of verifier)
        var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        var codeChallenge = Convert.ToBase64String(challengeBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        
        return (codeVerifier, codeChallenge);
    }
}

// OAuth client implementation
public class OAuthClient
{
    private readonly HttpClient _httpClient;
    
    public async Task<string> ExchangeCodeForTokenAsync(
        string code,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://auth.example.com/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", redirectUri },
                { "client_id", _clientId },
                { "code_verifier", codeVerifier }
            })
        };
        
        var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        
        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken);
        return tokenResponse?.AccessToken ?? throw new InvalidOperationException("Token response is null");
    }
}
```

## JWT (JSON Web Tokens)

### Structure

```
Header.Payload.Signature
eyJhbGciOi...  .  eyJzdWIiOi...  .  SflKxwRJ...
```

### Best Practices (2025)

1. **Short expiration** - Access tokens: 15 minutes, Refresh tokens: 7 days
2. **Use RS256** - Asymmetric signing (not HS256 for public APIs)
3. **Validate everything** - Signature, issuer, audience, expiration
4. **Include minimal claims** - Don't include sensitive data
5. **Refresh token rotation** - Issue new refresh token on each use

### Implementation with ASP.NET Core

**Configure JWT Authentication:**
```csharp
// Program.cs - Configure JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            ClockSkew = TimeSpan.Zero // Remove default 5-minute clock skew
        };
        
        // For RS256 (asymmetric signing)
        // options.TokenValidationParameters.IssuerSigningKey = 
        //     new RsaSecurityKey(RSA.Create().ImportRSAPublicKey(...));
    });

// Generate JWT Token
public class TokenService
{
    private readonly IConfiguration _configuration;
    
    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public string GenerateAccessToken(User user, IEnumerable<string> roles)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, 
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), 
                ClaimValueTypes.Integer64)
        };
        
        // Add roles
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15), // Short expiration
            signingCredentials: creds);
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    public string GenerateRefreshToken()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(randomBytes);
    }
}

// Verify JWT (automatic with ASP.NET Core middleware)
// The JWT bearer middleware validates tokens automatically
// Access user claims in controller:
[Authorize]
public class UsersController : ControllerBase
{
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var email = User.FindFirstValue(ClaimTypes.Email);
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);
        
        return Ok(new { UserId = userId, Email = email, Roles = roles });
    }
}
```

## Role-Based Access Control (RBAC)

### RBAC Model

```
Users → Roles → Permissions → Resources
```

### Implementation (ASP.NET Core)

**Using Policy-Based Authorization:**
```csharp
// Define roles as constants
public static class Roles
{
    public const string Admin = "Admin";
    public const string Editor = "Editor";
    public const string Viewer = "Viewer";
}

// Program.cs - Configure authorization policies
builder.Services.AddAuthorization(options =>
{
    // Policy-based authorization
    options.AddPolicy("AdminOnly", policy => 
        policy.RequireRole(Roles.Admin));
    
    options.AddPolicy("EditorOrAdmin", policy => 
        policy.RequireRole(Roles.Admin, Roles.Editor));
    
    // Custom policy with requirements
    options.AddPolicy("CanEdit", policy =>
        policy.RequireAssertion(context =>
            context.User.IsInRole(Roles.Admin) ||
            context.User.IsInRole(Roles.Editor)));
});

// Usage in controllers
[ApiController]
[Route("api/[controller]")]
[Authorize] // Require authentication
public class PostsController : ControllerBase
{
    [HttpPost]
    [Authorize(Roles = $"{Roles.Admin},{Roles.Editor}")] // Multiple roles
    public async Task<IActionResult> CreatePost(CreatePostDto dto)
    {
        // Only Admin or Editor can create posts
        return Ok();
    }
    
    [HttpDelete("{id}")]
    [Authorize(Policy = "AdminOnly")] // Policy-based
    public async Task<IActionResult> DeletePost(Guid id)
    {
        // Only Admin can delete posts
        return NoContent();
    }
    
    [HttpGet]
    [AllowAnonymous] // No authentication required
    public async Task<IActionResult> GetPosts()
    {
        // Public endpoint
        return Ok();
    }
}

// Custom Authorization Handler
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    
    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }
}

public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirstValue(ClaimTypes.DateOfBirth);
        
        if (dateOfBirthClaim != null && 
            DateTime.TryParse(dateOfBirthClaim, out var dateOfBirth))
        {
            var age = DateTime.Today.Year - dateOfBirth.Year;
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}

// Register handler
builder.Services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();

// Use custom requirement
[Authorize(Policy = "MinimumAge18")]
public class RestrictedController : ControllerBase { }
```

### RBAC Best Practices

1. **Deny by default** - Explicitly grant permissions
2. **Least privilege** - Minimum permissions needed
3. **Role hierarchy** - Admin inherits Editor inherits Viewer
4. **Separate roles and permissions** - Flexible permission assignment
5. **Audit trail** - Log role changes and access

## Multi-Factor Authentication (MFA)

### TOTP (Time-Based One-Time Password)

**Using Otp.NET Library:**
```csharp
// Install: Otp.NET
using OtpNet;

public class TotpService
{
    public (string Secret, string QrCodeUrl) GenerateSecret(string userEmail)
    {
        // Generate secret key
        var secretKey = KeyGeneration.GenerateRandomKey(20); // 160 bits
        var base32Secret = Base32Encoding.ToString(secretKey);
        
        // Generate QR code URL
        var issuer = "MyCompany";
        var accountTitle = userEmail;
        var qrCodeUrl = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{accountTitle}?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}";
        
        return (base32Secret, qrCodeUrl);
    }
    
    public bool VerifyTotp(string secret, string userToken, int timeStepWindow = 2)
    {
        var secretKey = Base32Encoding.ToBytes(secret);
        var totp = new Totp(secretKey);
        
        // Verify with time step tolerance
        return totp.VerifyTotp(userToken, out _, new VerificationWindow(2, 2));
    }
    
    public string GenerateTotp(string secret)
    {
        var secretKey = Base32Encoding.ToBytes(secret);
        var totp = new Totp(secretKey);
        return totp.ComputeTotp();
    }
}

// Controller implementation
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class MfaController : ControllerBase
{
    private readonly TotpService _totpService;
    private readonly IUserRepository _userRepository;
    
    [HttpPost("setup")]
    public async Task<IActionResult> SetupMfa()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _userRepository.GetByIdAsync(userId);
        
        var (secret, qrCodeUrl) = _totpService.GenerateSecret(user.Email ?? string.Empty);
        
        // Store secret (encrypted) in database
        user.MfaSecret = secret; // Should be encrypted!
        await _userRepository.UpdateAsync(user);
        
        return Ok(new { Secret = secret, QrCodeUrl = qrCodeUrl });
    }
    
    [HttpPost("verify")]
    public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaDto dto)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _userRepository.GetByIdAsync(userId);
        
        if (user.MfaSecret == null)
        {
            return BadRequest("MFA not set up");
        }
        
        var isValid = _totpService.VerifyTotp(user.MfaSecret, dto.Token);
        
        if (isValid)
        {
            // Mark MFA as verified in session/claims
            return Ok(new { Verified = true });
        }
        
        return BadRequest("Invalid token");
    }
}
```

### FIDO2/WebAuthn (Passwordless - 2025 Standard)

**Benefits:**
- Phishing-resistant
- No shared secrets
- Hardware-backed security
- Better UX (biometrics, security keys)

**Implementation with Fido2NetLib:**
```csharp
// Install: Fido2NetLib
using Fido2NetLib;

public class WebAuthnService
{
    private readonly IFido2 _fido2;
    
    public WebAuthnService(IFido2 fido2)
    {
        _fido2 = fido2;
    }
    
    public CredentialCreateOptions GenerateRegistrationOptions(
        string userName,
        string displayName,
        byte[] userId)
    {
        var options = _fido2.RequestNewCredential(
            new Fido2User
            {
                Id = userId,
                Name = userName,
                DisplayName = displayName
            },
            new List<PublicKeyCredentialDescriptor>(),
            authenticatorSelection: new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                UserVerification = UserVerificationRequirement.Required,
                ResidentKey = ResidentKeyRequirement.Required
            },
            attestationConveyancePreference: AttestationConveyancePreference.Direct);
        
        return options;
    }
    
    public async Task<Fido2.CredentialMakeResult> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions)
    {
        var result = await _fido2.MakeNewCredentialAsync(
            attestationResponse,
            originalOptions,
            async (args, cancellationToken) =>
            {
                // Check if credential already exists
                return false; // Credential doesn't exist
            });
        
        return result;
    }
    
    public AssertionOptions GenerateAssertionOptions(
        IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials)
    {
        var options = _fido2.GetAssertionOptions(
            allowedCredentials,
            UserVerificationRequirement.Required);
        
        return options;
    }
    
    public async Task<AssertionVerificationResult> VerifyAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        byte[] storedPublicKey,
        uint storedCounter,
        byte[] userId)
    {
        var result = await _fido2.MakeAssertionAsync(
            assertionResponse,
            originalOptions,
            storedPublicKey,
            storedCounter,
            async (args, cancellationToken) =>
            {
                // Verify user handle matches
                return args.UserHandle.SequenceEqual(userId);
            });
        
        return result;
    }
}

// Controller
[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly WebAuthnService _webAuthnService;
    
    [HttpPost("register/begin")]
    [Authorize]
    public IActionResult BeginRegistration()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userName = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        
        var options = _webAuthnService.GenerateRegistrationOptions(
            userName,
            userName,
            userId.ToByteArray());
        
        // Store challenge in session/cache
        HttpContext.Session.SetString("webauthn_challenge", options.Challenge);
        
        return Ok(options);
    }
    
    [HttpPost("register/complete")]
    [Authorize]
    public async Task<IActionResult> CompleteRegistration(
        [FromBody] AuthenticatorAttestationRawResponse response)
    {
        var challenge = HttpContext.Session.GetString("webauthn_challenge");
        // Reconstruct original options and verify
        // Store credential in database
        
        return Ok();
    }
}
```

## Session Management

### Best Practices

1. **Secure cookies** - HttpOnly, Secure, SameSite=Strict
2. **Session timeout** - Idle: 15 minutes, Absolute: 8 hours
3. **Regenerate session ID** - After login, privilege elevation
4. **Server-side storage** - Redis for distributed systems
5. **CSRF protection** - SameSite cookies + CSRF tokens

### Implementation (ASP.NET Core)

**Session Configuration:**
```csharp
// Program.cs - Configure session with Redis
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15); // Idle timeout
    options.Cookie.HttpOnly = true; // No JavaScript access
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only
    options.Cookie.SameSite = SameSiteMode.Strict; // CSRF protection
    options.Cookie.Name = ".MyApp.Session";
    options.Cookie.IsEssential = true;
});

// Use session middleware
app.UseSession();

// Distributed session with Redis
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "MyApp:";
});

builder.Services.AddDistributedMemoryCache(); // Fallback
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Usage in controllers
public class SessionController : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        // Validate credentials
        var user = await _userService.ValidateCredentialsAsync(dto.Email, dto.Password);
        
        if (user == null)
        {
            return Unauthorized();
        }
        
        // Regenerate session ID after login (security best practice)
        await HttpContext.Session.LoadAsync();
        HttpContext.Session.Clear();
        
        // Store user info in session
        HttpContext.Session.SetString("UserId", user.Id.ToString());
        HttpContext.Session.SetString("Email", user.Email ?? string.Empty);
        
        return Ok();
    }
    
    [HttpGet("session")]
    [Authorize]
    public IActionResult GetSession()
    {
        var userId = HttpContext.Session.GetString("UserId");
        var email = HttpContext.Session.GetString("Email");
        
        return Ok(new { UserId = userId, Email = email });
    }
}

// CSRF Protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.HttpOnly = false; // JavaScript needs access for AJAX
});

// Use antiforgery
app.UseAntiforgery();
```

## Password Security

### Argon2id (2025 Standard - Replaces bcrypt)

**Why Argon2id:**
- Winner of Password Hashing Competition (2015)
- Memory-hard (resistant to GPU/ASIC attacks)
- Configurable CPU and memory cost
- Combines Argon2i (data-independent) + Argon2d (data-dependent)

**Using ASP.NET Core Identity (Built-in Argon2id Support):**
```csharp
// ASP.NET Core Identity uses PBKDF2 by default, but can be configured
// For Argon2id, use Isopoh.Cryptography.Argon2

// Install: Isopoh.Cryptography.Argon2
using Isopoh.Cryptography.Argon2;

public class PasswordHasher
{
    public string HashPassword(string password)
    {
        var config = new Argon2Config
        {
            Type = Argon2Type.Id, // Argon2id
            TimeCost = 4, // 4 iterations
            MemoryCost = 1024 * 64, // 64 MB
            Lanes = 4, // 4 parallel lanes
            Threads = Environment.ProcessorCount,
            Password = Encoding.UTF8.GetBytes(password),
            Salt = RandomNumberGenerator.GetBytes(16) // 128-bit salt
        };
        
        using var argon2 = new Argon2(config);
        return argon2.Hash().EncodedString;
    }
    
    public bool VerifyPassword(string hash, string password)
    {
        return Argon2.Verify(hash, password);
    }
}

// Or use ASP.NET Core Identity PasswordHasher (PBKDF2)
public class UserService
{
    private readonly IPasswordHasher<User> _passwordHasher;
    
    public UserService(IPasswordHasher<User> passwordHasher)
    {
        _passwordHasher = passwordHasher;
    }
    
    public async Task<User> CreateUserAsync(CreateUserDto dto)
    {
        var user = new User
        {
            Email = dto.Email,
            UserName = dto.Email
        };
        
        // Hash password using Identity's password hasher
        user.PasswordHash = _passwordHasher.HashPassword(user, dto.Password);
        
        await _userRepository.AddAsync(user);
        return user;
    }
    
    public async Task<bool> ValidatePasswordAsync(string email, string password)
    {
        var user = await _userRepository.GetByEmailAsync(email);
        if (user == null || user.PasswordHash == null)
        {
            return false;
        }
        
        var result = _passwordHasher.VerifyHashedPassword(
            user, 
            user.PasswordHash, 
            password);
        
        return result == PasswordVerificationResult.Success;
    }
}
```

### Password Policy (2025 NIST Guidelines)

- **Minimum length:** 12 characters (not 8)
- **No composition rules** - Allow passphrases
- **Check against breach databases** - HaveIBeenPwned API
- **No periodic rotation** - Only on compromise
- **Allow all printable characters** - Including spaces, emojis

## API Key Authentication

### Best Practices

1. **Prefix keys** - `sk_live_`, `pk_test_` (identify type/environment)
2. **Hash stored keys** - Store SHA-256 hash, not plaintext
3. **Key rotation** - Allow users to rotate keys
4. **Scope limiting** - Separate keys for read/write operations
5. **Rate limiting** - Per API key limits

```csharp
// API Key Service
public class ApiKeyService
{
    private readonly IApiKeyRepository _repository;
    
    public ApiKeyService(IApiKeyRepository repository)
    {
        _repository = repository;
    }
    
    public string GenerateApiKey(string environment, string prefix = "sk")
    {
        var randomBytes = RandomNumberGenerator.GetBytes(24);
        var keyPart = Convert.ToBase64String(randomBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        
        return $"{prefix}_{environment}_{keyPart}";
    }
    
    public async Task<ApiKey> CreateApiKeyAsync(
        Guid userId,
        string environment,
        IEnumerable<string> scopes)
    {
        var apiKey = GenerateApiKey(environment);
        var hashedKey = HashApiKey(apiKey);
        
        var keyRecord = new ApiKey
        {
            UserId = userId,
            HashedKey = hashedKey,
            Scopes = scopes.ToList(),
            Environment = environment,
            CreatedAt = DateTime.UtcNow
        };
        
        await _repository.AddAsync(keyRecord);
        
        // Return plaintext key only once (store securely)
        keyRecord.PlaintextKey = apiKey; // Only for response
        return keyRecord;
    }
    
    private string HashApiKey(string apiKey)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
    
    public async Task<ApiKey?> ValidateApiKeyAsync(string providedKey)
    {
        var hashedKey = HashApiKey(providedKey);
        return await _repository.GetByHashedKeyAsync(hashedKey);
    }
}

// API Key Authentication Handler
public class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ApiKeyService _apiKeyService;
    
    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ApiKeyService apiKeyService)
        : base(options, logger, encoder, clock)
    {
        _apiKeyService = apiKeyService;
    }
    
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-API-Key", out var apiKeyHeaderValues))
        {
            return AuthenticateResult.NoResult();
        }
        
        var providedKey = apiKeyHeaderValues.ToString();
        if (string.IsNullOrWhiteSpace(providedKey))
        {
            return AuthenticateResult.NoResult();
        }
        
        var apiKey = await _apiKeyService.ValidateApiKeyAsync(providedKey);
        if (apiKey == null)
        {
            return AuthenticateResult.Fail("Invalid API key");
        }
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, apiKey.UserId.ToString()),
            new Claim("ApiKeyId", apiKey.Id.ToString())
        };
        
        // Add scope claims
        foreach (var scope in apiKey.Scopes)
        {
            claims = claims.Append(new Claim("scope", scope)).ToArray();
        }
        
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        
        return AuthenticateResult.Success(ticket);
    }
}

// Register API key authentication
builder.Services.AddAuthentication()
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        "ApiKey",
        options => { });

// Usage
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = "ApiKey")]
public class ApiController : ControllerBase
{
    [HttpGet("data")]
    [Authorize(Policy = "RequireReadScope")] // Custom scope policy
    public IActionResult GetData()
    {
        return Ok();
    }
}
```

## Authentication Decision Matrix (.NET)

| Use Case | Recommended Approach (.NET) |
|----------|----------------------------|
| Web application | ASP.NET Core Identity + JWT Bearer |
| Mobile app | OAuth 2.1 + PKCE (OpenIdConnect) |
| SPA (Single Page App) | OAuth 2.1 Authorization Code + PKCE (OpenIdConnect) |
| Server-to-server | Client credentials grant + mTLS (Certificate authentication) |
| Third-party API access | API keys with scopes (Custom authentication handler) |
| High-security | WebAuthn/FIDO2 + MFA (Fido2NetLib) |
| Internal admin | JWT + RBAC + MFA (ASP.NET Core Identity + TOTP) |
| Microservices | Service mesh (mTLS) + JWT (Certificate + JWT Bearer) |
| Azure-hosted | Azure AD / Entra ID (Microsoft.Identity.Web) |
| Optimizely CMS | Built-in user management + custom providers |

## Security Checklist (.NET)

- [ ] OAuth 2.1 with PKCE implemented (OpenIdConnect with UsePkce = true)
- [ ] JWT tokens expire in 15 minutes (TokenValidationParameters.ValidateLifetime)
- [ ] Refresh token rotation enabled
- [ ] RBAC with deny-by-default (Policy-based authorization)
- [ ] MFA required for admin accounts (TOTP or WebAuthn)
- [ ] Passwords hashed with Argon2id or PBKDF2 (ASP.NET Core Identity)
- [ ] Session cookies: HttpOnly, Secure, SameSite=Strict
- [ ] Rate limiting on auth endpoints (10 attempts/15 min) - ASP.NET Core Rate Limiting
- [ ] Account lockout after failed attempts (IdentityOptions.Lockout)
- [ ] Password policy: 12+ chars, breach check (IdentityOptions.Password)
- [ ] Audit logging for authentication events (Serilog + Application Insights)
- [ ] CSRF protection enabled (Antiforgery middleware)
- [ ] CORS properly configured (not `*` in production)

## ASP.NET Core Identity Setup

**Complete Identity Configuration:**
```csharp
// Program.cs - Full Identity setup
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<User, Role>(options =>
{
    // Password settings
    options.Password.RequireDigit = false; // NIST: no composition rules
    options.Password.RequiredLength = 12; // NIST: minimum 12 chars
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    
    // Lockout settings
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

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
```

## Resources

### Microsoft Documentation
- **ASP.NET Core Identity:** https://learn.microsoft.com/aspnet/core/security/authentication/identity
- **JWT Bearer Authentication:** https://learn.microsoft.com/aspnet/core/security/authentication/jwt-authn
- **Authorization in ASP.NET Core:** https://learn.microsoft.com/aspnet/core/security/authorization/
- **OpenIdConnect:** https://learn.microsoft.com/aspnet/core/security/authentication/openid-connect

### Libraries
- **Fido2NetLib:** https://github.com/passwordless-lib/fido2-net-lib
- **Otp.NET:** https://github.com/kspearrin/Otp.NET
- **Isopoh.Cryptography.Argon2:** https://github.com/kmaragon/Isopoh.Cryptography.Argon2
- **Microsoft.Identity.Web:** https://github.com/AzureAD/microsoft-identity-web

### Standards & Guidelines
- **OAuth 2.1:** https://oauth.net/2.1/
- **JWT Best Practices:** https://datatracker.ietf.org/doc/html/rfc8725
- **WebAuthn:** https://webauthn.guide/
- **NIST Password Guidelines:** https://pages.nist.gov/800-63-3/
- **OWASP Auth Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
