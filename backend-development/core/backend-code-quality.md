# Backend Code Quality

SOLID principles, design patterns, clean code practices, and refactoring strategies for C#/.NET following Microsoft's coding conventions and best practices (2025).

## SOLID Principles

### Single Responsibility Principle (SRP)

**Concept:** Class/module should have one reason to change

**Bad:**
```csharp
public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty; // Forcing default value
    public string Name { get; set; } = string.Empty; // Forcing default value
    
    public void SaveToDatabase() { /* ... */ }
    public void SendWelcomeEmail() { /* ... */ }
    public void GenerateReport() { /* ... */ }
    public void ValidateInput() { /* ... */ }
}
```

**Good (Following Microsoft Conventions with Nullable Reference Types):**
```csharp
// Domain entity - only data and domain logic
// With nullable reference types enabled, use nullable for optional fields
public class User
{
    public Guid Id { get; set; }
    public string? Email { get; set; } // Nullable - may not be set initially
    public string? Name { get; set; }  // Nullable - may not be set initially
    
    // Or if required, use non-nullable and validate in constructor/setter
    // public string Email { get; set; } = null!; // Non-nullable, initialized to null! (suppress warning)
}

// Repository - data access only
/// <summary>
/// Repository for user data access operations.
/// </summary>
public interface IUserRepository
{
    /// <summary>
    /// Gets a user by their unique identifier.
    /// </summary>
    /// <param name="id">The user's unique identifier.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>The user if found; otherwise, null.</returns>
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Gets a user by their email address.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>The user if found; otherwise, null.</returns>
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Saves a user to the database.
    /// </summary>
    /// <param name="user">The user to save.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    Task SaveAsync(User user, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Deletes a user from the database.
    /// </summary>
    /// <param name="id">The unique identifier of the user to delete.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}

/// <summary>
/// Entity Framework Core implementation of the user repository.
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly AppDbContext _context;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="UserRepository"/> class.
    /// </summary>
    /// <param name="context">The database context.</param>
    /// <exception cref="ArgumentNullException">Thrown when context is null.</exception>
    public UserRepository(AppDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }
    
    /// <inheritdoc />
    public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Users.FindAsync(new object[] { id }, cancellationToken);
    }
    
    // Other methods...
}

// Service - business logic only
public interface IEmailService
{
    Task SendWelcomeEmailAsync(User user, CancellationToken cancellationToken = default);
}

public class EmailService : IEmailService
{
    public async Task SendWelcomeEmailAsync(User user, CancellationToken cancellationToken = default)
    {
        // Email sending logic
    }
}

// Validator - validation logic only
public class UserValidator
{
    public ValidationResult Validate(User user)
    {
        // Validation logic
        return ValidationResult.Success;
    }
}

// Report generator - reporting logic only
public interface IReportGenerator
{
    Task<Report> GenerateUserReportAsync(User user, CancellationToken cancellationToken = default);
}
```

### Open/Closed Principle (OCP)

**Concept:** Open for extension, closed for modification

**Bad:**
```csharp
public class PaymentProcessor
{
    public async Task<PaymentResult> ProcessAsync(decimal amount, string method)
    {
        if (method == "stripe")
        {
            // Stripe logic
        }
        else if (method == "paypal")
        {
            // PayPal logic
        }
        // Adding new payment method requires modifying this class
    }
}
```

**Good (Strategy Pattern with Dependency Injection):**
```csharp
// Strategy interface
public interface IPaymentStrategy
{
    Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request, CancellationToken cancellationToken = default);
}

// Concrete strategies
public class StripePaymentStrategy : IPaymentStrategy
{
    public async Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request, CancellationToken cancellationToken = default)
    {
        // Stripe-specific logic
        return new PaymentResult { Success = true, TransactionId = Guid.NewGuid().ToString() };
    }
}

public class PayPalPaymentStrategy : IPaymentStrategy
{
    public async Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request, CancellationToken cancellationToken = default)
    {
        // PayPal-specific logic
        return new PaymentResult { Success = true, TransactionId = Guid.NewGuid().ToString() };
    }
}

// Payment processor - closed for modification, open for extension
public class PaymentProcessor
{
    private readonly IPaymentStrategy _strategy;
    
    public PaymentProcessor(IPaymentStrategy strategy)
    {
        _strategy = strategy ?? throw new ArgumentNullException(nameof(strategy));
    }
    
    public async Task<PaymentResult> ProcessAsync(decimal amount, PaymentRequest request, CancellationToken cancellationToken = default)
    {
        return await _strategy.ProcessAsync(amount, request, cancellationToken);
    }
}

// Usage with dependency injection
// In Program.cs:
builder.Services.AddScoped<IPaymentStrategy, StripePaymentStrategy>();
builder.Services.AddScoped<PaymentProcessor>();

// Or use factory pattern for runtime selection
public interface IPaymentStrategyFactory
{
    IPaymentStrategy Create(string paymentMethod);
}
```

### Liskov Substitution Principle (LSP)

**Concept:** Subtypes must be substitutable for base types

**Bad:**
```csharp
public class Bird
{
    public virtual void Fly()
    {
        // Flying logic
    }
}

public class Penguin : Bird
{
    public override void Fly()
    {
        throw new InvalidOperationException("Penguins cannot fly!");
    }
}

// Violates LSP - Penguin breaks Bird contract
```

**Good:**
```csharp
// Base interface - defines contract
public interface IBird
{
    void Move();
}

// Specific implementations
public class FlyingBird : IBird
{
    public void Move()
    {
        Fly();
    }
    
    private void Fly()
    {
        // Flying logic
    }
}

public class Penguin : IBird
{
    public void Move()
    {
        Swim();
    }
    
    private void Swim()
    {
        // Swimming logic
    }
}

// Usage - any IBird can be substituted
public void ProcessBird(IBird bird)
{
    bird.Move(); // Works for both FlyingBird and Penguin
}
```

### Interface Segregation Principle (ISP)

**Concept:** Clients shouldn't depend on interfaces they don't use

**Bad:**
```csharp
public interface IWorker
{
    void Work();
    void Eat();
    void Sleep();
}

public class Robot : IWorker
{
    public void Work() { /* ... */ }
    
    public void Eat() 
    { 
        throw new NotSupportedException("Robots don't eat"); 
    }
    
    public void Sleep() 
    { 
        throw new NotSupportedException("Robots don't sleep"); 
    }
}
```

**Good (Segregated Interfaces):**
```csharp
// Segregated interfaces - clients only depend on what they need
public interface IWorkable
{
    void Work();
}

public interface IEatable
{
    void Eat();
}

public interface ISleepable
{
    void Sleep();
}

// Human implements all interfaces
public class Human : IWorkable, IEatable, ISleepable
{
    public void Work() { /* ... */ }
    public void Eat() { /* ... */ }
    public void Sleep() { /* ... */ }
}

// Robot only implements what it needs
public class Robot : IWorkable
{
    public void Work() { /* ... */ }
}

// Usage - clients depend only on what they need
public void ProcessWorker(IWorkable worker)
{
    worker.Work(); // Only needs IWorkable, not IEatable or ISleepable
}
```

### Dependency Inversion Principle (DIP)

**Concept:** Depend on abstractions, not concretions

**Bad:**
```csharp
public class SqlServerDatabase
{
    public async Task<object> QueryAsync(string sql)
    {
        // SQL Server specific implementation
    }
}

public class UserService
{
    private readonly SqlServerDatabase _db = new SqlServerDatabase(); // Tight coupling
    
    public async Task<User?> GetUserAsync(Guid id)
    {
        return await _db.QueryAsync($"SELECT * FROM Users WHERE Id = '{id}'"); // SQL injection risk!
    }
}
```

**Good (Dependency Injection with .NET DI Container):**
```csharp
// Abstraction - interface defines contract
public interface IDatabase
{
    Task<T?> QueryFirstOrDefaultAsync<T>(string sql, object? parameters = null, CancellationToken cancellationToken = default);
}

// Concrete implementations
public class SqlServerDatabase : IDatabase
{
    private readonly IDbConnection _connection;
    
    public SqlServerDatabase(IDbConnection connection)
    {
        _connection = connection;
    }
    
    public async Task<T?> QueryFirstOrDefaultAsync<T>(string sql, object? parameters = null, CancellationToken cancellationToken = default)
    {
        // SQL Server implementation using Dapper
        return await _connection.QueryFirstOrDefaultAsync<T>(sql, parameters);
    }
}

public class PostgreSqlDatabase : IDatabase
{
    // PostgreSQL implementation
}

// Service depends on abstraction
public class UserService
{
    private readonly IDatabase _database;
    
    public UserService(IDatabase database)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
    }
    
    public async Task<User?> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT * FROM Users WHERE Id = @Id";
        return await _database.QueryFirstOrDefaultAsync<User>(sql, new { Id = id }, cancellationToken);
    }
}

// Register in Program.cs - dependency injection
builder.Services.AddScoped<IDatabase, SqlServerDatabase>();
builder.Services.AddScoped<UserService>();
```

## Design Patterns

### Repository Pattern

**Concept:** Abstraction layer between business logic and data access

```csharp
// Domain entity - using nullable reference types
public class User
{
    public Guid Id { get; set; }
    public string? Email { get; set; } // Nullable - optional field
    public string? Name { get; set; }  // Nullable - optional field
    
    // For required fields, use non-nullable and validate:
    // public string Email { get; set; } = null!; // Non-nullable, must be set
}

// Repository interface - follows Microsoft naming conventions
public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<IEnumerable<User>> GetAllAsync(CancellationToken cancellationToken = default);
    Task AddAsync(User user, CancellationToken cancellationToken = default);
    Task UpdateAsync(User user, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}

// EF Core implementation
public class UserRepository : IUserRepository
{
    private readonly AppDbContext _context;
    
    public UserRepository(AppDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }
    
    public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Users.FindAsync(new object[] { id }, cancellationToken);
    }
    
    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
    }
    
    public async Task<IEnumerable<User>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Users.ToListAsync(cancellationToken);
    }
    
    public async Task AddAsync(User user, CancellationToken cancellationToken = default)
    {
        await _context.Users.AddAsync(user, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);
    }
    
    public async Task UpdateAsync(User user, CancellationToken cancellationToken = default)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync(cancellationToken);
    }
    
    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await GetByIdAsync(id, cancellationToken);
        if (user != null)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}

// Service layer uses repository
public class UserService
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<UserService> _logger;
    
    public UserService(IUserRepository userRepository, ILogger<UserService> logger)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }
    
    public async Task<User?> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _userRepository.GetByIdAsync(id, cancellationToken);
    }
}

// Register in Program.cs
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<UserService>();
```

### Factory Pattern

**Concept:** Create objects without specifying exact class

```csharp
// Notification interface
public interface INotification
{
    Task SendAsync(string message, CancellationToken cancellationToken = default);
}

// Concrete implementations
public class EmailNotification : INotification
{
    public async Task SendAsync(string message, CancellationToken cancellationToken = default)
    {
        // Email sending logic
        await Task.CompletedTask;
    }
}

public class SmsNotification : INotification
{
    public async Task SendAsync(string message, CancellationToken cancellationToken = default)
    {
        // SMS sending logic
        await Task.CompletedTask;
    }
}

public class PushNotification : INotification
{
    public async Task SendAsync(string message, CancellationToken cancellationToken = default)
    {
        // Push notification logic
        await Task.CompletedTask;
    }
}

// Factory interface
public interface INotificationFactory
{
    INotification Create(NotificationType type);
}

// Factory implementation
public class NotificationFactory : INotificationFactory
{
    private readonly IServiceProvider _serviceProvider;
    
    public NotificationFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }
    
    public INotification Create(NotificationType type)
    {
        return type switch
        {
            NotificationType.Email => _serviceProvider.GetRequiredService<EmailNotification>(),
            NotificationType.Sms => _serviceProvider.GetRequiredService<SmsNotification>(),
            NotificationType.Push => _serviceProvider.GetRequiredService<PushNotification>(),
            _ => throw new ArgumentException($"Unknown notification type: {type}", nameof(type))
        };
    }
}

public enum NotificationType
{
    Email,
    Sms,
    Push
}

// Usage with dependency injection
builder.Services.AddScoped<EmailNotification>();
builder.Services.AddScoped<SmsNotification>();
builder.Services.AddScoped<PushNotification>();
builder.Services.AddSingleton<INotificationFactory, NotificationFactory>();

// In service
public class OrderService
{
    private readonly INotificationFactory _notificationFactory;
    
    public OrderService(INotificationFactory notificationFactory)
    {
        _notificationFactory = notificationFactory;
    }
    
    public async Task NotifyUserAsync(string message, NotificationType type)
    {
        var notification = _notificationFactory.Create(type);
        await notification.SendAsync(message);
    }
}
```

### Decorator Pattern

**Concept:** Add behavior to objects dynamically

```csharp
// Base interface
public interface ICoffee
{
    decimal Cost { get; }
    string Description { get; }
}

// Concrete component
public class SimpleCoffee : ICoffee
{
    public decimal Cost => 10.00m;
    public string Description => "Simple coffee";
}

// Base decorator
public abstract class CoffeeDecorator : ICoffee
{
    protected readonly ICoffee _coffee;
    
    protected CoffeeDecorator(ICoffee coffee)
    {
        _coffee = coffee ?? throw new ArgumentNullException(nameof(coffee));
    }
    
    public virtual decimal Cost => _coffee.Cost;
    public virtual string Description => _coffee.Description;
}

// Concrete decorators
public class MilkDecorator : CoffeeDecorator
{
    public MilkDecorator(ICoffee coffee) : base(coffee) { }
    
    public override decimal Cost => base.Cost + 2.00m;
    public override string Description => $"{base.Description}, milk";
}

public class SugarDecorator : CoffeeDecorator
{
    public SugarDecorator(ICoffee coffee) : base(coffee) { }
    
    public override decimal Cost => base.Cost + 1.00m;
    public override string Description => $"{base.Description}, sugar";
}

// Usage
ICoffee coffee = new SimpleCoffee();
coffee = new MilkDecorator(coffee);
coffee = new SugarDecorator(coffee);

Console.WriteLine(coffee.Description); // "Simple coffee, milk, sugar"
Console.WriteLine(coffee.Cost); // 13.00
```

**Real-world example: Caching Decorator**
```csharp
public interface IUserService
{
    Task<User?> GetUserAsync(Guid id, CancellationToken cancellationToken = default);
}

public class CachedUserService : IUserService
{
    private readonly IUserService _userService;
    private readonly IMemoryCache _cache;
    
    public CachedUserService(IUserService userService, IMemoryCache cache)
    {
        _userService = userService;
        _cache = cache;
    }
    
    public async Task<User?> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"user:{id}";
        
        if (_cache.TryGetValue(cacheKey, out User? cachedUser))
        {
            return cachedUser;
        }
        
        var user = await _userService.GetUserAsync(id, cancellationToken);
        
        if (user != null)
        {
            _cache.Set(cacheKey, user, TimeSpan.FromMinutes(5));
        }
        
        return user;
    }
}
```

### Observer Pattern (Pub/Sub) with MediatR

**Concept:** Notify multiple objects about state changes

**Using MediatR (Recommended for .NET):**
```csharp
// Domain event
public record UserCreatedEvent(Guid UserId, string Email, DateTime CreatedAt) : INotification;

// Handlers (Observers)
public class EmailNotificationHandler : INotificationHandler<UserCreatedEvent>
{
    private readonly IEmailService _emailService;
    
    public EmailNotificationHandler(IEmailService emailService)
    {
        _emailService = emailService;
    }
    
    public async Task Handle(UserCreatedEvent notification, CancellationToken cancellationToken)
    {
        await _emailService.SendWelcomeEmailAsync(notification.Email, cancellationToken);
    }
}

public class LoggingHandler : INotificationHandler<UserCreatedEvent>
{
    private readonly ILogger<LoggingHandler> _logger;
    
    public LoggingHandler(ILogger<LoggingHandler> logger)
    {
        _logger = logger;
    }
    
    public Task Handle(UserCreatedEvent notification, CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "User created: {UserId}, Email: {Email}, CreatedAt: {CreatedAt}",
            notification.UserId,
            notification.Email,
            notification.CreatedAt);
        
        return Task.CompletedTask;
    }
}

// Publisher (using MediatR)
public class UserService
{
    private readonly IUserRepository _repository;
    private readonly IMediator _mediator;
    
    public UserService(IUserRepository repository, IMediator mediator)
    {
        _repository = repository;
        _mediator = mediator;
    }
    
    public async Task<User> CreateUserAsync(CreateUserDto dto, CancellationToken cancellationToken = default)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = dto.Email,
            Name = dto.Name
        };
        
        await _repository.AddAsync(user, cancellationToken);
        
        // Publish event - all handlers are notified automatically
        await _mediator.Publish(
            new UserCreatedEvent(user.Id, user.Email, DateTime.UtcNow),
            cancellationToken);
        
        return user;
    }
}

// Register in Program.cs
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));
```

**Traditional Observer Pattern:**
```csharp
public interface IObserver<in T>
{
    void OnNext(T value);
}

public class EventEmitter<T>
{
    private readonly List<IObserver<T>> _observers = new();
    
    public IDisposable Subscribe(IObserver<T> observer)
    {
        _observers.Add(observer);
        return new Unsubscriber(_observers, observer);
    }
    
    public void Emit(T value)
    {
        foreach (var observer in _observers)
        {
            observer.OnNext(value);
        }
    }
    
    private class Unsubscriber : IDisposable
    {
        private readonly List<IObserver<T>> _observers;
        private readonly IObserver<T> _observer;
        
        public Unsubscriber(List<IObserver<T>> observers, IObserver<T> observer)
        {
            _observers = observers;
            _observer = observer;
        }
        
        public void Dispose()
        {
            _observers.Remove(_observer);
        }
    }
}
```

## Clean Code Practices

### Meaningful Names (Microsoft Conventions)

**Microsoft Naming Guidelines:**
- **PascalCase** for public members (classes, methods, properties, interfaces)
- **camelCase** for parameters and local variables
- **PascalCase** for constants (public and private)
- **PascalCase** for enums and enum values
- **_camelCase** for private fields (or use properties)

**Bad:**
```csharp
public static double d(double a, double b)
{
    return a * b * 0.0254;
}
```

**Good (Following Microsoft Conventions):**
```csharp
public static double CalculateAreaInMeters(double widthInInches, double heightInInches)
{
    const double InchesToMeters = 0.0254;
    return widthInInches * heightInInches * InchesToMeters;
}

// Or as a constant
public static class ConversionConstants
{
    public const double InchesToMeters = 0.0254;
}
```

### Nullable Reference Types Best Practices

**Microsoft Guidelines:**
- Enable nullable reference types: `<Nullable>enable</Nullable>` in .csproj
- Use nullable (`string?`) for optional fields that may not be set
- Use non-nullable (`string`) for required fields that must always have a value
- Avoid forcing default values like `string.Empty` - use nullable instead
- Use `null!` to suppress warnings only when you guarantee initialization (e.g., EF Core entities)

**Bad:**
```csharp
public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty; // Forcing empty string
    public string Name { get; set; } = string.Empty; // Forcing empty string
}

// Later in code - unclear if empty string means "not set" or "set to empty"
if (user.Email == string.Empty) { /* ... */ }
```

**Good:**
```csharp
// Option 1: Use nullable for optional fields
public class User
{
    public Guid Id { get; set; }
    public string? Email { get; set; } // Nullable - may not be set
    public string? Name { get; set; }  // Nullable - may not be set
}

// Usage - clear intent
if (user.Email is null) { /* Email not set */ }
if (string.IsNullOrEmpty(user.Email)) { /* Email not set or empty */ }

// Option 2: Use non-nullable for required fields (EF Core entities)
public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; } = null!; // Non-nullable, EF Core will set it
    public string Name { get; set; } = null!; // Non-nullable, EF Core will set it
}

// Option 3: Use constructor for required fields
public class User
{
    public Guid Id { get; set; }
    public string Email { get; set; }
    public string Name { get; set; }
    
    public User(string email, string name)
    {
        Email = email ?? throw new ArgumentNullException(nameof(email));
        Name = name ?? throw new ArgumentNullException(nameof(name));
    }
}
```

**When to Use Nullable vs Non-Nullable:**
- **Use `string?` (nullable)**: Optional fields, fields that may not be initialized immediately, DTOs with optional properties
- **Use `string` (non-nullable)**: Required fields, fields guaranteed to be set (e.g., by EF Core), fields validated in constructor
- **Use `null!`**: Only when you guarantee the value will be set before use (e.g., EF Core entities, properties set by framework)

### Small Functions (Microsoft Best Practices)

**Microsoft Guidelines:**
- Methods should be focused and do one thing
- Prefer composition over large methods
- Use async/await for I/O operations
- Follow async naming convention (MethodNameAsync)

**Bad:**
```csharp
public async Task ProcessOrderAsync(Guid orderId)
{
    // 200 lines of code doing everything
    // - validate order
    // - check inventory
    // - process payment
    // - update database
    // - send notifications
    // - generate invoice
}
```

**Good:**
```csharp
public class OrderService
{
    private readonly IOrderRepository _orderRepository;
    private readonly IInventoryService _inventoryService;
    private readonly IPaymentService _paymentService;
    private readonly IEmailService _emailService;
    private readonly IInvoiceService _invoiceService;
    
    public async Task ProcessOrderAsync(Guid orderId, CancellationToken cancellationToken = default)
    {
        var order = await ValidateOrderAsync(orderId, cancellationToken);
        await CheckInventoryAsync(order, cancellationToken);
        var payment = await ProcessPaymentAsync(order, cancellationToken);
        await UpdateOrderStatusAsync(orderId, OrderStatus.Paid, cancellationToken);
        await SendConfirmationEmailAsync(order, cancellationToken);
        await GenerateInvoiceAsync(order, payment, cancellationToken);
    }
    
    private async Task<Order> ValidateOrderAsync(Guid orderId, CancellationToken cancellationToken)
    {
        // Validation logic
    }
    
    // Other private methods...
}
```

### Avoid Magic Numbers (Use Constants)

**Microsoft Guidelines:**
- Use `const` for compile-time constants
- Use `static readonly` for runtime constants
- Use `readonly` for instance-level constants
- Group related constants in a class

**Bad:**
```csharp
if (user.Age < 18)
{
    throw new ArgumentException("User is too young");
}

await Task.Delay(86400000);
```

**Good:**
```csharp
// Option 1: Constants in a static class
public static class BusinessRules
{
    public const int MinimumAge = 18;
    public static readonly TimeSpan OneDay = TimeSpan.FromDays(1);
}

// Option 2: Constants in the class
public class UserService
{
    private const int MinimumAge = 18;
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromDays(1);
    
    public void ValidateUser(User user)
    {
        if (user.Age < MinimumAge)
        {
            throw new ArgumentException($"User must be at least {MinimumAge} years old", nameof(user));
        }
    }
    
    public async Task RefreshCacheAsync()
    {
        await Task.Delay(CacheExpiration);
    }
}

// Option 3: Configuration-based (preferred for runtime values)
public class AppSettings
{
    public int MinimumAge { get; set; } = 18;
    public TimeSpan CacheExpiration { get; set; } = TimeSpan.FromDays(1);
}
```

### Error Handling (Microsoft Best Practices)

**Microsoft Guidelines:**
- Use specific exception types
- Include context in exception messages
- Use `throw;` to preserve stack trace when rethrowing
- Use `throw ex;` only when intentionally resetting stack trace
- Log exceptions before rethrowing
- Use `CancellationToken` for cancellation

**Bad:**
```csharp
public async Task<User?> GetUserAsync(Guid id)
{
    try
    {
        var user = await _db.FindUserAsync(id);
        return user;
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex); // Don't use Console.WriteLine
        return null; // Swallowing exceptions
    }
}
```

**Good:**
```csharp
public async Task<User> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
{
    try
    {
        var user = await _repository.GetByIdAsync(id, cancellationToken);
        
        if (user == null)
        {
            throw new UserNotFoundException($"User with ID {id} was not found.");
        }
        
        return user;
    }
    catch (UserNotFoundException)
    {
        // Re-throw domain exceptions as-is
        throw;
    }
    catch (Exception ex)
    {
        _logger.LogError(
            ex,
            "Failed to fetch user. UserId: {UserId}",
            id);
        
        throw new DataAccessException(
            $"An error occurred while fetching user with ID {id}.",
            ex);
    }
}

// Custom exception types
public class UserNotFoundException : Exception
{
    public UserNotFoundException(string message) : base(message) { }
    
    public UserNotFoundException(string message, Exception innerException) 
        : base(message, innerException) { }
}

public class DataAccessException : Exception
{
    public DataAccessException(string message) : base(message) { }
    
    public DataAccessException(string message, Exception innerException) 
        : base(message, innerException) { }
}
```

### Don't Repeat Yourself (DRY)

**Microsoft Guidelines:**
- Extract common logic into methods
- Use base classes for shared functionality
- Use extension methods for reusable operations
- Use FluentValidation or Data Annotations for validation

**Bad:**
```csharp
[HttpPost("users")]
public async Task<IActionResult> CreateUser(CreateUserDto dto)
{
    if (string.IsNullOrEmpty(dto.Email) || !dto.Email.Contains('@'))
    {
        return BadRequest(new { error = "Invalid email" });
    }
    // ...
}

[HttpPut("users/{id}")]
public async Task<IActionResult> UpdateUser(Guid id, UpdateUserDto dto)
{
    if (string.IsNullOrEmpty(dto.Email) || !dto.Email.Contains('@'))
    {
        return BadRequest(new { error = "Invalid email" });
    }
    // ...
}
```

**Good (Using FluentValidation):**
```csharp
// Validator class
public class CreateUserDtoValidator : AbstractValidator<CreateUserDto>
{
    public CreateUserDtoValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .WithMessage("Invalid email address");
    }
}

// Controller
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;
    
    public UsersController(IUserService userService)
    {
        _userService = userService;
    }
    
    [HttpPost]
    public async Task<IActionResult> CreateUser(
        [FromBody] CreateUserDto dto,
        CancellationToken cancellationToken)
    {
        // Validation handled by FluentValidation middleware
        var user = await _userService.CreateUserAsync(dto, cancellationToken);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }
    
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateUser(
        Guid id,
        [FromBody] UpdateUserDto dto,
        CancellationToken cancellationToken)
    {
        // Validation handled by FluentValidation middleware
        await _userService.UpdateUserAsync(id, dto, cancellationToken);
        return NoContent();
    }
}

// Register FluentValidation in Program.cs
builder.Services.AddControllers()
    .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<CreateUserDtoValidator>());
```

**Good (Using Extension Methods):**
```csharp
public static class StringExtensions
{
    public static bool IsValidEmail(this string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }
        
        try
        {
            var mailAddress = new MailAddress(email);
            return mailAddress.Address == email;
        }
        catch
        {
            return false;
        }
    }
}

// Usage
if (!dto.Email.IsValidEmail())
{
    return BadRequest(new { error = "Invalid email" });
}
```

## Code Refactoring Techniques

### Extract Method

**Before:**
```csharp
public void RenderOrder(Order order)
{
    Console.WriteLine("Order Details:");
    Console.WriteLine($"ID: {order.Id}");
    Console.WriteLine($"Total: ${order.Total:F2}");

    Console.WriteLine("Items:");
    foreach (var item in order.Items)
    {
        Console.WriteLine($"- {item.Name}: ${item.Price:F2}");
    }
}
```

**After (Following Microsoft Conventions):**
```csharp
public void RenderOrder(Order order)
{
    if (order == null)
    {
        throw new ArgumentNullException(nameof(order));
    }
    
    PrintOrderHeader(order);
    PrintOrderItems(order.Items);
}

private void PrintOrderHeader(Order order)
{
    Console.WriteLine("Order Details:");
    Console.WriteLine($"ID: {order.Id}");
    Console.WriteLine($"Total: {order.Total:C}");
}

private void PrintOrderItems(IEnumerable<OrderItem> items)
{
    Console.WriteLine("Items:");
    foreach (var item in items)
    {
        Console.WriteLine($"- {item.Name}: {item.Price:C}");
    }
}
```

### Replace Conditional with Polymorphism

**Before:**
```csharp
public decimal GetShippingCost(Order order)
{
    return order.ShippingMethod switch
    {
        "standard" => 5.00m,
        "express" => 15.00m,
        "overnight" => 30.00m,
        _ => throw new ArgumentException($"Unknown shipping method: {order.ShippingMethod}")
    };
}
```

**After (Using Strategy Pattern):**
```csharp
// Strategy interface
public interface IShippingMethod
{
    decimal CalculateCost(Order order);
    string Name { get; }
}

// Concrete strategies
public class StandardShipping : IShippingMethod
{
    public string Name => "Standard";
    
    public decimal CalculateCost(Order order)
    {
        return 5.00m;
    }
}

public class ExpressShipping : IShippingMethod
{
    public string Name => "Express";
    
    public decimal CalculateCost(Order order)
    {
        return 15.00m;
    }
}

public class OvernightShipping : IShippingMethod
{
    public string Name => "Overnight";
    
    public decimal CalculateCost(Order order)
    {
        return 30.00m;
    }
}

// Factory for creating strategies
public interface IShippingMethodFactory
{
    IShippingMethod Create(string shippingMethod);
}

public class ShippingMethodFactory : IShippingMethodFactory
{
    private readonly Dictionary<string, IShippingMethod> _methods;
    
    public ShippingMethodFactory()
    {
        _methods = new Dictionary<string, IShippingMethod>
        {
            { "standard", new StandardShipping() },
            { "express", new ExpressShipping() },
            { "overnight", new OvernightShipping() }
        };
    }
    
    public IShippingMethod Create(string shippingMethod)
    {
        if (_methods.TryGetValue(shippingMethod.ToLowerInvariant(), out var method))
        {
            return method;
        }
        
        throw new ArgumentException($"Unknown shipping method: {shippingMethod}", nameof(shippingMethod));
    }
}

// Usage
public class OrderService
{
    private readonly IShippingMethodFactory _shippingFactory;
    
    public OrderService(IShippingMethodFactory shippingFactory)
    {
        _shippingFactory = shippingFactory;
    }
    
    public decimal GetShippingCost(Order order)
    {
        var shippingMethod = _shippingFactory.Create(order.ShippingMethod);
        return shippingMethod.CalculateCost(order);
    }
}
```

## Anti-Patterns to Avoid

### ❌ DON'T: Use mutable DTOs

```csharp
// BAD: Mutable DTO
public class CustomerDto
{
    public string Id { get; set; }
    public string Name { get; set; }
}

// GOOD: Immutable record
public record CustomerDto(string Id, string Name);
```

### ❌ DON'T: Use classes for value objects

```csharp
// BAD: Value object as class
public class OrderId
{
    public string Value { get; }
    public OrderId(string value) => Value = value;
}

// GOOD: Value object as readonly record struct
public readonly record struct OrderId(string Value);
```

### ❌ DON'T: Create deep inheritance hierarchies

```csharp
// BAD: Deep inheritance
public abstract class Entity { }
public abstract class AggregateRoot : Entity { }
public abstract class Order : AggregateRoot { }
public class CustomerOrder : Order { }

// GOOD: Flat structure with composition
public interface IEntity
{
    Guid Id { get; }
}

public record Order(OrderId Id, CustomerId CustomerId, Money Total) : IEntity
{
    Guid IEntity.Id => Id.Value;
}
```

### ❌ DON'T: Return List<T> when you mean IReadOnlyList<T>

```csharp
// BAD: Exposes internal list for modification
public List<Order> GetOrders() => _orders;

// GOOD: Returns read-only view
public IReadOnlyList<Order> GetOrders() => _orders;
```

### ❌ DON'T: Use byte[] when ReadOnlySpan<byte> works

```csharp
// BAD: Allocates array on every call
public byte[] GetHeader()
{
    var header = new byte[64];
    // Fill header
    return header;
}

// GOOD: Zero allocation with Span
public void GetHeader(Span<byte> destination)
{
    if (destination.Length < 64)
        throw new ArgumentException("Buffer too small");

    // Fill header directly into caller's buffer
}
```

### ❌ DON'T: Forget CancellationToken in async methods

```csharp
// BAD: No cancellation support
public async Task<Order> GetOrderAsync(OrderId id)
{
    return await _repository.GetAsync(id);
}

// GOOD: Cancellation support
public async Task<Order> GetOrderAsync(
    OrderId id,
    CancellationToken cancellationToken = default)
{
    return await _repository.GetAsync(id, cancellationToken);
}
```

### ❌ DON'T: Block on async code

```csharp
// BAD: Deadlock risk!
public Order GetOrder(OrderId id)
{
    return GetOrderAsync(id).Result;
}

// BAD: Also deadlock risk!
public Order GetOrder(OrderId id)
{
    return GetOrderAsync(id).GetAwaiter().GetResult();
}

// GOOD: Async all the way
public async Task<Order> GetOrderAsync(
    OrderId id,
    CancellationToken cancellationToken)
{
    return await _repository.GetAsync(id, cancellationToken);
}
```

### ❌ DON'T: Use exceptions for expected business errors

```csharp
// BAD: Exception for expected validation failure
public Order CreateOrder(CreateOrderDto dto)
{
    if (dto.Items.Count == 0)
        throw new ValidationException("Order must have items"); // Exception overhead
    
    // ...
}

// GOOD: Result pattern for expected errors
public Result<Order, ValidationError> CreateOrder(CreateOrderDto dto)
{
    if (dto.Items.Count == 0)
        return Result<Order, ValidationError>.Failure(
            new ValidationError("Items", "Order must have items"));
    
    // ...
}
```

### ❌ DON'T: Use implicit conversions in value objects

```csharp
// BAD: Implicit conversions defeat type safety
public readonly record struct UserId(Guid Value)
{
    public static implicit operator UserId(Guid value) => new(value);  // NO!
    public static implicit operator Guid(UserId value) => value.Value; // NO!
}

// GOOD: Explicit conversions only
public readonly record struct UserId(Guid Value)
{
    public static UserId New() => new(Guid.NewGuid());
    // No implicit operators - forces explicit conversion
}
```

## Code Quality Checklist (Microsoft Standards)

### SOLID & Design
- [ ] SOLID principles applied consistently
- [ ] Methods are small and focused (< 20 lines ideal)
- [ ] Meaningful names following Microsoft conventions (PascalCase/camelCase)
- [ ] No magic numbers (use constants or configuration)
- [ ] Proper error handling (specific exceptions, no silent failures)
- [ ] DRY principle (no code duplication)
- [ ] Comments explain "why", not "what" (XML documentation for public APIs)
- [ ] Design patterns used appropriately
- [ ] Dependency injection for testability and loose coupling

### .NET Specific
- [ ] Async/await used for all I/O operations (MethodNameAsync convention)
- [ ] CancellationToken used in async methods
- [ ] Nullable reference types enabled (`<Nullable>enable</Nullable>`)
- [ ] Nullable types (`string?`) used for optional fields instead of forcing defaults
- [ ] Non-nullable types (`string`) used for required fields
- [ ] `null!` used only when guaranteed initialization (e.g., EF Core entities)
- [ ] IDisposable implemented where needed
- [ ] Using statements for resource disposal
- [ ] LINQ used appropriately (avoid N+1 queries)
- [ ] Expression-bodied members used where appropriate
- [ ] Pattern matching used where beneficial (switch expressions, property patterns)
- [ ] XML documentation comments for public APIs (`/// <summary>`)
- [ ] File-scoped namespaces used (C# 10+)
- [ ] Primary constructors used where appropriate (C# 12+)
- [ ] Record types used for immutable DTOs, messages, and events
- [ ] `readonly record struct` used for value objects (not classes)
- [ ] Init-only properties for immutable data structures
- [ ] `IReadOnlyList<T>` returned instead of `List<T>` from public APIs
- [ ] `Result<T, TError>` pattern used for expected business errors
- [ ] Exceptions reserved for exceptional circumstances only
- [ ] `Span<T>`/`Memory<T>` used for performance-critical code paths
- [ ] `UnsafeAccessorAttribute` used instead of reflection when accessing private members (.NET 8+)
- [ ] No implicit conversions in value objects (explicit conversions only)

### Code Style
- [ ] Code follows Microsoft C# coding conventions
- [ ] Line length limited (recommended: 120 characters, maximum: 160 characters)
- [ ] Long lines broken appropriately (method parameters, LINQ chains, string concatenation)
- [ ] EditorConfig configured for consistent formatting
- [ ] Code analysis rules enabled (StyleCop, FxCop, or .NET analyzers)
- [ ] No compiler warnings
- [ ] Code is readable (readable > clever)

## Microsoft Coding Conventions Summary

### Naming Conventions
- **PascalCase**: Classes, methods, properties, interfaces, enums, constants
- **camelCase**: Parameters, local variables, private fields (or use properties)
- **_camelCase**: Private instance fields (alternative to properties)
- **PascalCase**: Enum values
- **I + PascalCase**: Interfaces (e.g., `IUserRepository`)

### Async/Await
- Suffix async methods with `Async` (e.g., `GetUserAsync`)
- Always accept `CancellationToken` in async methods
- Use `ConfigureAwait(false)` in library code
- Prefer `Task<T>` over `Task` for methods that return values

### Exception Handling
- Use specific exception types
- Include context in exception messages
- Use `throw;` to preserve stack trace
- Log exceptions before rethrowing
- Don't catch exceptions you can't handle

### Resource Management
- Implement `IDisposable` for types that own unmanaged resources
- Use `using` statements for `IDisposable` objects
- Prefer `using` declarations (C# 8.0+) when possible

### Line Length Limits

**Microsoft Guidelines:**
- **Recommended:** 120 characters per line
- **Maximum:** 160 characters per line
- Break long lines at logical points (commas, operators, method calls)
- Use indentation to show continuation

**Bad (Line too long):**
```csharp
public async Task<UserDto> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
{
    return await _userRepository.GetByIdAsync(userId, cancellationToken) ?? throw new UserNotFoundException($"User with ID {userId} was not found in the database");
}
```

**Good (Properly broken):**
```csharp
public async Task<UserDto> GetUserByIdAsync(
    Guid userId, 
    CancellationToken cancellationToken = default)
{
    var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
    
    return user ?? throw new UserNotFoundException(
        $"User with ID {userId} was not found in the database");
}
```

**Breaking Long Method Calls:**
```csharp
// Bad - line too long
var result = await _service.ProcessOrderAsync(orderId, userId, paymentMethod, shippingAddress, cancellationToken);

// Good - parameters on separate lines
var result = await _service.ProcessOrderAsync(
    orderId,
    userId,
    paymentMethod,
    shippingAddress,
    cancellationToken);
```

**Breaking Long LINQ Chains:**
```csharp
// Bad - line too long
var activeUsers = await _context.Users.Where(u => u.IsActive && u.EmailConfirmed && u.CreatedAt > DateTime.UtcNow.AddDays(-30)).OrderBy(u => u.CreatedAt).Select(u => new UserDto { Id = u.Id, Email = u.Email, Name = u.Name }).ToListAsync(cancellationToken);

// Good - broken into readable lines
var activeUsers = await _context.Users
    .Where(u => u.IsActive && u.EmailConfirmed && 
                u.CreatedAt > DateTime.UtcNow.AddDays(-30))
    .OrderBy(u => u.CreatedAt)
    .Select(u => new UserDto
    {
        Id = u.Id,
        Email = u.Email,
        Name = u.Name
    })
    .ToListAsync(cancellationToken);
```

**Breaking Long String Concatenation:**
```csharp
// Bad - line too long
var message = $"Order {orderId} for user {userId} with total {total:C} was processed successfully at {DateTime.UtcNow:O}";

// Good - use string interpolation with line breaks
var message = $"Order {orderId} for user {userId} " +
              $"with total {total:C} was processed successfully " +
              $"at {DateTime.UtcNow:O}";

// Or use verbatim strings for multi-line
var message = $@"Order {orderId} for user {userId}
with total {total:C} was processed successfully
at {DateTime.UtcNow:O}";
```

**EditorConfig Configuration:**
```ini
# .editorconfig
root = true

[*.cs]
max_line_length = 120
indent_size = 4
indent_style = space
# File-scoped namespaces (C# 10+)
csharp_style_namespace_declarations = file_scoped:warning
# Prefer 'var' when type is obvious
csharp_style_var_for_built_in_types = false:warning
csharp_style_var_when_type_is_apparent = true:warning
csharp_style_var_elsewhere = false:warning
# Expression-bodied members
csharp_style_expression_bodied_methods = when_on_single_line:warning
csharp_style_expression_bodied_properties = true:warning
# Pattern matching
csharp_style_pattern_matching_over_is_with_cast_check = true:warning
csharp_style_prefer_switch_expression = true:warning
```

## Modern C# Patterns

### Result<T, TError> Pattern for Expected Errors

**Concept:** Use `Result<T, TError>` for expected business errors instead of exceptions. Exceptions should be reserved for exceptional circumstances.

**Result Type Implementation:**
```csharp
public readonly struct Result<T, TError>
{
    private readonly T? _value;
    private readonly TError? _error;
    private readonly bool _isSuccess;

    private Result(T value)
    {
        _value = value;
        _error = default;
        _isSuccess = true;
    }

    private Result(TError error)
    {
        _value = default;
        _error = error;
        _isSuccess = false;
    }

    public bool IsSuccess => _isSuccess;
    public bool IsFailure => !_isSuccess;

    public T Value => _isSuccess ? _value! : throw new InvalidOperationException("Cannot access Value on failed Result");
    public TError Error => _isSuccess ? throw new InvalidOperationException("Cannot access Error on successful Result") : _error!;

    public static Result<T, TError> Success(T value) => new(value);
    public static Result<T, TError> Failure(TError error) => new(error);

    public Result<TOut, TError> Map<TOut>(Func<T, TOut> mapper) =>
        _isSuccess ? Result<TOut, TError>.Success(mapper(_value!)) : Result<TOut, TError>.Failure(_error!);

    public async Task<Result<TOut, TError>> MapAsync<TOut>(Func<T, Task<TOut>> mapper) =>
        _isSuccess ? Result<TOut, TError>.Success(await mapper(_value!)) : Result<TOut, TError>.Failure(_error!);
}
```

**Usage Example:**
```csharp
public readonly record struct ValidationError(string Field, string Message);

public Result<Order, ValidationError> CreateOrder(CreateOrderDto dto)
{
    if (dto.Items.Count == 0)
        return Result<Order, ValidationError>.Failure(
            new ValidationError("Items", "Order must have at least one item"));

    if (dto.Total <= 0)
        return Result<Order, ValidationError>.Failure(
            new ValidationError("Total", "Order total must be greater than zero"));

    var order = new Order
    {
        Id = Guid.NewGuid(),
        Items = dto.Items,
        Total = dto.Total
    };

    return Result<Order, ValidationError>.Success(order);
}

// Usage
var result = CreateOrder(dto);
if (result.IsFailure)
{
    return BadRequest(new { error = result.Error.Message });
}

var order = result.Value;
```

**When to Use Result vs Exceptions:**

| Scenario | Use |
|----------|-----|
| Expected business errors (validation, not found) | `Result<T, TError>` |
| Unexpected errors (network failure, null reference) | Exceptions |
| Domain validation failures | `Result<T, TError>` |
| System/infrastructure failures | Exceptions |

### Span<T> and Memory<T> for Zero-Allocation Patterns

**Concept:** Use `Span<T>` and `Memory<T>` for performance-critical code to avoid allocations and reduce GC pressure.

**When to Use:**
- High-throughput scenarios (parsing, serialization, networking)
- Working with binary data or buffers
- String manipulation in hot paths
- Array pooling scenarios

**Span<T> Examples:**

```csharp
// Zero-allocation string parsing
public bool TryParseOrderId(ReadOnlySpan<char> input, out OrderId orderId)
{
    if (Guid.TryParse(input, out var guid))
    {
        orderId = new OrderId(guid);
        return true;
    }

    orderId = default;
    return false;
}

// Usage
var input = "12345678-1234-1234-1234-123456789012".AsSpan();
if (TryParseOrderId(input, out var orderId))
{
    // Process order
}
```

**Memory<T> for Async Scenarios:**

```csharp
public async Task ProcessBufferAsync(Memory<byte> buffer, CancellationToken cancellationToken)
{
    // Memory<T> can be stored and passed across async boundaries
    // Span<T> cannot (stack-only)
    
    await ProcessChunkAsync(buffer.Slice(0, buffer.Length / 2), cancellationToken);
    await ProcessChunkAsync(buffer.Slice(buffer.Length / 2), cancellationToken);
}
```

**ArrayPool<T> for Large Allocations:**

```csharp
public void ProcessLargeData(ReadOnlySpan<byte> input)
{
    var pool = ArrayPool<byte>.Shared;
    var buffer = pool.Rent(input.Length);
    
    try
    {
        input.CopyTo(buffer);
        // Process buffer
    }
    finally
    {
        pool.Return(buffer);
    }
}
```

**StringBuilder with Span<T>:**

```csharp
public string FormatOrderId(OrderId id)
{
    var span = stackalloc char[36]; // GUID string length
    if (id.Value.TryFormat(span, out var written))
    {
        return new string(span[..written]);
    }
    
    return id.Value.ToString(); // Fallback
}
```

**When NOT to Use Span<T>/Memory<T>:**
- Simple scenarios where performance isn't critical
- Code that needs to store references across async boundaries (use `Memory<T>` instead)
- When working with existing APIs that don't support spans

### UnsafeAccessorAttribute (.NET 8+)

**Concept:** When you genuinely need to access private or internal members (serializers, test helpers, framework code), use `UnsafeAccessorAttribute` instead of traditional reflection. It provides **zero-overhead, AOT-compatible** member access.

**Why UnsafeAccessor over Reflection:**

| Aspect | Reflection | UnsafeAccessor |
|--------|------------|----------------|
| Performance | Slow (100-1000x) | Zero overhead |
| AOT compatible | No | Yes |
| Allocations | Yes (boxing, arrays) | None |
| Compile-time checked | No | Partially (signature) |

**Private Field Access:**
```csharp
// AVOID: Traditional reflection - slow, allocates, breaks AOT
var field = typeof(Order).GetField("_status", BindingFlags.NonPublic | BindingFlags.Instance);
var status = (OrderStatus)field!.GetValue(order)!;

// PREFER: UnsafeAccessor - zero overhead, AOT-compatible
[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_status")]
static extern ref OrderStatus GetStatusField(Order order);

var status = GetStatusField(order);  // Direct access, no reflection
```

**Private Method Access:**
```csharp
[UnsafeAccessor(UnsafeAccessorKind.Method, Name = "Recalculate")]
static extern void CallRecalculate(Order order);

CallRecalculate(order);
```

**Private Static Field:**
```csharp
[UnsafeAccessor(UnsafeAccessorKind.StaticField, Name = "_instanceCount")]
static extern ref int GetInstanceCount(Order order);

var count = GetInstanceCount(order);
```

**Private Constructor:**
```csharp
[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
static extern Order CreateOrder(OrderId id, CustomerId customerId);

var order = CreateOrder(orderId, customerId);
```

**Use Cases:**
- Serializers accessing private backing fields
- Test helpers verifying internal state
- Framework code that needs to bypass visibility

**Resources:**
- [A new way of doing reflection with .NET 8](https://steven-giesel.com/blogPost/05ecdd16-8dc4-490f-b1cf-780c994346a4)
- [Accessing private members without reflection in .NET 8.0](https://www.strathweb.com/2023/10/accessing-private-members-without-reflection-in-net-8-0/)

## Modern C# Features (2025)

### File-Scoped Namespaces (C# 10+)

**Microsoft Recommendation:** Use file-scoped namespaces to reduce indentation

**Before:**
```csharp
namespace MyApp.Services
{
    public class UserService
    {
        // ...
    }
}
```

**After (File-Scoped):**
```csharp
namespace MyApp.Services;

public class UserService
{
    // ...
}
```

### Primary Constructors (C# 12+)

**Microsoft Recommendation:** Use primary constructors for simple initialization

**Before:**
```csharp
public class UserService
{
    private readonly IUserRepository _userRepository;
    private readonly ILogger<UserService> _logger;
    
    public UserService(IUserRepository userRepository, ILogger<UserService> logger)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }
}
```

**After (Primary Constructor):**
```csharp
public class UserService(
    IUserRepository userRepository,
    ILogger<UserService> logger)
{
    public async Task<User?> GetUserAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await userRepository.GetByIdAsync(id, cancellationToken);
    }
}
```

### Records for Immutable Data (C# 9+)

**Microsoft Recommendation:** Use `record` types for DTOs, messages, events, and domain entities.

**When to use `record class` vs `record struct`:**
- `record class` (default): Reference types, use for entities, aggregates, DTOs with multiple properties
- `record struct`: Value types, use for value objects (see Value Objects section)

**Simple Immutable DTO:**
```csharp
/// <summary>
/// Data transfer object for creating a new user.
/// </summary>
/// <param name="Email">The user's email address.</param>
/// <param name="Name">The user's full name.</param>
public record CreateUserDto(
    string Email,
    string Name);
```

**Record with Validation in Constructor:**
```csharp
public record EmailAddress
{
    public string Value { get; init; }

    public EmailAddress(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.Contains('@'))
            throw new ArgumentException("Invalid email address", nameof(value));

        Value = value;
    }
}
```

**Record with Computed Properties:**
```csharp
public record Order(string Id, decimal Subtotal, decimal Tax)
{
    public decimal Total => Subtotal + Tax;
}
```

**Records with Collections - Use IReadOnlyList:**
```csharp
public record ShoppingCart(
    string CartId,
    string CustomerId,
    IReadOnlyList<CartItem> Items)
{
    public decimal Total => Items.Sum(item => item.Price * item.Quantity);
}
```

**Record with Init-Only Properties for Optional Fields:**
```csharp
public record UpdateUserDto
{
    public string? Email { get; init; }
    public string? Name { get; init; }
}
```

**Domain Events as Records:**
```csharp
public record UserCreatedEvent(Guid UserId, string Email, DateTime CreatedAt) : INotification;
```

### Value Objects as readonly record struct

**CRITICAL:** Value objects should **always be `readonly record struct`** for performance and value semantics.

**Why `readonly record struct` for value objects:**
- **Value semantics**: Equality based on content, not reference
- **Stack allocation**: Better performance, no GC pressure
- **Immutability**: `readonly` prevents accidental mutation
- **Pattern matching**: Works seamlessly with switch expressions

**Single-Value Object:**
```csharp
public readonly record struct OrderId(string Value)
{
    public OrderId(string value) : this(
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException("OrderId cannot be empty", nameof(value)))
    {
    }

    public override string ToString() => Value;

    // NO implicit conversions - defeats type safety!
    // Access inner value explicitly: orderId.Value
}
```

**Multi-Value Object:**
```csharp
public readonly record struct Money(decimal Amount, string Currency)
{
    public Money(decimal amount, string currency) : this(
        amount >= 0 ? amount : throw new ArgumentException("Amount cannot be negative", nameof(amount)),
        ValidateCurrency(currency))
    {
    }

    private static string ValidateCurrency(string currency)
    {
        if (string.IsNullOrWhiteSpace(currency) || currency.Length != 3)
            throw new ArgumentException("Currency must be a 3-letter code", nameof(currency));
        return currency.ToUpperInvariant();
    }

    public Money Add(Money other)
    {
        if (Currency != other.Currency)
            throw new InvalidOperationException($"Cannot add {Currency} to {other.Currency}");

        return new Money(Amount + other.Amount, Currency);
    }

    public override string ToString() => $"{Amount:N2} {Currency}";
}
```

**Complex Value Object with Factory Pattern:**
```csharp
public readonly record struct PhoneNumber
{
    public string Value { get; }

    private PhoneNumber(string value) => Value = value;

    public static Result<PhoneNumber, string> Create(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return Result<PhoneNumber, string>.Failure("Phone number cannot be empty");

        // Normalize: remove all non-digits
        var digits = new string(input.Where(char.IsDigit).ToArray());

        if (digits.Length < 10 || digits.Length > 15)
            return Result<PhoneNumber, string>.Failure("Phone number must be 10-15 digits");

        return Result<PhoneNumber, string>.Success(new PhoneNumber(digits));
    }

    public override string ToString() => Value;
}
```

**Strongly-Typed ID:**
```csharp
public readonly record struct CustomerId(Guid Value)
{
    public static CustomerId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString();
}
```

**CRITICAL: NO implicit conversions.** Implicit operators defeat the purpose of value objects by allowing silent type coercion:

```csharp
// WRONG - defeats compile-time safety:
public readonly record struct UserId(Guid Value)
{
    public static implicit operator UserId(Guid value) => new(value);  // NO!
    public static implicit operator Guid(UserId value) => value.Value; // NO!
}

// With implicit operators, this compiles silently:
void ProcessUser(UserId userId) { }
ProcessUser(Guid.NewGuid());  // Oops - meant to pass PostId

// CORRECT - all conversions explicit:
public readonly record struct UserId(Guid Value)
{
    public static UserId New() => new(Guid.NewGuid());
    // No implicit operators
    // Create: new UserId(guid) or UserId.New()
    // Extract: userId.Value
}
```

Explicit conversions force every boundary crossing to be visible:

```csharp
// API boundary - explicit conversion IN
var userId = new UserId(request.UserId);  // Validates on entry

// Database boundary - explicit conversion OUT
await _db.ExecuteAsync(sql, new { UserId = userId.Value });
```

### Pattern Matching (C# 8-12)

**Microsoft Recommendation:** Leverage modern pattern matching for cleaner, more expressive code.

**Property Patterns:**
```csharp
if (user is { IsActive: true, EmailConfirmed: true })
{
    // ...
}
```

**Switch Expressions with Value Objects:**
```csharp
public string GetPaymentMethodDescription(PaymentMethod payment) => payment switch
{
    { Type: PaymentType.CreditCard, Last4: var last4 } => $"Credit card ending in {last4}",
    { Type: PaymentType.BankTransfer, AccountNumber: var account } => $"Bank transfer from {account}",
    { Type: PaymentType.Cash } => "Cash payment",
    _ => "Unknown payment method"
};
```

**Relational and Logical Patterns:**
```csharp
public decimal CalculateDiscount(Order order) => order switch
{
    { Total: > 1000m } => order.Total * 0.15m,
    { Total: > 500m } => order.Total * 0.10m,
    { Total: > 100m } => order.Total * 0.05m,
    _ => 0m
};
```

**Type Patterns:**
```csharp
public string ProcessPayment(object payment) => payment switch
{
    CreditCardPayment card => $"Processing card ending in {card.Last4}",
    BankTransferPayment transfer => $"Processing transfer to {transfer.AccountNumber}",
    CashPayment => "Processing cash payment",
    null => throw new ArgumentNullException(nameof(payment)),
    _ => throw new ArgumentException($"Unknown payment type: {payment.GetType()}", nameof(payment))
};
```

**Tuple Patterns:**
```csharp
public string GetStatus((bool IsActive, bool IsVerified) user) => user switch
{
    (true, true) => "Active",
    (true, false) => "Pending",
    (false, _) => "Inactive"
};
```

**List Patterns (C# 11+):**
```csharp
public string GetFirstItem(List<string> items) => items switch
{
    [] => "Empty",
    [var first] => first,
    [var first, ..] => $"First: {first}, Total: {items.Count}"
};
```

## Optimizely-Specific Code Quality Patterns

### Content Type Definitions

**Best Practice:** Use proper inheritance and interfaces for Optimizely content types

```csharp
/// <summary>
/// Base page type for Optimizely CMS.
/// </summary>
[ContentType(
    GUID = "12345678-1234-1234-1234-123456789012",
    DisplayName = "Standard Page",
    Description = "Standard page content type")]
public class StandardPage : PageData
{
    /// <summary>
    /// Gets or sets the page title.
    /// </summary>
    [Display(
        Name = "Title",
        Description = "The page title",
        Order = 10)]
    [CultureSpecific]
    public virtual string? Title { get; set; }
    
    /// <summary>
    /// Gets or sets the page content.
    /// </summary>
    [Display(
        Name = "Content",
        Description = "The main content area",
        Order = 20)]
    [CultureSpecific]
    public virtual XhtmlString? MainContent { get; set; }
}
```

### Service Layer Pattern for Optimizely

```csharp
/// <summary>
/// Service for managing Optimizely content operations.
/// </summary>
public interface IContentService
{
    /// <summary>
    /// Gets a page by its content reference.
    /// </summary>
    /// <typeparam name="T">The type of content to retrieve.</typeparam>
    /// <param name="contentLink">The content reference.</param>
    /// <returns>The content if found; otherwise, null.</returns>
    T? GetPage<T>(ContentReference contentLink) where T : PageData;
}

/// <summary>
/// Implementation of content service using Optimizely APIs.
/// </summary>
public class ContentService : IContentService
{
    private readonly IContentLoader _contentLoader;
    private readonly ILogger<ContentService> _logger;
    
    public ContentService(
        IContentLoader contentLoader,
        ILogger<ContentService> logger)
    {
        _contentLoader = contentLoader ?? throw new ArgumentNullException(nameof(contentLoader));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }
    
    /// <inheritdoc />
    public T? GetPage<T>(ContentReference contentLink) where T : PageData
    {
        try
        {
            return _contentLoader.Get<T>(contentLink);
        }
        catch (ContentNotFoundException ex)
        {
            _logger.LogWarning(
                ex,
                "Content not found. ContentLink: {ContentLink}",
                contentLink);
            return null;
        }
    }
}
```

### Repository Pattern with Optimizely

```csharp
/// <summary>
/// Repository for Optimizely content operations.
/// </summary>
public interface IContentRepository
{
    /// <summary>
    /// Gets children of a content reference.
    /// </summary>
    /// <typeparam name="T">The type of content to retrieve.</typeparam>
    /// <param name="parentLink">The parent content reference.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of child content items.</returns>
    Task<IEnumerable<T>> GetChildrenAsync<T>(
        ContentReference parentLink,
        CancellationToken cancellationToken = default) where T : IContent;
}

/// <summary>
/// Optimizely implementation of content repository.
/// </summary>
public class OptimizelyContentRepository : IContentRepository
{
    private readonly IContentLoader _contentLoader;
    
    public OptimizelyContentRepository(IContentLoader contentLoader)
    {
        _contentLoader = contentLoader ?? throw new ArgumentNullException(nameof(contentLoader));
    }
    
    /// <inheritdoc />
    public Task<IEnumerable<T>> GetChildrenAsync<T>(
        ContentReference parentLink,
        CancellationToken cancellationToken = default) where T : IContent
    {
        // Optimizely operations are typically synchronous
        var children = _contentLoader.GetChildren<T>(parentLink);
        return Task.FromResult(children);
    }
}
```

## Best Practices Summary

### DO's ✅
- Use `record` for DTOs, messages, events, and domain entities
- Use `readonly record struct` for value objects
- Leverage pattern matching with `switch` expressions
- Enable and respect nullable reference types
- Use async/await for all I/O operations
- Accept `CancellationToken` in all async methods
- Use `Span<T>` and `Memory<T>` for high-performance scenarios
- Accept abstractions (`IEnumerable<T>`, `IReadOnlyList<T>`)
- Return appropriate interfaces or concrete types
- Use `Result<T, TError>` for expected errors
- Use `ConfigureAwait(false)` in library code
- Pool buffers with `ArrayPool<T>` for large allocations
- Prefer composition over inheritance
- Avoid abstract base classes in application code
- Use `UnsafeAccessorAttribute` instead of reflection when accessing private members (.NET 8+)

### DON'Ts ❌
- Don't use mutable classes when records work
- Don't use classes for value objects (use `readonly record struct`)
- Don't create deep inheritance hierarchies
- Don't ignore nullable reference type warnings
- Don't block on async code (`.Result`, `.Wait()`)
- Don't use `byte[]` when `Span<byte>` suffices
- Don't forget `CancellationToken` parameters
- Don't return mutable collections from APIs
- Don't throw exceptions for expected business errors
- Don't use `string` concatenation in loops
- Don't allocate large arrays repeatedly (use `ArrayPool`)
- Don't use implicit conversions in value objects

## Resources

### Microsoft Documentation
- **C# Coding Conventions:** https://learn.microsoft.com/dotnet/csharp/fundamentals/coding-style/coding-conventions
- **Framework Design Guidelines:** https://learn.microsoft.com/dotnet/standard/design-guidelines/
- **Async Best Practices:** https://learn.microsoft.com/dotnet/csharp/asynchronous-programming/async-scenarios
- **Exception Handling:** https://learn.microsoft.com/dotnet/csharp/fundamentals/exceptions/
- **Pattern Matching:** https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/functional/pattern-matching
- **Span<T> and Memory<T>:** https://learn.microsoft.com/dotnet/standard/memory-and-spans/
- **Modern C# Coding Standards:** https://github.com/Aaronontheweb/dotnet-skills/blob/master/skills/csharp/coding-standards/SKILL.md

### Books & Patterns
- **Clean Code (Book):** Robert C. Martin
- **Refactoring (Book):** Martin Fowler
- **Design Patterns:** https://refactoring.guru/design-patterns
- **SOLID Principles:** https://en.wikipedia.org/wiki/SOLID

### Tools
- **EditorConfig:** https://editorconfig.org/
- **StyleCop Analyzers:** https://github.com/DotNetAnalyzers/StyleCopAnalyzers
- **.NET Code Analysis:** https://learn.microsoft.com/dotnet/fundamentals/code-analysis/
- **Roslyn Analyzers:** https://github.com/dotnet/roslyn-analyzers
- **SonarAnalyzer for C#:** https://www.sonarsource.com/products/codeanalyzers/sonarcsharp.html

### Optimizely Code Quality
- **Optimizely Coding Standards:** https://docs.developers.optimizely.com/content-management-system/docs/coding-standards
- **Optimizely Best Practices:** https://docs.developers.optimizely.com/content-management-system/docs/best-practices