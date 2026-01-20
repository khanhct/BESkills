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
- [ ] Pattern matching used where beneficial
- [ ] XML documentation comments for public APIs (`/// <summary>`)
- [ ] File-scoped namespaces used (C# 10+)
- [ ] Primary constructors used where appropriate (C# 12+)
- [ ] Record types used for immutable DTOs and value objects
- [ ] Init-only properties for immutable data structures

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

### Record Types for DTOs

**Microsoft Recommendation:** Use records for immutable data transfer objects

**Before:**
```csharp
public class CreateUserDto
{
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}
```

**After (Record):**
```csharp
/// <summary>
/// Data transfer object for creating a new user.
/// </summary>
/// <param name="Email">The user's email address.</param>
/// <param name="Name">The user's full name.</param>
public record CreateUserDto(
    string Email,
    string Name);

// Or with init-only properties for optional fields
public record UpdateUserDto
{
    public string? Email { get; init; }
    public string? Name { get; init; }
}
```

### Pattern Matching Enhancements

**Microsoft Recommendation:** Use pattern matching for cleaner conditional logic

**Before:**
```csharp
if (user != null && user.IsActive && user.EmailConfirmed)
{
    // ...
}
```

**After (Pattern Matching):**
```csharp
if (user is { IsActive: true, EmailConfirmed: true })
{
    // ...
}

// Switch expressions
var status = user switch
{
    { IsActive: true, EmailConfirmed: true } => "Active",
    { IsActive: true, EmailConfirmed: false } => "Pending",
    _ => "Inactive"
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

## Resources

### Microsoft Documentation
- **C# Coding Conventions:** https://learn.microsoft.com/dotnet/csharp/fundamentals/coding-style/coding-conventions
- **Framework Design Guidelines:** https://learn.microsoft.com/dotnet/standard/design-guidelines/
- **Async Best Practices:** https://learn.microsoft.com/dotnet/csharp/asynchronous-programming/async-scenarios
- **Exception Handling:** https://learn.microsoft.com/dotnet/csharp/fundamentals/exceptions/

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