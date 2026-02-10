# Aegis.Auth Plugin System - Quick Reference

## 🎯 Problem Solved

Feature packages (Passkeys, TOTP, OAuth) can now be added **without ever modifying core** once it stabilizes.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Aegis.Auth (Core)                    │
│                                                         │
│  ┌────────────────┐         ┌────────────────┐        │
│  │ Email/Password │         │ Shared Services│        │
│  │   Services     │         │                │        │
│  └────────────────┘         │ • Session Mgmt │        │
│                             │ • Tokens       │        │
│  ┌────────────────┐         │ • Cookies      │        │
│  │ Core Entities  │         └────────────────┘        │
│  │ • User         │                                    │
│  │ • Session      │         ┌────────────────┐        │
│  │ • Account      │         │ IAegisAuthBuilder│       │
│  └────────────────┘         │ (Extension Point)│       │
│                             └────────────────┘        │
└─────────────────────────────────────────────────────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
       ┌────────▼──────┐  ┌───▼──────┐  ┌───▼─────────┐
       │ Aegis.Auth.   │  │ Aegis.   │  │ Aegis.Auth. │
       │   Passkeys    │  │ Auth.    │  │    SSO      │
       │               │  │  Totp    │  │             │
       │ • Entities    │  │          │  │ • Entities  │
       │ • Services    │  │ • Entities│  │ • Services  │
       │ • Controllers │  │ • Services│  │ • Controllers│
       │ • .AddPasskeys()│ │ • Controllers│ • .AddOAuth() │
       └───────────────┘  └──────────┘  └─────────────┘
```

## ✨ Key Interfaces

### IAegisAuthBuilder

```csharp
public interface IAegisAuthBuilder
{
    IServiceCollection Services { get; }
    AegisAuthOptions Options { get; }
}
```

**Purpose:** Enable fluent chaining and access to DI + core options.

### IAegisSessionService

```csharp
public interface IAegisSessionService
{
    Task<Session> CreateSessionAsync(User user, HttpContext context, ...);
    Task InvalidateSessionAsync(string sessionId, HttpContext context, ...);
}
```

**Purpose:** Shared session logic across all sign-in methods.

## 📋 Feature Package Template

```
Aegis.Auth.[Feature]/
├── Entities/           # DbContext entities (e.g., PasskeyCredential)
├── Options/            # Configuration (e.g., PasskeyOptions)
├── Abstractions/       # Service interfaces (e.g., IPasskeyService)
├── Services/           # Implementations
├── Controllers/        # HTTP endpoints
├── Extensions/         # .Add[Feature]() method
└── README.md          # Consumer documentation
```

## 🚀 Consumer Usage

```csharp
// Program.cs
builder.Services
    .AddAegisAuth<AppDbContext>(options =>
    {
        options.AppName = "My App";
        options.BaseURL = "https://example.com";
        options.Secret = "secret";
    })
    .AddPasskeys(passkey =>
    {
        passkey.RelyingPartyName = "My App";
        passkey.RelyingPartyId = "example.com";
    })
    .AddTotp(totp =>
    {
        totp.Issuer = "My App";
    });

// AppDbContext.cs
public class AppDbContext : DbContext, IAuthDbContext
{
    // Core (required)
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();

    // Features (opt-in)
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    public DbSet<TotpDevice> TotpDevices => Set<TotpDevice>();
}
```

## 🔌 Creating a Feature Package

### 1. Extension Method

```csharp
public static IAegisAuthBuilder Add[Feature](
    this IAegisAuthBuilder builder,
    Action<[Feature]Options>? configure = null)
{
    var options = new [Feature]Options();
    configure?.Invoke(options);

    builder.Services.AddSingleton(options);
    builder.Services.AddScoped<I[Feature]Service, [Feature]Service>();

    return builder; // ← Enable chaining
}
```

### 2. Service Implementation

```csharp
public class [Feature]Service : I[Feature]Service
{
    private readonly IAuthDbContext _dbContext;
    private readonly IAegisSessionService _sessionService; // ← Shared!

    public async Task<Result<User>> AuthenticateAsync(...)
    {
        // Feature-specific authentication logic
        var user = ...;
        return Result<User>.Success(user);
    }
}
```

### 3. Controller

```csharp
[ApiController]
[Route("auth/[feature]")]
public class [Feature]Controller : AegisControllerBase
{
    private readonly I[Feature]Service _featureService;
    private readonly IAegisSessionService _sessionService; // ← Shared!

    [HttpPost("sign-in")]
    public async Task<IActionResult> SignIn(...)
    {
        var userResult = await _featureService.AuthenticateAsync(...);
        if (!userResult.IsSuccess) return BadRequest(userResult.Error);

        var session = await _sessionService.CreateSessionAsync(
            userResult.Value, HttpContext);

        return Ok(new { user = userResult.Value, session });
    }
}
```

## 📊 Comparison Table

| Aspect           | Core Package                     | Feature Package                   |
| ---------------- | -------------------------------- | --------------------------------- |
| **Entities**     | User, Session, Account           | PasskeyCredential, TotpDevice     |
| **Services**     | SignInService, SignUpService     | PasskeyService, TotpService       |
| **Controllers**  | `/auth/sign-in`, `/auth/sign-up` | `/auth/passkey/*`, `/auth/totp/*` |
| **Options**      | `AegisAuthOptions`               | `PasskeyOptions`, `TotpOptions`   |
| **Extension**    | `.AddAegisAuth<TContext>()`      | `.AddPasskeys()`, `.AddTotp()`    |
| **Shared Utils** | Provides                         | Consumes                          |

## ✅ Benefits Summary

1. **Zero Core Changes:** Add features without touching core
2. **Type-Safe:** Strong typing, IntelliSense, compile-time checks
3. **Explicit:** No reflection, no magic, no dynamic schemas
4. **Composable:** Mix and match features as needed
5. **Testable:** Test features independently
6. **Maintainable:** Clear separation of concerns
7. **Discoverable:** Fluent API, clear documentation

## 🎓 Mental Model

Think of it like:

- **ASP.NET Core Auth:** `.AddAuthentication().AddJwtBearer().AddGoogle()`
- **EF Core:** Explicit `DbSet<T>` declarations
- **BetterAuth:** Plugin-based, great DX
- **Clean Architecture:** Clear boundaries, dependency inversion

## 📚 Documentation Map

- **[PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md)** - Full design explanation
- **[CREATING_FEATURES.md](CREATING_FEATURES.md)** - Step-by-step guide
- **[API_ENDPOINTS.md](API_ENDPOINTS.md)** - HTTP endpoint reference
- **examples/** - Real implementations

## 🎯 Next Steps

1. **Stabilize Core:** Finalize email/password, session management
2. **Complete Passkeys:** Full WebAuthn implementation
3. **Add TOTP:** Two-factor authentication
4. **Add OAuth:** Social sign-in (Google, GitHub, etc.)
5. **Add Magic Links:** Passwordless email authentication

Each can be developed **independently** and **in parallel** without core changes.

---

**Mission Accomplished:** You now have a plugin architecture that fits exactly how you're building Aegis.Auth. 🎉
