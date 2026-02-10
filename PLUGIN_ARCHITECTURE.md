# Aegis.Auth Plugin Architecture

## 🎯 Design Philosophy

Aegis.Auth uses a **builder-based extension pattern** that allows feature packages to:

- ✅ Add new authentication methods without modifying core
- ✅ Register services, options, and endpoints independently
- ✅ Share common utilities (session management, cookies, tokens)
- ✅ Maintain type safety and discoverability
- ✅ Keep explicit EF Core DbContext patterns (no dynamic schema mutation)

This feels like **ASP.NET Core's authentication middleware** + **BetterAuth's DX** + **EF Core's explicitness**.

---

## 🏗️ Architecture Overview

### Core Package: `Aegis.Auth`

**Responsibilities:**

- Basic email/password authentication
- Core entities: `User`, `Account`, `Session`, `Verification`
- Core services: `ISignInService`, `ISignUpService`
- Shared utilities: `IAegisSessionService`, `TokenGenerator`, `AegisCookieManager`
- Builder abstraction: `IAegisAuthBuilder`

**What it DOESN'T own:**

- OAuth, Passkeys, TOTP, or any advanced features
- Feature-specific endpoints or entities

### Feature Packages: `Aegis.Auth.*`

Examples: `Aegis.Auth.Passkeys`, `Aegis.Auth.Totp`, `Aegis.Auth.SSO`

**Each feature package can:**

1. Define its own entities (e.g., `PasskeyCredential`)
2. Define its own options (e.g., `PasskeyOptions`)
3. Define its own services (e.g., `IPasskeyService`)
4. Define its own controllers/endpoints (e.g., `/auth/passkey/*`)
5. Use shared core utilities (`IAegisSessionService`)

---

## 🔧 How It Works

### 1. Core Builder Pattern

```csharp
public interface IAegisAuthBuilder
{
    IServiceCollection Services { get; }
    AegisAuthOptions Options { get; }
}
```

The core `AddAegisAuth()` returns this builder, enabling fluent extension:

```csharp
builder.Services
    .AddAegisAuth<AppDbContext>(options =>
    {
        options.AppName = "My App";
        options.BaseURL = "https://example.com";
        options.Secret = "your-secret";
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
```

### 2. Shared Session Service

Core provides `IAegisSessionService` that ALL authentication methods use:

```csharp
public interface IAegisSessionService
{
    Task<Session> CreateSessionAsync(User user, HttpContext context, ...);
    Task InvalidateSessionAsync(string sessionId, HttpContext context, ...);
}
```

**Why this matters:**

- Email/password sign-in uses it
- Passkey sign-in uses it
- OAuth callback uses it
- TOTP verification uses it

**Result:** Consistent session handling across all methods, zero duplication.

### 3. Independent Controllers

Feature packages add their own controllers:

```csharp
[ApiController]
[Route("auth/passkey")]
public sealed class PasskeyController : AegisControllerBase
{
    private readonly IPasskeyService _passkeyService;
    private readonly IAegisSessionService _sessionService; // Shared!

    [HttpPost("sign-in/verify")]
    public async Task<IActionResult> VerifyAuthentication(...)
    {
        var user = await _passkeyService.VerifyAuthenticationAsync(...);
        var session = await _sessionService.CreateSessionAsync(user, HttpContext);
        return Ok(new { user, session });
    }
}
```

**No modification to core controllers needed.** Each feature is self-contained.

### 4. Explicit DbContext Extension

Consumers add feature entities to their DbContext:

```csharp
public class AppDbContext : DbContext, IAuthDbContext
{
    // Core entities (required)
    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Verification> Verifications => Set<Verification>();

    // Feature entities (opt-in)
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    public DbSet<TotpDevice> TotpDevices => Set<TotpDevice>();
}
```

**No reflection.** **No dynamic schemas.** Pure EF Core.

---

## 📦 Example: Adding Passkeys Feature

### Step 1: Feature Package Structure

```
Aegis.Auth.Passkeys/
├── Entities/
│   └── PasskeyCredential.cs        # Entity definition
├── Options/
│   └── PasskeyOptions.cs           # Configuration
├── Abstractions/
│   └── IPasskeyService.cs          # Service interface
├── Services/
│   └── PasskeyService.cs           # Implementation
├── Controllers/
│   └── PasskeyController.cs        # Endpoints
└── Extensions/
    └── PasskeyExtensions.cs        # .AddPasskeys() method
```

### Step 2: Extension Method

```csharp
public static class PasskeyExtensions
{
    public static IAegisAuthBuilder AddPasskeys(
        this IAegisAuthBuilder builder,
        Action<PasskeyOptions>? configure = null)
    {
        var options = new PasskeyOptions();
        configure?.Invoke(options);

        // Register services
        builder.Services.AddSingleton(options);
        builder.Services.AddScoped<IPasskeyService, PasskeyService>();

        return builder; // Enable chaining
    }
}
```

### Step 3: Consumer Usage

```csharp
// Program.cs
builder.Services
    .AddAegisAuth<AppDbContext>(options =>
    {
        options.AppName = "My App";
        options.Secret = "secret";
    })
    .AddPasskeys(passkey =>
    {
        passkey.RelyingPartyName = "My App";
        passkey.RelyingPartyId = "example.com";
    });

// AppDbContext.cs
public class AppDbContext : DbContext, IAuthDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>(); // ← Add this
}
```

### Step 4: Endpoints Available

Feature package automatically adds:

- `POST /auth/passkey/register/options` - Generate registration challenge
- `POST /auth/passkey/register/verify` - Verify and store credential
- `POST /auth/passkey/sign-in/options` - Generate authentication challenge
- `POST /auth/passkey/sign-in/verify` - Verify and create session

**No routes registered in core. No coupling.**

---

## 🔑 Key Benefits

### ✅ Zero Core Modification

Once core is stable, feature packages never touch it. They extend, don't replace.

### ✅ Type-Safe & Discoverable

```csharp
builder.Services.AddAegisAuth<AppDbContext>(...)
    .AddPasskeys(...) // ← IntelliSense shows this
    .AddTotp(...)     // ← And this
```

### ✅ Shared Utilities

All features use `IAegisSessionService`, `TokenGenerator`, `AegisCookieManager` - no reinventing the wheel.

### ✅ Explicit DbContext

```csharp
public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
```

Pure EF Core. No magic. Full migration control.

### ✅ Independent Testing

Test passkey feature without loading OAuth feature. Test core without loading any features.

### ✅ Composable

```csharp
.AddAegisAuth<AppDbContext>(...)
    .AddPasskeys(...)
    .AddTotp(...)
    .AddOAuth(oauth => oauth.AddGoogle(...).AddGitHub(...))
```

---

## 🚀 Extending Further: TOTP Example

```csharp
public static class TotpExtensions
{
    public static IAegisAuthBuilder AddTotp(
        this IAegisAuthBuilder builder,
        Action<TotpOptions>? configure = null)
    {
        var options = new TotpOptions();
        configure?.Invoke(options);

        builder.Services.AddSingleton(options);
        builder.Services.AddScoped<ITotpService, TotpService>();

        return builder;
    }
}

// Controller adds these endpoints:
// POST /auth/totp/setup
// POST /auth/totp/verify
// POST /auth/totp/remove
```

Consumer:

```csharp
builder.Services
    .AddAegisAuth<AppDbContext>(...)
    .AddTotp(totp => totp.Issuer = "My App");

// Add to DbContext:
public DbSet<TotpDevice> TotpDevices => Set<TotpDevice>();
```

---

## 📋 Checklist for Creating a Feature Package

1. **Define Entities** (if needed)
    - Example: `PasskeyCredential`, `TotpDevice`, `OAuthConnection`

2. **Define Options**
    - Example: `PasskeyOptions`, `TotpOptions`

3. **Define Service Interface**
    - Example: `IPasskeyService`, `ITotpService`

4. **Implement Service**
    - Use `IAuthDbContext` for data access
    - Use shared utilities (`IAegisSessionService`, etc.)

5. **Create Controller**
    - Inherit from `AegisControllerBase`
    - Inject feature service + shared services
    - Define routes under `/auth/{feature}/...`

6. **Create Extension Method**
    - Return `IAegisAuthBuilder` for chaining
    - Register options, services
    - Validate required configuration

7. **Document Consumer Requirements**
    - Which entities to add to DbContext
    - Which options to configure
    - Example usage

---

## 🎓 Mental Model

Think of Aegis.Auth like:

| Concept         | Aegis.Auth Equivalent                                       |
| --------------- | ----------------------------------------------------------- |
| ASP.NET Core    | `AddAegisAuth()` is like `AddAuthentication()`              |
| Middleware      | Feature packages are like `.AddJwtBearer()`, `.AddGoogle()` |
| Builder Pattern | `IAegisAuthBuilder` enables fluent chaining                 |
| Shared Services | `IAegisSessionService` is like `IAuthenticationService`     |
| Options Pattern | Each feature has its own `*Options` class                   |
| EF Core         | Explicit `DbSet<T>` in consumer's DbContext                 |

---

## ✨ Comparison to BetterAuth

| BetterAuth (TypeScript) | Aegis.Auth (C#)                             |
| ----------------------- | ------------------------------------------- |
| `plugins: [passkey()]`  | `.AddPasskeys()`                            |
| Runtime schema mutation | Explicit `DbSet<PasskeyCredential>`         |
| Plugin exports routes   | Feature package has `PasskeyController`     |
| Plugin options          | `PasskeyOptions` passed to `.AddPasskeys()` |
| Plugin hooks            | Shared services like `IAegisSessionService` |

Same developer experience, **C# idioms, EF Core control**.

---

## 🏁 Result

You now have a plugin architecture that:

- ✅ Matches BetterAuth's DX
- ✅ Respects ASP.NET Core patterns
- ✅ Maintains EF Core explicitness
- ✅ Requires zero core changes once stable
- ✅ Is type-safe and discoverable
- ✅ Allows independent feature development

**This is exactly how you're already building it.** The foundation is now in place.
