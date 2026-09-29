# Aegis.Auth

Modular authentication library for .NET, inspired by BetterAuth (TypeScript).

## Status

This is v0.1 — actively developed. The feature set below reflects what is **actually implemented and tested**, not a target state.

### Implemented

- Email/password sign-up
- Email/password sign-in
- Database-backed sessions with HMAC-signed cookies
- Session token hashing (raw token never stored in the database)
- Cookie-based authentication (`aegis.session` / `__Host-aegis.session`)
- Logout / session revocation
- Revoke all sessions for a user
- Current user/session lookup via `IAegisAuthContextAccessor`
- Native ASP.NET Core authentication handler (`AegisAuthenticationHandler`)
- `HttpContext.User` population with claims
- `[Authorize]` and `RequireAuthorization()` support
- `RequireAegisAuth()` convenience wrapper for minimal APIs
- Optional distributed cache layer (Redis/memory) on top of PostgreSQL
- Optional encrypted cookie session data cache
- Email verification
- Password reset
- CSRF protection
- Rate limiting / brute-force protection
- OAuth (Google, GitHub, Microsoft, Apple) with account linking

### Planned

- Passkeys
- TOTP
- Hooks / events system
- `Aegis.Auth.EntityFrameworkCore` package split
- `Aegis.Auth.OAuth.*` provider packages

## Getting Started

```bash
git clone https://github.com/DanielvG-IT/Aegis.Auth.git
cd Aegis.Auth
dotnet restore
dotnet build
```

## Minimal setup

```csharp
// Program.cs
builder.Services.AddAegisAuth<AppDbContext>(options =>
{
    options.AppName = "MyApp";
    options.BaseURL = "https://localhost:5001";
    options.Secret = "replace-with-a-32-char-secret-at-minimum";

    options.EmailAndPassword.Enabled = true;
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapAegisAuthEndpoints();

// Protected endpoints
app.MapGet("/api/me", (HttpContext ctx) =>
{
    var auth = ctx.GetAegisAuthContext();
    return Results.Ok(new { auth!.UserId });
})
.RequireAegisAuth();
```

## Extending the database model

Library consumers own their `DbContext` and implement `IAuthDbContext`:

```csharp
using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Microsoft.EntityFrameworkCore;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options)
    : DbContext(options), IAuthDbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Session> Sessions => Set<Session>();

    // App-specific tables
    public DbSet<Project> Projects => Set<Project>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyAegisAuthModel();
    }
}
```

## Rate limiting

Enabled by default. Rejected requests get `429 Too Many Requests` with a problem details body whose `errorCode` is `TOO_MANY_REQUESTS`.

```csharp
options.RateLimit.Enabled = true;                     // default
options.RateLimit.MaxAttemptsPerIpPerMinute = 10;     // per client IP, per endpoint
options.RateLimit.MaxAttemptsPerEmailPer15Minutes = 5; // sign-in attempts per email, from any IP
```

- The per-IP limit covers email sign-in and sign-up, password reset (send-token, reset) and email verification (send-token, verify). IPv6 clients are grouped by /64.
- The per-email limit counts every sign-in attempt, successful or not, so a distributed attack cannot brute-force one account.
- Limits are enforced by the endpoints themselves; no `app.UseRateLimiter()` call is needed.
- Behind a reverse proxy, configure [forwarded headers](https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer) so each client is seen with its own IP instead of the proxy's.
- Counters live in memory per application instance, so with several instances each enforces the limits separately.

## Project structure

```
src/
  Aegis.Auth/          — Core: entities, services, crypto, options
  Aegis.Auth.Http/     — HTTP endpoints, protection extensions

tests/
  Aegis.Auth.Tests/    — xUnit tests

samples/
  Aegis.Auth.Sample/
```

## Contributing

PRs welcome. Follow `.editorconfig` and add tests for new features.
