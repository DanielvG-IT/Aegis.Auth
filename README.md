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
- Optional distributed cache layer (any `IDistributedCache`, e.g. Redis/memory) on top of the database; without one, sessions are stored in the database only
- Optional encrypted cookie session data cache
- Email verification (optionally required before sign-in)
- Password reset (token-only, no session required)
- CSRF protection
- Opt-in persistent account lockout after repeated failed sign-ins
- OAuth (Google, GitHub, Microsoft, Apple) with account linking and PKCE (S256) by default
- Rate limiting per client IP and per email (see [Rate limiting](#rate-limiting))

### Known gaps

- Rate limit counters are kept in memory per instance. Shared storage for multi-instance deployments and per-endpoint custom rules are tracked in [#120](https://github.com/DanielvG-IT/Aegis.Auth/issues/120) and [#98](https://github.com/DanielvG-IT/Aegis.Auth/issues/98).

### Planned

The full roadmap is tracked in [#86](https://github.com/DanielvG-IT/Aegis.Auth/issues/86): plugins, organizations, SSO (OIDC + SAML 2.0), SCIM, passkeys, 2FA, API keys, an OAuth/OIDC provider with MCP support, billing integrations and more. Contributors and coding agents should start with [`AGENTS.md`](AGENTS.md).

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

## Password reset & email verification

Tokens are delivered only through delegates you configure; they never appear in an HTTP
response. The endpoints under `/api/auth/password-reset/*` and `/api/auth/email-verify/*`
are mapped only when the matching delegate is set.

```csharp
builder.Services.AddAegisAuth<AppDbContext>(options =>
{
    // ...
    options.EmailAndPassword.SendResetPassword = (ctx, ct) =>
        ctx.Services.GetRequiredService<IEmailSender>()
            .SendResetLinkAsync(ctx.User.Email, $"https://app.example.com/reset?token={ctx.Token}", ct);

    options.EmailAndPassword.RequireEmailVerification = true; // block sign-in until verified
    options.EmailVerification.SendVerificationEmail = (ctx, ct) =>
        ctx.Services.GetRequiredService<IEmailSender>()
            .SendVerifyLinkAsync(ctx.User.Email, $"https://app.example.com/verify?token={ctx.Token}", ct);
});
```

| Endpoint | Body | Notes |
| --- | --- | --- |
| `POST /api/auth/password-reset/send-token` | `{ email }` | Same response whether or not the account exists |
| `POST /api/auth/password-reset/reset` | `{ token, newPassword }` | Revokes all sessions by default (`RevokeSessionsOnPasswordReset`) |
| `POST /api/auth/email-verify/send-token` | `{ email? }` | Uses the session's user when signed in |
| `POST /api/auth/email-verify/verify` | `{ token }` | No session required |

Startup validation fails if `RequireEmailVerification`, `SendOnSignUp` or `SendOnSignIn` is
enabled without a `SendVerificationEmail` delegate.

## Account lockout

Opt-in, because anyone who knows an email address can lock that account:

```csharp
options.AccountLockout.Enabled = true;
options.AccountLockout.MaxFailedAttempts = 10;
options.AccountLockout.LockoutDuration = TimeSpan.FromMinutes(15);
options.AccountLockout.PermanentLockout = false; // true: stays locked until unlocked
```

Locked accounts get `ACCOUNT_LOCKED` (HTTP 403). Unlock from your own admin endpoint with
`IAccountLockoutService.UnlockAsync(userId)`. Lockout state lives on `User`
(`FailedSignInCount`, `LockoutUntil`), so add a migration when upgrading.

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

## Benchmarks

`benchmarks/Aegis.Auth.Benchmarks` measures the hot paths with [BenchmarkDotNet](https://benchmarkdotnet.org). It builds with the solution but never runs in CI's build and test jobs.

```bash
# Everything, SQLite only (no Docker needed)
dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- --filter '*'

# Add PostgreSQL: starts postgres:17-alpine through Testcontainers (needs Docker)
dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- --postgres --filter '*'

# Use an existing PostgreSQL server instead; the benchmarks create and drop their own databases
AEGIS_BENCH_POSTGRES="Host=localhost;Username=postgres;Password=postgres" \
  dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- --filter '*'

# One group, or list what exists
dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- --filter '*Queries*'
dotnet run -c Release --project benchmarks/Aegis.Auth.Benchmarks -- --list flat
```

Any other argument goes to BenchmarkDotNet (`--job short` for a quicker, noisier pass). Results, including GitHub-flavoured Markdown tables, land in `BenchmarkDotNet.Artifacts/results/`.

| Group | Benchmarks |
|---|---|
| Crypto | `SessionTokenHashBenchmark` (SHA-256 token hash, token generation), `CookieSignBenchmark` (HMAC sign/verify), `CookieCacheEncryptBenchmark` (AES-256-GCM vs compact `session_data`), `PasswordHashBenchmark` (BCrypt work factor 10/11/12/14) |
| Session | `SessionValidationBenchmark`: one request through `AegisAuthenticationHandler` with a cookie-cache hit (compact, encrypted), a database lookup, and a secondary-storage (`IDistributedCache`) lookup |
| Sign-in | `SignInBenchmark`: `SignInEmail` end to end (lookup, BCrypt verify, session insert), plus wrong-password and unknown-email timings |
| Queries | `SessionByTokenHashBenchmark`, `UserByEmailBenchmark`, `TokenConsumeBenchmark`: EF Core tracked vs `AsNoTracking` vs compiled query (with and without a pooled context) vs Dapper |

Database benchmarks seed 10,000 users (each with an account, a session and a verification token) and run once per provider. Every variant is checked to return the same row before it is measured. Compare numbers only within one run on one machine; a laptop and a CI runner differ far more than most of the variants do.

## Project structure

```
src/
  Aegis.Auth/          — Core: entities, services, crypto, options
  Aegis.Auth.Http/     — HTTP endpoints, protection extensions

tests/
  Aegis.Auth.Tests/    — xUnit tests

benchmarks/
  Aegis.Auth.Benchmarks/ — BenchmarkDotNet suite (see Benchmarks)

samples/
  Aegis.Auth.Sample/
```

## Contributing

PRs welcome. Follow `.editorconfig` and add tests for new features.
