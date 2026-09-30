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
- Secondary storage (`IAegisSecondaryStorage`): short-lived key/value state with TTL, atomic increments and set-if-not-exists; in-memory, database or `IDistributedCache` backed (see [Secondary storage](#secondary-storage))
- Organizations (`Aegis.Auth.Organizations`): organizations, members, owner/admin/member roles with permissions, the active organization per session, and `RequireOrganizationPermission` for your own endpoints (see [Organizations](#organizations))
- Plugin contract: features contribute services, EF model, endpoints, error codes, rate-limit rules and startup validation (see [Plugins](#plugins)). Email verification is built on it.

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
    public DbSet<AuthToken> AuthTokens => Set<AuthToken>();
    public DbSet<AegisKeyValue> AegisKeyValues => Set<AegisKeyValue>();

    // App-specific tables
    public DbSet<Project> Projects => Set<Project>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyAegisAuthModel();
    }
}
```

`ApplyAegisAuthModel` maps the core entities only. To also get the tables of registered plugins, add
`UseAegisAuth(sp)` after the database provider:

```csharp
builder.Services.AddDbContext<AppDbContext>((sp, options) =>
    options.UseSqlite(connectionString).UseAegisAuth(sp));
```

With `UseAegisAuth`, Aegis applies the core model (with OAuth tokens encrypted at rest) and every plugin's
model before your `OnModelCreating` runs, so your own configuration still wins. You can drop the
`ApplyAegisAuthModel` call; keeping it is harmless. Call `UseAegisAuth` after the provider (`UseSqlite`,
`UseSqlServer`, …), otherwise it throws.

## Plugins

`AddAegisAuth<TContext>()` returns an `IAegisAuthBuilder`. Plugins are added on it, usually through an
extension method the plugin ships:

```csharp
builder.Services
    .AddAegisAuth<AppDbContext>(options => { /* ... */ })
    .AddPlugin(new MyPlugin());

// Plugin endpoints are mapped under the Aegis base path, after the core endpoints.
app.MapAegisAuthEndpoints();
```

- Plugin ids are unique; registering one twice fails at startup. So does a plugin route that collides with a core route or another plugin's route.
- Plugin option validation runs with the core validation, so the app fails to start with every message at once.
- Plugin error codes get their own HTTP status in the ProblemDetails response (`errorCode` extension).
- Plugins that add tables need `UseAegisAuth` on the `DbContext` (see above) and a migration; without `UseAegisAuth` the app fails to start.
- A plugin can require another (e.g. SSO requires organizations); a missing dependency fails at startup.
- Email verification is a built-in plugin (`EmailVerificationPlugin`, id `email-verification`), registered by `AddAegisAuth`.

Writing a plugin is described in [`AGENTS.md`](AGENTS.md#writing-a-plugin).

> **Upgrading:** `AddAegisAuth<TContext>()` now returns `IAegisAuthBuilder` instead of `IServiceCollection`.
> The builder is an `IServiceCollection` too, so existing code compiles unchanged, but libraries compiled
> against the old signature must be rebuilt.
>
> `AegisAuthContext` has a new required `SessionId`. Code that constructs it itself (e.g. in tests) must set it.

## Organizations

The `Aegis.Auth.Organizations` package is a plugin that adds organizations, members and roles.

```csharp
builder.Services.AddDbContext<AppDbContext>((sp, o) => o.UseSqlite(cs).UseAegisAuth(sp));
builder.Services.AddAegisAuth<AppDbContext>(options => { /* ... */ })
    .AddOrganizations(o =>
    {
        o.OrganizationLimit = 5;          // organizations per user
        o.MembershipLimit = 100;          // members per organization
        o.AllowUserToCreateOrganization = user => Task.FromResult(true);
        o.Roles["admin"].Permissions.Add("project:create"); // your own permissions
    });
```

It adds the `Organizations` and `OrganizationMembers` tables and a `Session.ActiveOrganizationId` column, so add a migration.

| Option | Default | Notes |
|---|---|---|
| `OrganizationLimit` | 5 | Organizations a user can belong to |
| `MembershipLimit` | 100 | Members per organization |
| `AllowUserToCreateOrganization` | always | `Func<User, Task<bool>>` |
| `CreatorRole` | `owner` | Role of the user who creates an organization |
| `Roles` | owner (300), admin (200), member (100) | Rank and `resource:action` permissions per role |
| `MapAddMemberEndpoint` | false | Adding members directly is a server-side API (`IOrganizationService.AddMemberAsync`) until invitations ship |

Endpoints, under `/organization`, all require sign-in. Where `organizationId` is optional, the session's active organization is used.

| Method | Path | Requires |
|---|---|---|
| POST | `/create` | caller becomes `owner`; set as active |
| GET | `/check-slug?slug=` | |
| POST | `/update` | `organization:update` |
| POST | `/delete` | `organization:delete`; removes members |
| GET | `/list` | the caller's organizations |
| GET | `/full` | membership |
| POST | `/set-active` | membership (`null` clears) |
| GET | `/active-member` | |
| POST | `/members/remove`, `/members/update-role` | `member:delete` / `member:update` |
| POST | `/leave` | membership |

Rules enforced server-side:
- Every organization-scoped call re-checks membership in the database. Non-members and unknown ids both get `ORG_NOT_MEMBER`.
- A member cannot grant, change or remove a role ranked above their own.
- An organization always keeps an owner (`ORG_LAST_OWNER`).
- Deleting a user removes their memberships.

Protect your own endpoints by the caller's role in their active organization:

```csharp
app.MapPost("/projects", CreateProject).RequireOrganizationPermission("project:create");
```

Organization logs use event IDs 10000–10999. Invitations, teams, dynamic roles and hooks are separate issues.

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

## Secondary storage

`IAegisSecondaryStorage` holds short-lived, high-churn state (challenges, single-use request IDs,
attempt counters, caches). Every entry has a TTL. Inject it anywhere; `AddAegisAuth` registers the
in-memory implementation by default.

```csharp
var key = AegisStorageKey.Create("my-plugin", "challenge", challengeId); // aegis:my-plugin:challenge:{challengeId}

await storage.SetAsync(key, payload, TimeSpan.FromMinutes(5));
string? value = await storage.GetAsync(key);                          // null when missing or expired
bool deleted = await storage.DeleteAsync(key);
long attempts = await storage.IncrementAsync(key, TimeSpan.FromMinutes(15)); // counter; expiry set on first increment
bool first = await storage.SetIfNotExistsAsync(key, "used", TimeSpan.FromMinutes(5)); // single-use / replay protection
```

Choose the implementation with one call, before or after `AddAegisAuth`:

| Registration | Shared across instances | `IncrementAsync` / `SetIfNotExistsAsync` |
| --- | --- | --- |
| _(default)_ in-memory | No | Atomic |
| `builder.Services.AddAegisDatabaseSecondaryStorage()` | Yes, `AegisKeyValues` table | Atomic (primary key conflict + conditional update) |
| `builder.Services.AddAegisDistributedCacheSecondaryStorage()` | Yes, any registered `IDistributedCache` | **Not atomic** |
| Your own `IAegisSecondaryStorage` (register it before `AddAegisAuth`) | Up to you | Up to you |

- **The `IDistributedCache` adapter is not atomic.** `IDistributedCache` has no compare-and-set, so concurrent
  increments can be lost and more than one caller can win `SetIfNotExistsAsync`. A warning (event ID 9000)
  is logged at startup. Don't use it where single-use or replay protection must hold across instances;
  use the database storage (or a Redis implementation, planned as `Aegis.Auth.Redis`).
- The database storage needs a relational EF Core provider and the `AegisKeyValues` table, which
  `ApplyAegisAuthModel` maps. Add a migration when upgrading. Expired rows are ignored and purged
  every few minutes.
- Keys are at most 256 characters. Values are stored as given: never use a raw secret (token, code) as a key or value; store its SHA-256 hash instead.
- Expiry uses the registered `TimeProvider` (`TimeProvider.System` by default).

Secondary storage logs use event IDs 9000–9999.

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
  Aegis.Auth/          — Core: entities, services, crypto, options, plugin contract
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
