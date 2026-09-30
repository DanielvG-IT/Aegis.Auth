# AGENTS.md

Guide for coding agents (and humans) working on Aegis.Auth. Read this before picking up an issue.
The roadmap lives in [#86](https://github.com/DanielvG-IT/Aegis.Auth/issues/86); every roadmap issue links to its epic and dependencies.

## Repository map

| Path | What lives there |
|---|---|
| `src/Aegis.Auth` | Core: entities (`Entities/`), options (`Options/`), one folder per feature with its service (`Features/<Feature>/`), EF model (`Extensions/ModelBuilderExtensions.cs`), DI + startup validation (`Extensions/ServiceCollectionExtensions.cs`), crypto (`Core/Crypto/`), error codes (`Constants/ErrorCodes.cs`), log messages (`Logging/LogMessages.cs`), plugin contract (`Plugins/`), EF model integration for plugins (`Infrastructure/EntityFramework/`) |
| `src/Aegis.Auth.Organizations` | Organizations plugin (`AddOrganizations`): entities, `OrganizationService`, endpoints under `/organization` |
| `src/Aegis.Auth.Http` | Minimal-API endpoints (`Features/<Feature>/*Endpoints.cs`), endpoint mapping (`Extensions/AegisAuthEndpointRouteBuilderExtensions.cs`), error → ProblemDetails mapping (`Internal/AegisHttpResultMapper.cs`, which delegates to `Plugins/AegisResults.cs` in core) |
| `tests/Aegis.Auth.Tests` | xUnit. Service tests use strict Moq mocks + EF InMemory or SQLite in-memory (`Helpers/ServiceTestFixture.cs`, `Helpers/TestDbContext.cs`); HTTP tests use `Http/AegisTestHost.cs` (TestServer on SQLite) |
| `samples/Aegis.Auth.Sample` | SQLite sample app with EF migrations |
| `benchmarks/Aegis.Auth.Benchmarks` | BenchmarkDotNet suite (crypto, session validation, sign-in, EF vs Dapper hot queries on SQLite and PostgreSQL). Built by CI, never run by it; see the README's "Benchmarks" section |

## Commands (mirror CI)

```bash
dotnet format --verify-no-changes
dotnet build -c Release -warnaserror
dotnet test -c Release --no-build
```

The SDK version is pinned in `global.json`. Sample migrations:
`dotnet ef migrations add <Name> --project samples/Aegis.Auth.Sample`.

## Conventions

- **Services** are `internal sealed` classes behind a public interface and return `Result` / `Result<T>` with a code from `AuthErrors`. Expected failures are results, not exceptions.
- **Endpoints** are `internal static Map…(this RouteGroupBuilder group)` methods, registered in `MapAegisAuthEndpoints`, gated by `AegisAuthEndpointMapOptions` (and `RespectConfiguration`). Failures go through `AegisHttpResultMapper` (core and plugin endpoints use `AegisResults.Problem`), so the client always gets ProblemDetails with the error code. Give new core error codes an HTTP status in `AegisPluginRegistry.CoreErrorStatusCodes`; plugins declare theirs in `ErrorStatusCodes`.
- **Options** are plain classes in `Options/`. New features are **off by default**. Invalid combinations fail at startup with a clear message (see the `Validate…` methods in `ServiceCollectionExtensions`).
- **Logging** uses source-generated `[LoggerMessage]` methods in `Logging/LogMessages.cs`, one EventId range per feature: 1000 sign-in, 2000 sign-up, 3000 sessions, 4000 sign-out, 5000 password reset, 6000 email verification, 7000 OAuth, 8000 rate limiting, 9000 secondary storage, 10000 organizations. New features take the next free thousand.
- **Style** follows `.editorconfig`; `dotnet format` enforces it. Match the surrounding code.

## Security rules (non-negotiable)

1. Only SHA-256 hashes of tokens are stored (`AegisCrypto.HashToken`). Raw tokens go to delivery delegates or signed cookies, **never** to HTTP response bodies or logs.
2. Endpoints that take an identifier (email, username, phone) respond identically whether or not the account exists.
3. Single-use tokens and codes are consumed **atomically** (conditional update), never read-check-write. See [#121](https://github.com/DanielvG-IT/Aegis.Auth/issues/121). Every single-use flow (password reset, email verification, and future magic links, email OTPs, invitations, device codes, one-time tokens) redeems through `IAuthTokenStore.TryConsumeAsync` (`Infrastructure/Tokens/AuthTokenStore.cs`), which runs the dependent writes in the same transaction. Counters such as `FailedSignInCount` are incremented with `ExecuteUpdateAsync`, not read-increment-write.
4. Redirect and callback URLs go through `CallbackValidator` (`TrustedOrigins`).
5. Third-party secrets at rest are encrypted with `ITokenEncryptionService`.
6. Never hand-roll protocol or crypto validation (XML signatures, JWT validation, WebAuthn). Use vetted libraries.
7. Every security-relevant branch has a negative test: tampered, expired, replayed, wrong user, cross-tenant.

## Tests

- Every new endpoint gets an HTTP test through `AegisTestHost.StartAsync(configure, configureEndpoints, configureServices)`, not only a service test.
- EF InMemory has no transactions, constraints or `ExecuteUpdate`. Use SQLite in-memory for tests that depend on them: `new ServiceTestFixture(useSqlite: true)` for service tests (`AegisTestHost` always uses SQLite). Race tests use `Helpers/SqliteFileDatabase.cs`, which gives each parallel request its own connection.
- Schema changes update `ApplyAegisAuthModel` (or the plugin's model), set `HasMaxLength` on indexed strings, and add a sample migration.

## Working on a roadmap issue

- Check the issue's dependencies are merged first. Stay inside its **Scope**; file follow-ups for anything else.
- If the issue says **Decision needed**, record the decision and the alternatives in the PR description (or the ADR the issue asks for).
- One issue per PR, with `Closes #N` in the description.
- Update the README's "Implemented" list when a feature ships.

### Definition of done

- [ ] Acceptance criteria in the issue are met and ticked
- [ ] Format, `-warnaserror` build and tests pass locally
- [ ] HTTP tests cover the happy path and the security-negative cases
- [ ] New options are documented in the README; breaking changes are called out in the PR

## Writing a plugin

New features ship as plugins: a public class deriving from `AegisPlugin` (`src/Aegis.Auth/Plugins/AegisPlugin.cs`).
The reference implementation is `Features/EmailVerification/EmailVerificationPlugin.cs`.

```csharp
public sealed class OrganizationPlugin(OrganizationOptions options) : AegisPlugin
{
    public override string Id => "organization";                        // kebab-case, unique

    public override void ConfigureServices(IServiceCollection services) =>
        services.AddScoped<IOrganizationService, OrganizationService>(); // internal sealed service

    public override void ConfigureModel(ModelBuilder modelBuilder) =>
        modelBuilder.Entity<Organization>(e => { e.HasKey(o => o.Id); e.Property(o => o.Slug).HasMaxLength(64); e.HasIndex(o => o.Slug).IsUnique(); });

    public override void MapEndpoints(RouteGroupBuilder group) =>
        group.MapPost("/organization/create", CreateAsync);              // relative to the Aegis base path

    public override bool ShouldMapEndpoints(AegisAuthOptions options) => true; // e.g. "is a delegate configured?"

    public override IEnumerable<AegisRateLimitRule> RateLimitRules => [new("/organization/create") { MaxRequests = 5 }];

    public override IReadOnlyDictionary<string, int> ErrorStatusCodes { get; } = new Dictionary<string, int>
    {
        ["ORGANIZATION_SLUG_TAKEN"] = StatusCodes.Status409Conflict,
    };

    public override void Validate(AegisAuthOptions options, IList<string> errors)
    {
        if (options.EmailAndPassword.Enabled is false) errors.Add("OrganizationOptions: ... must ...");
    }
}

public static class OrganizationAegisAuthBuilderExtensions
{
    public static IAegisAuthBuilder AddOrganizations(this IAegisAuthBuilder builder, Action<OrganizationOptions>? configure = null)
    {
        var options = new OrganizationOptions();
        configure?.Invoke(options);
        return builder.AddPlugin(new OrganizationPlugin(options));
    }
}
```

What each member is for, and the rules:

- **`Id`**: kebab-case and unique. A duplicate or malformed id throws when the plugin is added.
- **`Dependencies`**: ids of plugins this one builds on (SSO, SCIM, teams and invitations list `"organization"`). Startup fails when one is missing; registration order doesn't matter.
- **`ConfigureServices`**: runs once, when the plugin is added. Services stay `internal sealed` behind a public interface and return `Result`/`Result<T>`.
- **`ConfigureModel`**: runs after the core model and before the app's `OnModelCreating`, for contexts that call `UseAegisAuth(sp)`. EF caches the model per context type and plugin set, so the model must depend only on the plugin itself. Set `HasMaxLength` on indexed strings and add a sample migration. Startup fails when a plugin overrides it but the context lacks `UseAegisAuth`. Endpoints reach plugin tables, shadow properties and transactions through `authDbContext.GetDbContext()` (`Set<TEntity>()`, `Entry(…).Property("…")`, `Database`); `IAuthDbContext` only exposes the core sets. Columns a plugin adds to core entities are shadow properties (e.g. `modelBuilder.Entity<Session>().Property<string?>("ActiveOrganizationId")`).
- **`MapEndpoints`**: called by `MapAegisAuthEndpoints` after the core endpoints, in registration order, each plugin in its own sub-group. A route that collides with a core route or an earlier plugin's route (same path and method; parameter names ignored) fails at startup. Return failures with `AegisResults.Problem(httpContext, code, message)`.
- **`ShouldMapEndpoints`**: skip mapping when the feature isn't configured. Ignored when `RespectConfiguration` is off.
- **`RateLimitRules`**: collected in `AegisPluginRegistry.RateLimitRules`; enforcement is separate ([#120](https://github.com/DanielvG-IT/Aegis.Auth/issues/120)). Until then, also call `RequireAegisRateLimit` on the endpoint.
- **`ErrorStatusCodes`**: merged with the core map; statuses must be 400–599, and remapping an existing code to a different status throws. Unmapped codes return 400. Add the constants next to the plugin, or to `AuthErrors` for shared codes.
- **`Validate`**: add one message per invalid setting. It runs with the core validation (`ValidateOnStart`), so the app fails to start with every message at once. New features stay **off by default**.

Signed-in endpoints: put `RequireAegisAuth()` (from `Aegis.Auth.Http`) on the plugin's group and read the caller with `httpContext.GetAegisAuthContext()`, which carries `UserId` and `SessionId`. The context can come from the signed cookie cache, so re-check anything that can be revoked (membership, roles) against the database on every request, and never trust an id from the request body without that check.

Plugins must build against the **public** API only: shipped plugin packages get no `InternalsVisibleTo`. `tests/Aegis.Auth.TestPlugins` enforces this. It holds `WorkspacesPlugin`, a cut-down organizations plugin (own tables, cascade from `User`, a shadow column on `Session`, signed-in endpoints with membership checks, options, a dependent plugin), with HTTP tests in `tests/Aegis.Auth.Tests/Http/WorkspacesPluginTests.cs`. Start a new plugin from it.

Tests: register the plugin with `AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(...))`. The host already calls `UseAegisAuth`. `tests/Aegis.Auth.Tests/Http/PluginContractTests.cs` shows each contract member tested through HTTP.
Logging: take the next free EventId thousand (see **Conventions**).
