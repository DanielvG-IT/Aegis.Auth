# AGENTS.md

Guide for coding agents (and humans) working on Aegis.Auth. Read this before picking up an issue.
The roadmap lives in [#86](https://github.com/DanielvG-IT/Aegis.Auth/issues/86); every roadmap issue links to its epic and dependencies.

## Repository map

| Path | What lives there |
|---|---|
| `src/Aegis.Auth` | Core: entities (`Entities/`), options (`Options/`), one folder per feature with its service (`Features/<Feature>/`), EF model (`Extensions/ModelBuilderExtensions.cs`), DI + startup validation (`Extensions/ServiceCollectionExtensions.cs`), crypto (`Core/Crypto/`), error codes (`Constants/ErrorCodes.cs`), log messages (`Logging/LogMessages.cs`) |
| `src/Aegis.Auth.Http` | Minimal-API endpoints (`Features/<Feature>/*Endpoints.cs`), endpoint mapping (`Extensions/AegisAuthEndpointRouteBuilderExtensions.cs`), error → ProblemDetails mapping (`Internal/AegisHttpResultMapper.cs`) |
| `tests/Aegis.Auth.Tests` | xUnit. Service tests use strict Moq mocks + EF InMemory (`Helpers/TestDbContext.cs`); HTTP tests use `Http/AegisTestHost.cs` (TestServer) |
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
- **Endpoints** are `internal static Map…(this RouteGroupBuilder group)` methods, registered in `MapAegisAuthEndpoints`, gated by `AegisAuthEndpointMapOptions` (and `RespectConfiguration`). Failures go through `AegisHttpResultMapper`, so the client always gets ProblemDetails with the error code. Give new error codes an HTTP status there.
- **Options** are plain classes in `Options/`. New features are **off by default**. Invalid combinations fail at startup with a clear message (see the `Validate…` methods in `ServiceCollectionExtensions`).
- **Logging** uses source-generated `[LoggerMessage]` methods in `Logging/LogMessages.cs`, one EventId range per feature: 1000 sign-in, 2000 sign-up, 3000 sessions, 4000 sign-out, 5000 password reset, 6000 email verification, 7000 OAuth, 8000 rate limiting. New features take the next free thousand.
- **Style** follows `.editorconfig`; `dotnet format` enforces it. Match the surrounding code.

## Security rules (non-negotiable)

1. Only SHA-256 hashes of tokens are stored (`AegisCrypto.HashToken`). Raw tokens go to delivery delegates or signed cookies, **never** to HTTP response bodies or logs.
2. Endpoints that take an identifier (email, username, phone) respond identically whether or not the account exists.
3. Single-use tokens and codes are consumed **atomically** (conditional update), never read-check-write. See [#121](https://github.com/DanielvG-IT/Aegis.Auth/issues/121).
4. Redirect and callback URLs go through `CallbackValidator` (`TrustedOrigins`).
5. Third-party secrets at rest are encrypted with `ITokenEncryptionService`.
6. Never hand-roll protocol or crypto validation (XML signatures, JWT validation, WebAuthn). Use vetted libraries.
7. Every security-relevant branch has a negative test: tampered, expired, replayed, wrong user, cross-tenant.

## Tests

- Every new endpoint gets an HTTP test through `AegisTestHost.StartAsync(configure, configureEndpoints, configureServices)`, not only a service test.
- EF InMemory has no transactions, constraints or `ExecuteUpdate`. Use SQLite in-memory for tests that depend on them.
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

The plugin contract is being designed in [#95](https://github.com/DanielvG-IT/Aegis.Auth/issues/95). That issue fills in this section when it lands.
