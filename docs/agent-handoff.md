# Agent handoff: open work on Aegis.Auth

For the next coding agent. Read `AGENTS.md` first; this file adds the branch rules, the current state of `canary`, and a work queue.
Last updated 2026-09-30, at `canary` 2978e3a.

## Rule 1: everything goes to `canary`

- `canary` is the integration branch. `main` is far behind (180fbfd) and is **not** a base for anything.
- Start every branch from the latest `canary`:
  `git fetch origin canary && git checkout -B <your-branch> origin/canary`
- Open every PR with **base `canary`**, one issue per PR.
- Before merging, check the PR against the **current** `canary`, not the one you branched from. Other sessions merge in parallel.
  1. Merge `origin/canary` into your branch as a merge commit. Don't rebase or force-push someone else's branch.
  2. Run the three CI commands below.
  3. Push, then merge.
- The last round of merges broke because of this: #162, #163 and #166 each compiled against an older `canary`. When `IAuthDbContext` or `AegisAuthContext` gains a required member, every `DbContext` or context in the repo must be updated in the same PR: `TestDbContext`, `OidcSpikeDbContext`, `BenchDbContext`, the sample's DbContext, and `AegisAuthContext` initializers.
- A PR into `canary` does **not** auto-close its issue, because `canary` isn't the default branch. After merging, close the issue by hand, with a comment that links the PR.

## Commands (same as CI)

```bash
dotnet format --verify-no-changes
dotnet build -c Release -warnaserror
dotnet test -c Release --no-build
```

The 3 skipped tests at the time of writing are expected: 2 parallel tests for the `IDistributedCache` storage, which can't be atomic, and the Keycloak SAML test, which needs Docker.

## Environment notes (cloud sessions)

- The .NET SDK installer may be blocked by the proxy. Ubuntu's `apt install dotnet-sdk-10.0` works.
- `dotnet-ef`: `dotnet tool install --global dotnet-ef --version "10.0.*"`, then add `~/.dotnet/tools` to `PATH`. Sample migrations: `dotnet ef migrations add <Name> --project samples/Aegis.Auth.Sample`.
- There is no Docker daemon, so Testcontainers tests (Keycloak, PostgreSQL benchmarks) skip or can't run. Say so in the PR instead of claiming they pass.
- `gh` isn't installed; use the GitHub MCP tools.

## Done on `canary`, but the issue is still open

Verify, tick the acceptance criteria, and close each of these (or leave the follow-up noted):

| Issue | Merged in | Follow-up before closing |
|---|---|---|
| #95 plugin contract | #164 | None; close |
| #98 secondary storage | #159 | Redis package (`Aegis.Auth.Redis`, Testcontainers; needs Docker); moving rate limiting and session caching onto it is tracked in #120 and #141. Decide: close with follow-up issues, or keep open |
| #100 organizations core | #165 | Needs #97 (`RequireAegisPermission` resolver instead of `RequireOrganizationPermission`) and #55 (emit `OrganizationCreated`, `MemberAdded`, `MemberRemoved`, `MemberRoleChanged`). Keep open until those land, or split them into follow-up issues |
| #106 SAML library spike | #163 | None; close. Its PR body holds the validation checklist for #107 |
| #116 OpenIddict spike | #162 | None; close. `docs/adr/0002-oidc-provider-engine.md` holds the gap list for #117, #118 and #119 |
| #67 benchmarks | #166 | Check its acceptance criteria (the CI benchmark comment job may still be missing) |

## Known follow-ups from the last session

1. **Organizations without the last-owner race window on non-SQLite.** `OrganizationService` checks "an owner remains" inside a `Serializable` transaction. That's correct on SQLite, PostgreSQL and SQL Server, but add a race test (`Helpers/SqliteFileDatabase.cs`) where two owners demote each other in parallel.
2. **Organizations need `ConfigureModel` + OpenIddict together.** ADR 0002 says OpenIddict's `DbContextOptionsBuilder.UseOpenIddict()` replaces `IModelCustomizer`, which `UseAegisAuth` also wraps. The OIDC provider plugin (#117) must call `modelBuilder.UseOpenIddict()` from `ConfigureModel` instead.
3. **SAML decryption allow-list.** ITfoxtec accepts RSA-1.5/3DES encrypted assertions. #107 must reject them before decrypting (see #163's PR body).
4. **Refresh-token re-check.** OpenIddict's token endpoint replays the principal from sign-in time. #117 must re-check the Aegis user and session on refresh, and must not trust the session cookie cache (`IsFromCookieCache`) when issuing codes.

## Work queue (in dependency order)

Always read the issue itself: each lists its dependencies, scope and acceptance criteria. Check its dependencies are closed or merged on `canary` first.

### 1. Foundations: unblock everything else
- **#120** fix(security): rate limiting is registered but never enforced. A bug, and plugin rules already exist in `AegisPluginRegistry.RateLimitRules`.
- **#97** access control primitives. Unblocks #100's role resolver, #103, #114, #69.
- **#55** lifecycle hooks / events. Unblocks the organization events, audit log (#61) and billing.
- **#96** schema extensibility: extra User/Session columns, transactions. Organizations already uses shadow properties and `GetDbContext()`; formalize them here.
- **#57** advanced cookie configuration.

### 2. Accounts and sign-in methods (Epic #88)
- #125 self-service account management; #62 active sessions management
- #48 magic link, #49 email OTP. These are single-use: redeem through `IAuthTokenStore.TryConsumeAsync` (security rule 3).
- #47 TOTP MFA, #46 passkeys/WebAuthn. Use vetted libraries (security rule 6).
- #50 OAuth account linking, #51 OAuth token refresh, #53 more providers, #126 generic OAuth/OIDC providers
- #127 username sign-in, #128 phone + SMS OTP, #129 multi-session, #130 last login method, #131 one-time token

### 3. Security hardening (Epic #91)
- #122 constant-time responses, #123 CAPTCHA, #124 Have I Been Pwned check

### 4. Enterprise and B2B (Epic #89). Needs #100 (done), #97 and #55
- #101 invitations (single-use: `TryConsumeAsync`), #102 teams, #103 dynamic roles
- #104 SSO foundation → #105 enterprise OIDC SSO, #107 SAML SP (ITfoxtec, per ADR 0001) → #108 domain verification → #109 SSO enforcement
- #110 SCIM Users → #111 SCIM Groups
- #61 audit log storage

### 5. Machine and agent access (Epic #90)
- #112 bearer token auth → #113 JWT + JWKS → #114 API keys → #69 admin API
- #115 device authorization grant (keep it compatible with an OpenIddict-backed implementation, per ADR 0002)
- #117 OIDC provider (OpenIddict 7.7.1, per ADR 0002) → #118 MCP authorization → #119 CIMD

### 6. Data and performance (Epic #93)
- #45 EF Core package split (**breaking change**; call it out in the PR)
- #139 database provider matrix (Testcontainers; needs Docker), #140 persistence ADR, #141 hot-path performance (benchmarks from #166 exist to measure it)

### 7. Developer experience (Epics #94, #152)
- #142 OpenAPI → #153 client generation pipeline → #145 TypeScript client → #154 Axios, #155 React; #156 Python client; #157 .NET client
- #143 `Aegis.Auth.Testing` package, #144 i18n, #146 reference setups

### 8. Payments (Epic #92)
- #132 billing core + Stripe → #133 Polar (validates the abstraction) → #134–#138 other providers

## Definition of done (from AGENTS.md)

- The issue's acceptance criteria are met and ticked.
- Format, the `-warnaserror` build and tests pass locally, on top of the **current** `canary`.
- HTTP tests cover the happy path and the security-negative cases: tampered, expired, replayed, wrong user, cross-tenant.
- New options are documented in the README; breaking changes are called out in the PR; schema changes get a sample migration.
- New features ship as plugins where possible (see "Writing a plugin" in `AGENTS.md`), off by default.
