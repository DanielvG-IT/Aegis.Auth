# ADR 0002: OpenIddict as the OAuth 2.1 / OpenID Connect provider engine

- **Status:** Accepted
- **Date:** 2026-09-30
- **Issue:** [#116](https://github.com/danielvanginneken/Aegis.Auth/issues/116) (spike), feeding [#117](https://github.com/danielvanginneken/Aegis.Auth/issues/117) (OIDC provider), [#118](https://github.com/danielvanginneken/Aegis.Auth/issues/118) (MCP), [#119](https://github.com/danielvanginneken/Aegis.Auth/issues/119) (CIMD)
- **Proof of concept:** [`tests/Aegis.Auth.Tests/Http/OidcProvider/`](../../tests/Aegis.Auth.Tests/Http/OidcProvider/)

## Context

Making Aegis an authorization server means implementing a large set of specifications:
authorization code + PKCE, refresh token rotation, client credentials, discovery (OIDC and RFC 8414),
JWKS, userinfo, introspection (RFC 7662), revocation (RFC 7009), end-session, resource indicators
(RFC 8707, which MCP depends on) and, for MCP, client registration (CIMD, and DCR as a legacy path).

Aegis already owns the parts an authorization server engine usually leaves to its host:
users, sign-in, sessions, and (soon) consent. What it lacks is the protocol engine. `AGENTS.md`
security rule 6 says never to hand-roll protocol or crypto validation.

All findings below were verified against the OpenIddict source at tag
[`7.7.1`](https://github.com/openiddict/openiddict-core/tree/7.7.1), the `dev` branch at
`b48729e` (2026-09-29), the [documentation repository](https://github.com/openiddict/openiddict-documentation),
the NuGet feed, and the MCP specification revision `2026-07-28`. Where a finding matters to a
downstream issue, the PoC pins it with a test.

## Options

### A. OpenIddict (Apache-2.0)

The established open-source .NET engine. It deliberately leaves the user store, login and consent
to the host, and exposes every endpoint in *passthrough* mode, so the host decides who is signed in.

### B. Hand-rolled on ASP.NET Core primitives

Implement the endpoints ourselves on minimal APIs, `Microsoft.IdentityModel` for JWT/JWKS and our
existing crypto helpers.

- **For:** no dependency, no imposed schema, full control over every response.
- **Against:**
  - The spec surface above is roughly the size of Aegis today. Each endpoint has subtle,
    security-critical validation rules: redirect URI matching, PKCE downgrade, code and refresh
    replay, `iss` mix-up defences, client assertion audiences (OpenIddict shipped a fix for exactly
    that in 7.7.0), `typ`-based token confusion, and so on.
  - It directly contradicts `AGENTS.md` rule 6. Every one of those rules would be ours to get
    right, test and keep current as OAuth 2.1 and the MCP profile keep moving (the MCP
    authorization spec has changed in almost every revision).
  - No interoperability track record; the OpenID conformance suite would find the gaps for us, late.
  - Estimated at several XL issues before reaching parity with what option A gives on day one,
    plus a permanent maintenance and security-response burden.

### C. Duende IdentityServer

Excluded: commercial licence, incompatible with Aegis being freely redistributable.

## Findings

### 1. Supported .NET versions and version pin

- Latest stable: **OpenIddict 7.7.1** (released 2026-09-17). `Directory.Build.props` at `7.7.1`
  targets `net8.0; net9.0; net10.0`, and the ASP.NET Core integration docs list ASP.NET Core 10.0
  as supported. Aegis targets `net10.0`, so no friction.
- Transitive dependencies resolve cleanly with ours: `Microsoft.EntityFrameworkCore.Relational`
  10.0.12, `Microsoft.IdentityModel.*` 8.19.2, with no downgrade warnings.
- **7.7.0 fixed a security issue in client assertion audience validation**, so the floor is 7.7.0.
- **8.0 is in preview** (`8.0.0-preview.4`, 2026-09-06). It brings things we want: native DCR
  (upstream issue [openiddict-core#2404](https://github.com/openiddict/openiddict-core/issues/2404),
  milestone `8.0.0-preview.5`), a database-backed resource store (`IOpenIddictResourceManager`,
  preview.3), session binding for tokens, and modernised EF Core stores. It also brings **schema
  changes** (a new resource entity; EF Core stores that use JSON operators) and drops the Quartz
  integration in favour of a built-in pruning `BackgroundService` (dev branch, 2026-09-29).

**Decision:** pin `7.7.1` exactly (no floating ranges), in the `Aegis.Auth.OidcProvider` package
only. Re-evaluate when 8.0 is GA; plan the upgrade as its own issue, since it needs a migration.

### 2. EF Core integration in the consumer's DbContext

Works, with one caveat for #95.

- `modelBuilder.UseOpenIddict()` in `OnModelCreating` adds four tables: `OpenIddictApplications`,
  `OpenIddictAuthorizations`, `OpenIddictScopes`, `OpenIddictTokens`. None collide with the Aegis
  tables (`Users`, `Accounts`, `Sessions`, `AuthTokens`). The PoC puts both models in one context
  on SQLite and asserts there are no table-name collisions
  (`SharedDbContext_HoldsAegisAndOpenIddictTables_WithoutCollisions`).
- `options.UseEntityFrameworkCore().UseDbContext<TContext>()` takes the consumer's context type,
  which the plugin already knows from `AddAegisAuth<TContext>()`.
- Key type defaults to `string`, matching Aegis; `UseOpenIddict<TKey>()` or custom entity types are
  available if we need extra columns (see CIMD below).
- **Caveat:** use the `ModelBuilder` overload. The documented
  `DbContextOptionsBuilder.UseOpenIddict()` calls `ReplaceService<IModelCustomizer, …>()`, which
  conflicts with #95's recommended option (b) (Aegis replacing `IModelCustomizer` itself). The
  plugin's `ConfigureModel(ModelBuilder)` should call `modelBuilder.UseOpenIddict()`.
- The stores rely on relational features (optimistic concurrency, bulk updates and deletes,
  transactions). Tests that exercise them need SQLite, not EF InMemory, which `AGENTS.md` already
  requires for such tests.

### 3. Passthrough mode

Supported for every endpoint that needs host logic:
`EnableAuthorizationEndpointPassthrough`, `EnableTokenEndpointPassthrough`,
`EnableUserInfoEndpointPassthrough`, `EnableEndSessionEndpointPassthrough`,
`EnableEndUserVerificationEndpointPassthrough` (device flow), plus `EnableErrorPassthrough`.

OpenIddict validates the request **before** the host endpoint runs: client, redirect URI, PKCE,
scopes, resources and permissions. The host only decides who the user is and which claims to issue.
The PoC's authorize endpoint (`OidcSpikeEnvironment.MapPassthroughEndpoints`) is about 30 lines:

1. `AuthenticateAsync(AegisDefaults.AuthenticationScheme)`. No Aegis session → redirect to the
   app's login page with `returnUrl`. Revoked and tampered session cookies go back to login too
   (`RevokedAegisSession_…`, `TamperedAegisSessionCookie_…`).
2. Load the user from `IAuthDbContext`, build a `ClaimsIdentity` (`sub` = Aegis user id),
   `SetScopes`, `SetResources`, `SetDestinations`.
3. `Results.SignIn(principal, scheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)`.

The userinfo endpoint reads claims from the Aegis user store at call time.

Without token endpoint passthrough, OpenIddict answers code and refresh grants itself by replaying
the principal captured at authorize time (`AttachPrincipal`). That means **a refresh never consults
Aegis**; see the gap list.

### 4. Resource indicators (RFC 8707) and audience binding

Supported, with two gaps.

- The `resource` parameter is validated on authorization, pushed authorization and token requests:
  - must be an absolute URI without a fragment (`invalid_request`);
  - must be registered with `RegisterResources` (`invalid_target`), unless `DisableResourceValidation()`;
  - must be in the client's `rsrc:` permissions (`invalid_request`), unless `IgnoreResourcePermissions()`.

  These checks run before passthrough. The PoC shows they reject even without a session
  (`InvalidResource_IsRejected_BeforeThePassthroughEndpointRuns`).
- Token `aud` comes from the **principal's resources**, which the host sets:
  `identity.SetResources(request.GetResources())` (`OpenIddictServerHandlers.cs`,
  `principal.SetAudiences(context.Principal.GetResources())`). Refreshed tokens keep the audience.
  The PoC asserts that `aud` equals the requested resource, and that the RP's access token is bound
  to the resource it asked for (`AccessToken_IsAudienceBound_ToTheRequestedResource`).
- **Gap: canonical URIs.** Requested resources are compared ordinally against `Uri.AbsoluteUri`,
  which appends `/` to an empty path, while permissions are stored as written. A bare-origin
  resource registered the way MCP recommends (`https://mcp.example.com`, no trailing slash)
  cannot be requested in either form (`BareOriginResource_IsRejected_WithOrWithoutTrailingSlash`).
- **Gap: token-request downscoping.** On a code or refresh grant, OpenIddict validates the token
  request's `resource`, but issues the token for the resources captured at authorize time. It
  neither narrows `aud` to the requested one nor rejects a resource outside the grant, as RFC 8707
  §2.2 describes (`TokenRequestResource_NeitherNarrowsNorRejects_TheGrantedAudience`). This isn't
  an escalation, because `aud` never widens. But MCP clients send `resource` on both requests, so
  Aegis should enforce "subset of the grant, else `invalid_target`".

### 5. Dynamic client registration (RFC 7591)

**Not built in** to 7.7.1, and not on the `dev` branch yet. Upstream tracks it in
[openiddict-core#2404](https://github.com/openiddict/openiddict-core/issues/2404) (open, milestone
`8.0.0-preview.5`).

The MCP `2026-07-28` revision now marks DCR **deprecated** in favour of CIMD, kept only for
backwards compatibility.

**Recommendation:** don't build DCR on 7.x. #118 keeps `AllowDynamicClientRegistration`
(default `false`) and implements it once 8.0 ships native support. If it's needed sooner, a thin
`POST /oauth2/register` that maps RFC 7591 metadata onto `IOpenIddictApplicationManager.CreateAsync`
is small, but it needs its own metadata validation (redirect URIs, grant types, auth method) and
rate limiting. RFC 7592 (management) stays out of scope.

### 6. Hooks for CIMD

No native support; the hooks are sufficient.

- Every server handler resolves clients through `IOpenIddictApplicationManager.FindByClientIdAsync`:
  client validation, redirect URI checks, permissions, requirements, and token/PAR/end-session
  requests. That's a single choke point. `OpenIddictCoreBuilder.ReplaceApplicationManager(…)`
  (subclass `OpenIddictApplicationManager<T>`, whose `FindByClientIdAsync` is `virtual`) or
  `ReplaceApplicationStore(…)` lets Aegis resolve an unknown HTTPS-URL `client_id` on the fly.
  It fetches and validates the document (#119's SSRF-safe fetcher), then creates or refreshes the
  application and returns it.
- The client **must be persisted**, not synthesised in memory: authorizations and tokens have
  foreign keys to `OpenIddictApplications`.
- **Gap:** `ClientId` is `HasMaxLength(100)` in OpenIddict's EF configuration. CIMD client IDs are
  URLs and routinely longer. #119 needs a widened column: a custom application entity or a model
  override after `UseOpenIddict()`, sized to stay within index-key limits.
- Provenance (`cimd` vs managed vs DCR) fits in the application's `Properties` bag or a custom
  column. The override must only fetch when the store has **no** record, so a managed client with
  the same ID can never be taken over.
- The manager's entity cache (`IOpenIddictApplicationCache`) absorbs the repeated lookups within
  one request. HTTP-cache-driven refresh stays in #119's own cache.
- Discovery metadata is extensible: a `HandleConfigurationRequestContext` event handler adds
  `client_id_metadata_document_supported`. OpenIddict serves both `/.well-known/openid-configuration`
  and `/.well-known/oauth-authorization-server` (RFC 8414), with `code_challenge_methods_supported`
  (`Discovery_ServesPkceAndCustomMetadata_AtBothWellKnownPaths`).

### 7. Device authorization grant (RFC 8628)

Fully supported:

- `AllowDeviceAuthorizationFlow()`, `SetDeviceAuthorizationEndpointUris`,
  `SetEndUserVerificationEndpointUris` with passthrough for the approval page;
- configurable user code charset and length (`SetUserCodeCharset`, `SetUserCodeLength`);
- device and user codes stored as token entries, with polling (`authorization_pending`,
  `slow_down`) built in;
- 7.7.0 rejects device-code grants without a client identifier.

**Recommendation:** #115 stays standalone as scoped. It issues Aegis bearer sessions and must work
without the provider package. Once the provider exists, the device flow should be served by
OpenIddict whenever the provider is enabled, so an app never runs two RFC 8628 state machines. #115
should keep its endpoint paths and options shape compatible with that handover. OpenIddict does
not rate-limit user-code entry; Aegis's rate limiter has to cover the verification endpoint either way.

### 8. Token formats and key management

- **Formats:** JWT by default for every token.
  - Access tokens are `typ: at+jwt` (RFC 9068).
  - Authorization codes, refresh tokens and device codes are always encrypted (JWE).
  - Access tokens are encrypted by default too. `DisableAccessTokenEncryption()` is required for
    third-party resource servers and MCP servers to validate them via JWKS; the PoC does this.
  - Reference (opaque) access and refresh tokens are opt-in (`UseReferenceAccessTokens` /
    `UseReferenceRefreshTokens`) and need introspection.
  - ASP.NET Core Data Protection is an optional alternative format.
  - Revocation works for all formats while token storage is enabled.
- **Storage vs `AGENTS.md` rule 1:** the value a client holds for a code or reference token is
  looked up by a SHA-256 hash (`ObfuscateReferenceIdAsync`). The stored *payload* is the encrypted
  JWE, and self-contained JWT access and refresh tokens persist metadata only. That's weaker than
  "hashes only" (a leaked database plus the encryption key yields live codes within their short
  lifetime), and we accept it. Client secrets are hashed (PBKDF2).
- **Replay (rule 3):** redemption uses an optimistic-concurrency conditional update
  (`TryRedeemAsync`, `ConcurrencyToken`). Code reuse revokes the tokens already issued from that
  code (`AuthorizationCode_Replay_…`). Refresh-token reuse outside the leeway (default 30 s;
  `SetRefreshTokenReuseLeeway`) revokes the whole token family (`RefreshToken_Reuse_…`), which
  meets #117's "revoke the family on reuse".
- **Keys:** OpenIddict signs and encrypts with whatever keys the host registers. It does **not**
  generate, persist or rotate production keys.
  - Development: ephemeral keys, or development certificates in the user certificate store (these
    fail on IIS and Azure App Service).
  - Production (per the docs): two RSA X.509 certificates, one for signing and one for
    encryption, distinct from the TLS certificate.
  - Rotation: register several certificates. The one with the furthest `NotAfter` signs, and
    not-yet-valid certificates are skipped.
  - If a symmetric signing key is registered, it is preferred for everything except identity
    tokens, which would make access tokens unverifiable via JWKS.

## Decision

Adopt **OpenIddict 7.7.1** (server, core, EF Core, ASP.NET Core integration) as the engine behind
`Aegis.Auth.OidcProvider`, with:

- authorize, userinfo and end-session in **passthrough** mode, backed by Aegis sessions and the Aegis user store;
- token endpoint passthrough (or an equivalent event handler) so refreshes re-check the user;
- OpenIddict's entities in the consumer's `DbContext` via the plugin's `ConfigureModel`;
- JWT access tokens, unencrypted, audience-bound through resource indicators;
- OpenIddict types kept out of the Aegis core public API, so the 8.0 upgrade (and a future engine
  swap) stays inside one package.

## Consequences

**Positive**

- #117 becomes mostly glue: configuration, the passthrough endpoints, consent, client management.
- Hardened, widely deployed validation for every protocol path; refresh reuse detection and code
  replay revocation come for free.
- A clear path to DCR and dynamic resources in 8.0.

**Negative / risks**

- The consumer's schema gains four tables owned by a third party, and 8.0 will change them: every
  OpenIddict major is a migration for our users.
- Single-maintainer project: bus-factor risk. Mitigation: Apache-2.0, the package boundary above,
  and Dependabot on the pin.
- HTTPS is enforced at the endpoints. That's correct, but proxies must forward the scheme;
  `DisableTransportSecurityRequirement()` must never be exposed as an Aegis option.
- Gaps we own on top of the engine (below).

## Gap list

**#117: OIDC provider**

1. Token endpoint passthrough (or a `HandleTokenRequestContext` handler) that re-checks the Aegis
   user (exists, not banned or locked) on refresh. Otherwise a refresh token outlives user deletion.
2. The authorize passthrough must ignore Aegis's session **cookie cache**
   (`AegisAuthContext.IsFromCookieCache`). With `Session.CookieCache` enabled, a revoked session
   could otherwise still mint codes until the cache expires.
3. Aegis's authentication handler only emits `NameIdentifier`. The provider loads the user for
   claims; a scope → claims mapping (`ClaimsFor`) plus destinations are ours to build.
4. Consent (the `OAuthConsent` table, or OpenIddict *permanent authorizations*, which already
   model per-user, per-client, per-scope grants and are worth evaluating before adding a table).
5. Signing and encryption key options: X.509 certificates in production. Startup validation must
   fail when the provider is enabled outside Development without persistent keys, and must reject
   symmetric signing keys when JWT access tokens are validated via JWKS.
6. End-session passthrough that signs out the Aegis session and validates
   `post_logout_redirect_uri` (OpenIddict validates it against the client; Aegis `TrustedOrigins`
   still applies to anything else).
7. Token pruning (Quartz in 7.x, a built-in `BackgroundService` in 8.0): decide who schedules it.
8. `EnableAuthorizationRequestCaching` or PAR for large requests; `RequirePushedAuthorizationRequests` as an option.
9. Map OpenIddict error responses into Aegis's ProblemDetails conventions where the endpoint is ours
   (userinfo, consent), and leave protocol errors in OAuth format.

**#118: MCP**

1. **Canonicalise resource URIs** before `RegisterResources`, `AddResourcePermissions` and the
   request comparison (trailing slash on bare origins, host case). Pinned by
   `BareOriginResource_IsRejected_WithOrWithoutTrailingSlash`.
2. **Token-request `resource` enforcement:** subset of the granted resources, narrowed `aud`,
   `invalid_target` otherwise. Pinned by `TokenRequestResource_NeitherNarrowsNorRejects_TheGrantedAudience`.
3. `DisableAccessTokenEncryption()` is mandatory for MCP resource servers; the resource-server
   helper validates `typ: at+jwt`, `iss`, `aud` = resource, expiry and scopes. OpenIddict.Validation
   checks the token type natively; `JwtBearer` only does so when `TokenValidationParameters.ValidTypes`
   is set to `at+jwt`.
4. RFC 8414 metadata is already served at `/.well-known/oauth-authorization-server`; the RFC 9728
   Protected Resource Metadata endpoint belongs to the resource-server helper.
5. DCR: deferred to OpenIddict 8.0 native support (openiddict-core#2404); deprecated in MCP `2026-07-28` anyway.
6. Resources are static (`RegisterResources`) in 7.x; the dynamic resource store arrives in 8.0.
   Until then, the plugin registers resources from options at startup.

**#119: CIMD**

1. `ReplaceApplicationManager` subclass overriding `FindByClientIdAsync` as the single resolution point (fetch only on a miss).
2. Widen `OpenIddictApplications.ClientId` beyond 100 characters (custom entity or model override), with an index-safe length.
3. Store provenance in application `Properties` (or a custom column) and never refresh non-CIMD records from a URL.
4. Advertise `client_id_metadata_document_supported` through a `HandleConfigurationRequestContext` handler (demonstrated in the PoC).
5. Force `ClientType = public` or `private_key_jwt` (JWKS) for CIMD clients. OpenIddict supports
   `private_key_jwt` client assertions, including the 7.7.0 audience fix.

**Other**

- #95: the plugin's `ConfigureModel` must use `modelBuilder.UseOpenIddict()`, not the `DbContextOptionsBuilder` overload.
- #115: keep the device-flow surface compatible with a later OpenIddict-backed implementation.
- A follow-up issue to upgrade to OpenIddict 8.0 once GA (schema migration, DCR, resource store, session binding).
