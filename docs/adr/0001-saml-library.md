# ADR 0001: SAML 2.0 library for the service provider

- **Status:** Accepted
- **Date:** 2026-09-30
- **Issue:** [#106](https://github.com/danielvanginneken/Aegis.Auth/issues/106) (spike) · blocks [#107](https://github.com/danielvanginneken/Aegis.Auth/issues/107) (SAML SP) · epic [#89](https://github.com/danielvanginneken/Aegis.Auth/issues/89)
- **Proof of concept:** `tests/Aegis.Auth.Tests/Spikes/SamlLibrary/`

## Context

Aegis.Auth will act as a SAML 2.0 service provider (SP) for per-organization SSO. SAML is built on XML signatures, and
its history is a list of validation bugs: XML signature wrapping (XSW), comment injection in `NameID`, XXE, algorithm
confusion, and accepting unsigned assertions. [AGENTS.md](../../AGENTS.md) rule 6 says we never hand-roll this, so we
need a vetted library.

The library has to fit how SSO works in Aegis.Auth:

- IdP connections are **data**, loaded per tenant at request time. There is no ASP.NET authentication scheme per IdP,
  and adding an IdP must not need a restart.
- Aegis.Auth is MIT-licensed and redistributed on NuGet, so the library must be permissively licensed with no
  commercial terms.
- It must support the current target (`net10.0`).

## Options

1. **ITfoxtec.Identity.Saml2**: a low-level library. You build the `AuthnRequest` and read the `Response` yourself
   using a `Saml2Configuration` object.
2. **Sustainsys.Saml2 v2** (`Sustainsys.Saml2` + `Sustainsys.Saml2.AspNetCore2`): a full ASP.NET authentication
   handler.
3. **Sustainsys.Saml2 v3**: the rewrite on the `main` branch.
4. Commercial libraries (e.g. ComponentSpace): ruled out by the issue because their licenses aren't MIT-compatible.
   Not evaluated further.

## Findings

Checked on 2026-09-30 against NuGet metadata, the libraries' source at their release tags, and the GitHub Advisory
Database. The claims in the issue's table were not taken on trust.

### ITfoxtec.Identity.Saml2 (evaluated at 4.21.0)

- **License:** BSD-3-Clause (NuGet `licenseExpression`, repo `LICENSE`). This is compatible with MIT redistribution,
  but the copyright notice must be kept.
- **.NET:** ships a `net10.0` build, plus net6–9, netstandard2.1, net462 and net48. The core package has no ASP.NET
  dependency. It uses its own `Http.HttpRequest` abstraction; `ITfoxtec.Identity.Saml2.MvcCore` is optional and we
  don't need it.
- **Maintenance:** releases 4.19.2 (2026-06-23), 4.20.0 (06-24), 4.20.1 (06-27) and 4.21.0 (09-15). 79 commits in the
  last 12 months. Recent security hardening: signature-algorithm and canonicalization allow-lists (4.19.2), and
  upgrades of `System.Security.Cryptography.Xml` for its advisories. No GHSA/CVE is published against the package.
  The risk is that it is maintained by a single vendor (ITfoxtec / FoxIDs).
- **Signature validation** (`Saml2Request.ValidateXmlSignature`, `Saml2SignedXml.CheckSignature`):
  - validates the Response signature and/or the Assertion signature;
  - any signature that is present must be valid, and at least one must be;
  - tries every configured certificate, so rotation works.
- **XSW defences:**
  - at most one `Signature` per element and exactly one `Reference`;
  - the reference must resolve to the element being validated (the root or the assertion);
  - transforms are allow-listed;
  - the document must contain exactly one top-level `Assertion`.
- **Encrypted assertions:**
  - `DecryptionCertificates` accepts several certificates, for rotation;
  - the Response signature is checked **before** decryption and the Assertion signature after it;
  - **gap:** there is no algorithm allow-list on decryption. An assertion encrypted with RSA-1.5 key transport and
    3DES content encryption is decrypted and accepted (verified in the spike with a scratch run). RSA-1.5 means
    Bleichenbacher-style oracle risk, so we must reject these algorithms ourselves before decrypting.
- **XML parsing:** `DtdProcessing.Prohibit` and `XmlResolver = null` everywhere.
- **Checks it does itself:**
  - Response `Issuer`, but only if present (`AllowedIssuer`);
  - `Status`;
  - `Audience`;
  - `Conditions/@NotBefore` and `@NotOnOrAfter`, through `Microsoft.IdentityModel`. It uses the 5-minute default
    skew, and `Saml2Configuration` doesn't expose that setting; the handler's `TokenValidationParameters` object is
    public and mutable, which #107 has to confirm as the hook;
  - `SubjectConfirmationData/@NotOnOrAfter` of the **first** `SubjectConfirmation`, with no clock skew;
  - optional replay cache.
- **Checks it leaves to the caller:** `InResponseTo`, `Destination`, `Recipient`, the subject-confirmation method, and
  the Assertion `Issuer`. It exposes all of these on the parsed token.
- **Metadata:**
  - reads IdP metadata (`EntityDescriptor.ReadIdPSsoDescriptor[FromUrlAsync]`): entity ID, SSO endpoints and signing
    certificates;
  - generates SP metadata, signed if you want;
  - does **not** verify metadata signatures and has no refresh scheduler.
- **Test support:**
  - it can act as an IdP (`Saml2AuthnResponse.CreateSecurityToken`, plus the `TestIdPCore` sample);
  - the PoC uses an independent `SignedXml` signer instead, so the library isn't validating its own output.

### Sustainsys.Saml2 v2 (evaluated at 2.11.0)

- **License:** MIT.
- **.NET:** the latest package targets `net8.0` (plus net461/net47). It runs on .NET 10 through forward compatibility,
  but has no `net10.0` build. Its dependency floors are old (e.g. `Microsoft.IdentityModel.Tokens.Saml >= 5.2.4`), so
  we would have to pin transitive versions ourselves.
- **Maintenance:**
  - the repo README says the `v2` branch "will only receive security fixes or critical compatibility fixes";
  - last release 2.11.0 on 2025-03-02; last `v2` commit 2026-01-09.
- **Security history:** three published advisories, all fixed promptly:
  - CVE-2020-5261 / GHSA-g6j2-ch25-5mmv: missing replay detection (fixed in 2.5.0);
  - CVE-2020-5268 / GHSA-9475-xg6m-j7pw: subject-confirmation method not validated (fixed in 2.7.0);
  - CVE-2023-41890 / GHSA-fv2h-753j-9g39: insufficient IdP issuer validation (fixed in 2.9.2).
- **Features:** feature-complete as a handler:
  - InResponseTo, handled through its own state cookie;
  - metadata loading with refresh;
  - `MinIncomingSigningAlgorithm` (SHA-256 by default);
  - XXE-safe loading;
  - a StubIdp project.
- **Per-tenant use:**
  - dynamic IdPs are possible inside **one** scheme, through `Options.IdentityProviders` and the
    `Notifications.GetIdentityProvider` callback;
  - `SPOptions` (SP entity ID, certificates, ACS) is one object per scheme, so a per-tenant SP entity ID or SP
    certificate works against the design;
  - the library also owns the HTTP flow (challenge, ACS, sign-in), which overlaps with how Aegis.Auth issues sessions.

### Sustainsys.Saml2 v3

- **Not released:** it isn't on NuGet. Its `SECURITY.md` marks the development branch as unsupported ("Wait for
  development to get ready").
- **License:** dual (`LICENSE.txt` on `main`). `src/foss` is MIT, but "Everything under `/src/commercial` requires a
  license agreement with Sustainsys AB for any use". The commercial part (`Sustainsys.Saml2.Plus`) already contains
  pieces such as the IdP-side writers and the IdentityServer integration.
- **Verdict:** can't be adopted today. If we adopted it later, every feature would need a licensing check.

## Scored comparison

Scores: 2 means meets the criterion, 1 means partly or with work, 0 means doesn't. The per-tenant row is the
issue's core requirement and is weighted ×2.

| # | Criterion | ITfoxtec 4.21.0 | Sustainsys v2.11.0 | Sustainsys v3 |
|---|---|:-:|:-:|:-:|
| 0 | Runtime per-tenant config, no scheme per IdP (×2) | **2** (a `Saml2Configuration` per request, which the PoC proves) | 1 (one scheme; the SP side is global) | – (handler-based, per its README) |
| 1 | License compatible with MIT redistribution | 2 (BSD-3) | 2 (MIT) | 1 (MIT core + commercial parts) |
| 2 | Supports the current .NET target | 2 (`net10.0` build) | 1 (`net8.0` only, old dependency floors) | 0 (unreleased) |
| 3 | Maintenance and security response | 2 (active, hardening in 2026; single vendor) | 1 (security fixes only; good advisory record) | 0 (unsupported) |
| 4 | SP-initiated Redirect AuthnRequest, POST ACS | 2 | 2 | – |
| 5 | Signature validation, pinned certs, rotation, rejects unsigned | 2 (tested) | 2 | – |
| 6 | XSW defence | 2 (3 XSW variants tested) | 2 (single reference enforced; not tested here) | – |
| 7 | Encrypted assertions | 1 (tested; no decryption algorithm allow-list, accepts RSA-1.5/3DES) | 2 | – |
| 8 | InResponseTo / Audience / Recipient / Destination / time checks | 1 (audience and time only; we add the rest, as the PoC shows) | 2 (inside its handler flow) | – |
| 9 | IdP metadata parsing, SP metadata generation | 1 (no metadata signature check, no refresh) | 2 | – |
| 10 | Algorithm allow-list (rejects SHA-1) | 2 (tested) | 2 | – |
| 11 | XXE-safe parsing | 2 (tested) | 2 | – |
| 12 | Can act as an IdP in tests | 2 | 1 (StubIdp is a separate web app) | – |
| | **Total (max 28)** | **25** | **23** | n/a |

The ITfoxtec scores marked "tested" come from the PoC tests. The Sustainsys v2 scores for rows 4–12 come from
reviewing its source and documentation; they weren't run in this spike.

## Decision

Use **ITfoxtec.Identity.Saml2**, core package only, as the SAML protocol and XML-signature engine for the SP.

- Pin an exact version and let Dependabot propose upgrades. Every upgrade must pass the SAML negative-test suite.
- Wrap it behind an internal Aegis SAML service in the SAML feature/plugin (#107). Endpoints and the rest of Aegis
  depend on our interface and our `Result` codes, never on ITfoxtec types, so a future swap stays local.
- Build a `Saml2Configuration` per request from the tenant's stored connection. Don't cache it across tenants.
- Implement the checks the library leaves open in our layer. The checklist is in the #106 PR description; the ones we
  must add are listed under Consequences below.

Sustainsys v2 is a good library. We didn't pick it because it is a handler with a global SP side, it has no `net10.0`
build, and it is in maintenance mode. Sustainsys v3 is out until it ships, and its commercial split is a risk for an
MIT project.

## Consequences

- **More code on our side:**
  - `InResponseTo` binding and single use;
  - `Destination`;
  - bearer `SubjectConfirmation` plus `Recipient`;
  - the Assertion `Issuer`;
  - assertion replay;
  - an allow-list for decryption algorithms (reject RSA-1.5 and 3DES before calling the library);
  - configurable clock skew for the subject-confirmation check;
  - metadata trust and refresh;
  - mapping library exceptions to `AuthErrors` codes.

  Each one needs a negative test. The spike's tests are the starting set.
- **The library throws.** Expected failures surface as exceptions (`InvalidSignatureException`,
  `Saml2RequestException`, `SecurityToken*Exception`, `XmlException`, `CryptographicException`). The SP service
  catches them and returns `Result` failures.
- **Messages must stay out of responses.** Exception messages can contain attacker-controlled values. They go to logs
  with care and are never sent in ProblemDetails.
- **Pinning must be configured explicitly.** `Saml2Configuration` defaults to `ChainTrust` with online revocation,
  and self-signed IdP certificates (the norm) fail that. Trust comes from the configured certificate list, so the SP
  sets `CertificateValidationMode.None` and `X509RevocationMode.NoCheck`. Certificate expiry becomes an admin-facing
  warning, not a silent rejection.
- **Single-vendor risk.** Watch the upstream repo for advisories. If it goes unmaintained, the wrapper keeps a
  migration (e.g. to Sustainsys v3's MIT core) contained.
- **Licensing notice.** BSD-3 attribution goes in the package's third-party notices when the SAML package ships.
- **The spike code is throwaway.** `tests/Aegis.Auth.Tests/Spikes/SamlLibrary` is removed or replaced by #107. Until
  then the Keycloak test runs only where a Linux Docker engine is available (it's skipped on the Windows CI runner).
