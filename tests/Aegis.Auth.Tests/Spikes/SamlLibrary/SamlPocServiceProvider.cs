// ─────────────────────────────────────────────────────────────────────────────
// SPIKE / PROOF OF CONCEPT for #106 (SAML library choice). Throwaway test code.
// See docs/adr/0001-saml-library.md. Remove or replace when the SAML SP (#107) lands.
// ─────────────────────────────────────────────────────────────────────────────

using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;

using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;

using Microsoft.IdentityModel.Tokens.Saml2;

using SamlHttpRequest = ITfoxtec.Identity.Saml2.Http.HttpRequest;

namespace Aegis.Auth.Tests.Spikes.SamlLibrary;

/// <summary>
/// One tenant's SAML connection, as it would be loaded from the database for the current request.
/// Nothing here is registered in DI or as an ASP.NET authentication scheme.
/// </summary>
internal sealed record SamlConnection(
    string SpEntityId,
    Uri AcsUrl,
    string IdpEntityId,
    Uri IdpSsoUrl,
    IReadOnlyList<X509Certificate2> IdpSigningCertificates,
    IReadOnlyList<X509Certificate2>? SpDecryptionCertificates = null);

/// <summary>What the SP stored when it sent the AuthnRequest (the real SP keeps this server-side, bound to the browser).</summary>
internal sealed record PendingAuthnRequest(string RequestId, Uri RedirectUrl);

/// <summary>
/// PoC of the SP side on top of ITfoxtec.Identity.Saml2, driven entirely by a per-request
/// <see cref="SamlConnection"/>. Library validation first; then the checks the library leaves to the caller
/// (marked "Aegis layer"), which become the #107 checklist.
/// </summary>
internal static class SamlPocServiceProvider
{
    private const string BearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    public static Saml2Configuration BuildConfiguration(SamlConnection connection)
    {
        var config = new Saml2Configuration
        {
            Issuer = connection.SpEntityId,
            SingleSignOnDestination = connection.IdpSsoUrl,
            AllowedIssuer = connection.IdpEntityId,

            // Certificates are pinned: only the configured IdP certificates are trusted, so no chain building.
            CertificateValidationMode = X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,

            AudienceRestricted = true,
            SignatureValidationAlgorithms =
            {
                Saml2SecurityAlgorithms.RsaSha256Signature,
                Saml2SecurityAlgorithms.RsaSha384Signature,
                Saml2SecurityAlgorithms.RsaSha512Signature,
            },
        };
        config.AllowedAudienceUris.Add(connection.SpEntityId);
        config.SignatureValidationCertificates.AddRange(connection.IdpSigningCertificates);
        config.DecryptionCertificates.AddRange(connection.SpDecryptionCertificates ?? []);
        return config;
    }

    /// <summary>SP-initiated login: HTTP-Redirect binding AuthnRequest.</summary>
    public static PendingAuthnRequest CreateAuthnRequest(SamlConnection connection, string relayState)
    {
        var request = new Saml2AuthnRequest(BuildConfiguration(connection))
        {
            AssertionConsumerServiceUrl = connection.AcsUrl,
            ProtocolBinding = ProtocolBindings.HttpPost,
        };

        var binding = new Saml2RedirectBinding();
        binding.SetRelayStateQuery(new Dictionary<string, string> { ["s"] = relayState });
        binding.Bind(request);

        return new PendingAuthnRequest(request.IdAsString, binding.RedirectLocation);
    }

    /// <summary>ACS over HTTP-POST. Throws on any validation failure; returns the identity on success.</summary>
    public static ClaimsIdentity ValidateResponse(SamlConnection connection, PendingAuthnRequest? pending, string samlResponseBase64)
    {
        var httpRequest = new SamlHttpRequest
        {
            Method = "POST",
            Form = new NameValueCollection { ["SAMLResponse"] = samlResponseBase64 },
        };

        // Library: parse (DTD prohibited), signature (pinned certs, algorithm allow-list, single reference to the
        // validated element, exactly one Assertion), Response Issuer, Status, Audience, Conditions NotBefore/NotOnOrAfter,
        // SubjectConfirmationData NotOnOrAfter.
        var response = new Saml2AuthnResponse(BuildConfiguration(connection));
        new Saml2PostBinding().Unbind(httpRequest, response);

        if (response.Status != Saml2StatusCodes.Success)
        {
            throw new SamlPocValidationException($"IdP returned status {response.Status}.");
        }

        Saml2Assertion assertion = response.Saml2SecurityToken.Assertion;

        // Aegis layer: the Response Issuer is optional, so pin the Assertion Issuer too (cf. CVE-2023-41890).
        if (!string.Equals(assertion.Issuer?.Value, connection.IdpEntityId, StringComparison.Ordinal))
        {
            throw new SamlPocValidationException("Assertion Issuer does not match the configured IdP.");
        }

        // Aegis layer: Destination must be our ACS (required when the Response is signed).
        if (response.Destination is null || response.Destination != connection.AcsUrl)
        {
            throw new SamlPocValidationException("Response Destination does not match the ACS URL.");
        }

        // Aegis layer: InResponseTo must match the request we sent (unsolicited responses are rejected).
        if (pending is null || !string.Equals(response.InResponseToAsString, pending.RequestId, StringComparison.Ordinal))
        {
            throw new SamlPocValidationException("InResponseTo does not match a pending AuthnRequest.");
        }

        // Aegis layer: exactly one bearer SubjectConfirmation whose Recipient and InResponseTo match (cf. CVE-2020-5268).
        Saml2SubjectConfirmation[] bearer = [.. assertion.Subject.SubjectConfirmations.Where(c => c.Method?.OriginalString == BearerMethod)];
        if (bearer.Length != 1)
        {
            throw new SamlPocValidationException("Expected exactly one bearer SubjectConfirmation.");
        }

        Saml2SubjectConfirmationData? data = bearer[0].SubjectConfirmationData;
        if (data?.Recipient != connection.AcsUrl)
        {
            throw new SamlPocValidationException("SubjectConfirmationData Recipient does not match the ACS URL.");
        }

        if (!string.Equals(data.InResponseTo?.Value, pending.RequestId, StringComparison.Ordinal))
        {
            throw new SamlPocValidationException("SubjectConfirmationData InResponseTo does not match.");
        }

        return response.ClaimsIdentity;
    }
}

internal sealed class SamlPocValidationException(string message) : Exception(message);
