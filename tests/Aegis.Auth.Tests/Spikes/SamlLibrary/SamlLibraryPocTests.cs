// ─────────────────────────────────────────────────────────────────────────────
// SPIKE / PROOF OF CONCEPT for #106 (SAML library choice). Throwaway test code.
// See docs/adr/0001-saml-library.md. Remove or replace when the SAML SP (#107) lands.
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Cryptography;

using Microsoft.IdentityModel.Tokens;

namespace Aegis.Auth.Tests.Spikes.SamlLibrary;

/// <summary>
/// Exercises ITfoxtec.Identity.Saml2 against an in-process IdP that signs with a self-signed certificate.
/// Each test builds the SP configuration per call from a <see cref="SamlConnection"/>: two tenants, two IdPs,
/// no authentication scheme per IdP.
/// </summary>
[Trait("Category", "Spike")]
public sealed class SamlLibraryPocTests : IDisposable
{
    private readonly TestSamlIdp _idpA = new("https://idp-a.example.test/saml");
    private readonly TestSamlIdp _idpB = new("https://idp-b.example.test/saml");
    private readonly SamlConnection _tenantA;
    private readonly SamlConnection _tenantB;

    public SamlLibraryPocTests()
    {
        _tenantA = Connection("tenant-a", _idpA);
        _tenantB = Connection("tenant-b", _idpB);
    }

    private static SamlConnection Connection(string tenant, TestSamlIdp idp, params TestSamlIdp[] extraCertificates) => new(
        SpEntityId: $"https://sp.aegis.test/saml/{tenant}",
        AcsUrl: new Uri($"https://sp.aegis.test/saml/{tenant}/acs"),
        IdpEntityId: idp.EntityId,
        IdpSsoUrl: new Uri(idp.EntityId + "/sso"),
        IdpSigningCertificates: [idp.PublicCertificate, .. extraCertificates.Select(e => e.PublicCertificate)]);

    private static SamlResponseSpec SpecFor(SamlConnection connection, PendingAuthnRequest pending) => new()
    {
        Destination = connection.AcsUrl.ToString(),
        Audience = connection.SpEntityId,
        InResponseTo = pending.RequestId,
    };

    private static PendingAuthnRequest Pending(SamlConnection connection) =>
        SamlPocServiceProvider.CreateAuthnRequest(connection, relayState: "state-123");

    // ═══════════════════════════════════════════════════════════════════════════
    // HAPPY PATH — per-request configuration, several IdPs, no auth scheme
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void AuthnRequest_UsesRedirectBinding_ToTheTenantsIdp()
    {
        PendingAuthnRequest pending = Pending(_tenantA);

        Assert.StartsWith(_tenantA.IdpSsoUrl.ToString(), pending.RedirectUrl.ToString());
        Assert.Contains("SAMLRequest=", pending.RedirectUrl.Query);
        Assert.Contains("RelayState=", pending.RedirectUrl.Query);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void SignedResponse_IsAccepted(bool signResponse, bool signAssertion)
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { SignResponse = signResponse, SignAssertion = signAssertion });

        ClaimsIdentity identity = SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response);

        Assert.Equal("alice@example.test", identity.FindFirst(Saml2ClaimTypes.NameId)?.Value);
    }

    [Fact]
    public void TwoTenants_ValidateAgainstTheirOwnIdp_InTheSameProcess()
    {
        PendingAuthnRequest pendingA = Pending(_tenantA);
        PendingAuthnRequest pendingB = Pending(_tenantB);

        Assert.NotNull(SamlPocServiceProvider.ValidateResponse(_tenantA, pendingA, _idpA.CreateResponse(SpecFor(_tenantA, pendingA))));
        Assert.NotNull(SamlPocServiceProvider.ValidateResponse(_tenantB, pendingB, _idpB.CreateResponse(SpecFor(_tenantB, pendingB))));
    }

    [Fact]
    public void CertificateRotation_AnyConfiguredCertificateIsAccepted()
    {
        using var rotated = new TestSamlIdp(_idpA.EntityId);
        SamlConnection connection = Connection("tenant-a", _idpA, rotated);
        PendingAuthnRequest pending = Pending(connection);

        string response = rotated.CreateResponse(SpecFor(connection, pending));

        Assert.NotNull(SamlPocServiceProvider.ValidateResponse(connection, pending, response));
    }

    [Fact]
    public void EncryptedAssertion_IsDecryptedWithTheSpCertificate_AndItsSignatureValidated()
    {
        using X509Certificate2 spCertificate = TestSamlIdp.CreateSelfSignedCertificate(_tenantA.SpEntityId);
        SamlConnection connection = _tenantA with { SpDecryptionCertificates = [spCertificate] };
        PendingAuthnRequest pending = Pending(connection);

        string response = _idpA.CreateResponse(SpecFor(connection, pending) with { SignResponse = false, EncryptFor = spCertificate });

        ClaimsIdentity identity = SamlPocServiceProvider.ValidateResponse(connection, pending, response);
        Assert.Equal("alice@example.test", identity.FindFirst(Saml2ClaimTypes.NameId)?.Value);
    }

    [Fact]
    public void EncryptedAssertion_WithoutInnerSignature_IsRejected()
    {
        // Encryption is not authentication: anyone with the SP's public certificate can encrypt an assertion.
        using X509Certificate2 spCertificate = TestSamlIdp.CreateSelfSignedCertificate(_tenantA.SpEntityId);
        SamlConnection connection = _tenantA with { SpDecryptionCertificates = [spCertificate] };
        PendingAuthnRequest pending = Pending(connection);

        string response = _idpA.CreateResponse(SpecFor(connection, pending) with { SignResponse = false, SignAssertion = false, EncryptFor = spCertificate });

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(connection, pending, response));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE — rejected by the library
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void UnsignedResponse_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { SignResponse = false, SignAssertion = false });

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void TamperedAssertion_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending));
        doc.GetElementsByTagName("NameID", TestSamlIdp.AssertionNs)[0]!.InnerText = "admin@example.test";

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(doc)));
    }

    [Fact]
    public void SignedByUnconfiguredCertificate_IsRejected()
    {
        using var attacker = new TestSamlIdp(_idpA.EntityId);
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = attacker.CreateResponse(SpecFor(_tenantA, pending));

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void CrossTenant_ResponseFromOtherTenantsIdp_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpB.CreateResponse(SpecFor(_tenantA, pending) with { Issuer = _idpA.EntityId });

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void Sha1Signature_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { SignatureAlgorithm = TestSamlIdp.RsaSha1 });

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE WRAPPING (XSW)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Xsw_ExtraUnsignedAssertionNextToSignedOne_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending) with { SignResponse = false });
        var signed = (XmlElement)doc.GetElementsByTagName("Assertion", TestSamlIdp.AssertionNs)[0]!;

        XmlElement evil = EvilCopy(signed);
        signed.ParentNode!.InsertBefore(evil, signed);

        var ex = Assert.Throws<Saml2RequestException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(doc)));
        Assert.Contains("not exactly one Assertion", ex.Message);
    }

    [Fact]
    public void Xsw_SignedAssertionWrappedInsideUnsignedEvilAssertion_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending) with { SignResponse = false });
        var signed = (XmlElement)doc.GetElementsByTagName("Assertion", TestSamlIdp.AssertionNs)[0]!;

        XmlElement evil = EvilCopy(signed);
        signed.ParentNode!.ReplaceChild(evil, signed);
        evil.AppendChild(signed);

        Assert.Throws<InvalidSignatureException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(doc)));
    }

    [Fact]
    public void Xsw_SignedResponseMovedIntoExtensions_WithEvilResponseAround_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending) with { SignAssertion = false });
        XmlElement original = doc.DocumentElement!;

        // New root with a new ID and an evil assertion; the original, validly signed response hides in Extensions.
        var evilRoot = (XmlElement)original.CloneNode(deep: true);
        evilRoot.SetAttribute("ID", "_evil-response");
        XmlNode signature = evilRoot.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        signature.ParentNode!.RemoveChild(signature);
        evilRoot.GetElementsByTagName("NameID", TestSamlIdp.AssertionNs)[0]!.InnerText = "admin@example.test";

        XmlElement extensions = doc.CreateElement("samlp", "Extensions", TestSamlIdp.ProtocolNs);
        extensions.AppendChild(original.CloneNode(deep: true));
        evilRoot.InsertAfter(extensions, evilRoot.GetElementsByTagName("Issuer", TestSamlIdp.AssertionNs)[0]);

        var ex = Assert.Throws<Saml2RequestException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(evilRoot.OuterXml)));
        Assert.Contains("not exactly one Assertion", ex.Message);
    }

    [Fact]
    public void CommentInjectionInNameId_DoesNotTruncateTheValue()
    {
        // The IdP signs "alice@example.test.evil.test"; the attacker adds a comment. Exclusive C14N drops comments,
        // so the signature stays valid; the library must still read the full text, not the first text node.
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending) with { NameId = "alice@example.test.evil.test", SignResponse = false });
        XmlNode nameId = doc.GetElementsByTagName("NameID", TestSamlIdp.AssertionNs)[0]!;
        nameId.RemoveAll();
        nameId.AppendChild(doc.CreateTextNode("alice@example.test"));
        nameId.AppendChild(doc.CreateComment(""));
        nameId.AppendChild(doc.CreateTextNode(".evil.test"));
        ((XmlElement)nameId).SetAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        ClaimsIdentity identity = SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(doc));

        Assert.Equal("alice@example.test.evil.test", identity.FindFirst(Saml2ClaimTypes.NameId)?.Value);
    }

    private static XmlElement EvilCopy(XmlElement signedAssertion)
    {
        var evil = (XmlElement)signedAssertion.CloneNode(deep: true);
        evil.SetAttribute("ID", "_evil-assertion");
        XmlNode signature = evil.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        signature.ParentNode!.RemoveChild(signature);
        evil.GetElementsByTagName("NameID", TestSamlIdp.AssertionNs)[0]!.InnerText = "admin@example.test";
        return evil;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // XML PARSING
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void DoctypeAndExternalEntity_AreRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        XmlDocument doc = _idpA.CreateResponseDocument(SpecFor(_tenantA, pending));
        string xxe = "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" + doc.OuterXml.Replace("alice@example.test", "&xxe;");

        Assert.Throws<XmlException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, TestSamlIdp.Encode(xxe)));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CONDITIONS — library (audience, lifetime)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void WrongAudience_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { Audience = _tenantB.SpEntityId });

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void ExpiredAssertion_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with
        {
            NotBefore = DateTime.UtcNow.AddHours(-2),
            NotOnOrAfter = DateTime.UtcNow.AddHours(-1),
        });

        Assert.Throws<Saml2RequestException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void NotYetValidAssertion_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with
        {
            NotBefore = DateTime.UtcNow.AddHours(1),
            NotOnOrAfter = DateTime.UtcNow.AddHours(2),
        });

        Assert.Throws<SecurityTokenNotYetValidException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AEGIS LAYER — checks the library leaves to us (the #107 checklist)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void InResponseToMismatch_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { InResponseTo = "_someone-elses-request" });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void UnsolicitedResponse_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { InResponseTo = null });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending: null, response));
    }

    [Fact]
    public void WrongDestination_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { Destination = _tenantB.AcsUrl.ToString(), Recipient = _tenantA.AcsUrl.ToString() });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void WrongRecipient_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { Recipient = _tenantB.AcsUrl.ToString() });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void NonBearerSubjectConfirmation_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { SubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    [Fact]
    public void AssertionIssuerMismatch_IsRejected()
    {
        PendingAuthnRequest pending = Pending(_tenantA);
        string response = _idpA.CreateResponse(SpecFor(_tenantA, pending) with { AssertionIssuer = _idpB.EntityId });

        Assert.Throws<SamlPocValidationException>(() => SamlPocServiceProvider.ValidateResponse(_tenantA, pending, response));
    }

    public void Dispose()
    {
        _idpA.Dispose();
        _idpB.Dispose();
    }
}
