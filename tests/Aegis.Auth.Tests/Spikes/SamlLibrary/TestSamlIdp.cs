// ─────────────────────────────────────────────────────────────────────────────
// SPIKE / PROOF OF CONCEPT for #106 (SAML library choice). Throwaway test code.
// See docs/adr/0001-saml-library.md. Remove or replace when the SAML SP (#107) lands.
// ─────────────────────────────────────────────────────────────────────────────

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Aegis.Auth.Tests.Spikes.SamlLibrary;

/// <summary>
/// Minimal in-process SAML 2.0 identity provider for tests. It builds <c>samlp:Response</c> documents
/// by hand and signs them with <see cref="SignedXml"/> directly, so the signer is independent of the
/// library under test. Every knob that a negative test needs to turn is on <see cref="SamlResponseSpec"/>.
/// </summary>
internal sealed class TestSamlIdp : IDisposable
{
    public const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    public const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    public TestSamlIdp(string entityId)
    {
        EntityId = entityId;
        SigningCertificate = CreateSelfSignedCertificate(entityId);
    }

    public string EntityId { get; }

    /// <summary>Certificate with private key, used to sign.</summary>
    public X509Certificate2 SigningCertificate { get; }

    /// <summary>What an SP admin would paste or import from metadata: public key only.</summary>
    public X509Certificate2 PublicCertificate => X509CertificateLoader.LoadCertificate(SigningCertificate.Export(X509ContentType.Cert));

    public static X509Certificate2 CreateSelfSignedCertificate(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={new Uri(subject).Host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>Builds the response and returns it as the XML document (for tests that tamper after signing).</summary>
    public XmlDocument CreateResponseDocument(SamlResponseSpec spec)
    {
        DateTime now = DateTime.UtcNow;
        string responseId = "_" + Guid.NewGuid().ToString("N");
        string assertionId = "_" + Guid.NewGuid().ToString("N");
        string issuer = spec.Issuer ?? EntityId;
        string assertionIssuer = spec.AssertionIssuer ?? issuer;
        string notBefore = Iso(spec.NotBefore ?? now.AddMinutes(-1));
        string notOnOrAfter = Iso(spec.NotOnOrAfter ?? now.AddMinutes(5));
        string inResponseTo = spec.InResponseTo is null ? "" : $" InResponseTo=\"{spec.InResponseTo}\"";

        string xml =
            $"""
            <samlp:Response xmlns:samlp="{ProtocolNs}" xmlns:saml="{AssertionNs}" ID="{responseId}" Version="2.0" IssueInstant="{Iso(now)}" Destination="{spec.Destination}"{inResponseTo}>
              <saml:Issuer>{issuer}</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
              <saml:Assertion ID="{assertionId}" Version="2.0" IssueInstant="{Iso(now)}">
                <saml:Issuer>{assertionIssuer}</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{spec.NameId}</saml:NameID>
                  <saml:SubjectConfirmation Method="{spec.SubjectConfirmationMethod}">
                    <saml:SubjectConfirmationData NotOnOrAfter="{notOnOrAfter}" Recipient="{spec.Recipient ?? spec.Destination}"{inResponseTo}/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="{notBefore}" NotOnOrAfter="{notOnOrAfter}">
                  <saml:AudienceRestriction><saml:Audience>{spec.Audience}</saml:Audience></saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="{Iso(now)}" SessionIndex="{assertionId}">
                  <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
                </saml:AuthnStatement>
                <saml:AttributeStatement>
                  <saml:Attribute Name="email"><saml:AttributeValue>{spec.NameId}</saml:AttributeValue></saml:Attribute>
                </saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>
            """;

        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        doc.LoadXml(xml);

        X509Certificate2 signer = spec.SigningCertificate ?? SigningCertificate;
        if (spec.SignAssertion)
        {
            var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", AssertionNs)[0]!;
            Sign(assertion, assertionId, signer, spec.SignatureAlgorithm);
        }

        if (spec.EncryptFor is not null)
        {
            EncryptAssertion(doc, spec.EncryptFor);
        }

        if (spec.SignResponse)
        {
            Sign(doc.DocumentElement!, responseId, signer, spec.SignatureAlgorithm);
        }

        return doc;
    }

    /// <summary>Builds, signs and base64-encodes the response, as it would arrive in the <c>SAMLResponse</c> form field.</summary>
    public string CreateResponse(SamlResponseSpec spec) => Encode(CreateResponseDocument(spec));

    public static string Encode(XmlDocument doc) => Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));

    public static string Encode(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    private static void Sign(XmlElement element, string id, X509Certificate2 certificate, string signatureAlgorithm)
    {
        var signedXml = new SignedXml(element) { SigningKey = certificate.GetRSAPrivateKey() };
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = signatureAlgorithm;

        var reference = new Reference("#" + id)
        {
            DigestMethod = signatureAlgorithm == RsaSha1 ? SignedXml.XmlDsigSHA1Url : SignedXml.XmlDsigSHA256Url,
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        XmlElement signature = signedXml.GetXml();

        // Schema order: the Signature goes directly after the element's own Issuer.
        XmlNode issuer = element.GetElementsByTagName("Issuer", AssertionNs)[0]!;
        element.InsertAfter(element.OwnerDocument.ImportNode(signature, true), issuer);
    }

    /// <summary>Replaces the (already signed) Assertion with an EncryptedAssertion: AES-256-CBC content key wrapped with RSA-OAEP.</summary>
    private static void EncryptAssertion(XmlDocument doc, X509Certificate2 spCertificate)
    {
        var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", AssertionNs)[0]!;
        using var contentKey = Aes.Create();
        contentKey.KeySize = 256;

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            CipherData = new CipherData(new EncryptedXml().EncryptData(assertion, contentKey, false)),
        };
        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl),
            CipherData = new CipherData(EncryptedXml.EncryptKey(contentKey.Key, spCertificate.GetRSAPublicKey()!, useOAEP: true)),
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

        XmlElement wrapper = doc.CreateElement("saml", "EncryptedAssertion", AssertionNs);
        wrapper.AppendChild(doc.ImportNode(encryptedData.GetXml(), true));
        assertion.ParentNode!.ReplaceChild(wrapper, assertion);
    }

    private static string Iso(DateTime value) => value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

    public void Dispose() => SigningCertificate.Dispose();
}

internal sealed record SamlResponseSpec
{
    public required string Destination { get; init; }
    public required string Audience { get; init; }
    public string? InResponseTo { get; init; }
    public string? Recipient { get; init; }
    public string NameId { get; init; } = "alice@example.test";
    public string? Issuer { get; init; }
    public string? AssertionIssuer { get; init; }
    public DateTime? NotBefore { get; init; }
    public DateTime? NotOnOrAfter { get; init; }
    public string SubjectConfirmationMethod { get; init; } = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public bool SignResponse { get; init; } = true;
    public bool SignAssertion { get; init; } = true;
    public string SignatureAlgorithm { get; init; } = TestSamlIdp.RsaSha256;
    public X509Certificate2? SigningCertificate { get; init; }

    /// <summary>When set, the signed Assertion is encrypted to this SP certificate.</summary>
    public X509Certificate2? EncryptFor { get; init; }
}
