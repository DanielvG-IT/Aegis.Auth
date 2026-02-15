using System.Text.Json;

using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Extensions;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Models;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Infrastructure.Cookies
{
    public sealed class SessionCookieHandler(AegisAuthOptions options, bool isDevelopment = false)
    {
        private readonly AegisAuthOptions _options = options;
        private readonly bool _isDevelopment = isDevelopment;

        // TODO Cookie roadmap:
        // [ ] Add per-cookie config models (session_token, session_data, dont_remember)
        // [ ] Support per-cookie + default attribute overrides from configuration
        // [ ] Add secure prefix strategy (__Host-/__Secure-) and configurable cookie prefix
        // [ ] Add optional cross-subdomain domain support
        // [ ] Add chunking for oversized session_data cookies (>4093 bytes)
        // [ ] Align remember-me behavior between sign-in and sign-up flows

        private string SessionCookieName => _isDevelopment ? "aegis.session" : "__Host-aegis.session";
        private string SessionDataCookieName => _isDevelopment ? "aegis.session_data" : "__Host-aegis.session_data";
        private string DontRememberCookieName => _isDevelopment ? "aegis.dont_remember" : "__Host-aegis.dont_remember";

        public void SetSessionCookie(HttpContext context, Session session, User user, bool rememberMe)
        {
            var sessionCookieName = SessionCookieName;
            var dontRememberCookieName = DontRememberCookieName;

            var signedToken = AegisSigner.Sign(session.Token, _options.Secret);
            var sessionOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = !_isDevelopment, // Only secure in production
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = rememberMe ? session.ExpiresAt : null
            };
            context.Response.Cookies.Append(sessionCookieName, signedToken, sessionOptions);

            if (rememberMe is false)
            {
                var drOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = !_isDevelopment,
                    Path = "/",
                    SameSite = SameSiteMode.Lax
                };
                var signedTrue = AegisSigner.Sign("true", _options.Secret);
                context.Response.Cookies.Append(dontRememberCookieName, signedTrue, drOptions);
            }

            if (_options.Session.CookieCache?.Enabled == true)
                SetCookieCache(context, session, user, rememberMe);

            return;
        }

        public void SetCookieCache(HttpContext context, Session session, User user, bool rememberMe)
        {
            if (_options.Session.CookieCache?.Enabled is false) return;

            var sessionDataCookieName = SessionDataCookieName;

            var sessionPayload = new SessionCacheDto
            {
                Session = new()
                {
                    Session = session.ToDto(),
                    User = user.ToDto(),
                },
                UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Version = _options.Session.CookieCache?.Version ?? "1"
            };

            DateTimeOffset cacheExpiry = DateTimeOffset.UtcNow.AddSeconds(_options.Session.CookieCache?.MaxAge ?? 300);
            var signableEnvelope = new
            {
                ExpiresAt = cacheExpiry.ToUnixTimeMilliseconds(),
                Session = sessionPayload
            };
            var signableEnvelopeJson = JsonSerializer.Serialize(signableEnvelope);
            var signature = AegisSigner.GenerateSignature(signableEnvelopeJson, _options.Secret);

            var finalEnvelope = new SessionCachePayload
            {
                Signature = signature,
                Session = sessionPayload,
                ExpiresAt = cacheExpiry.ToUnixTimeMilliseconds(),
            };

            var finalJson = JsonSerializer.Serialize(finalEnvelope);
            CookieCacheMode mode = _options.Session.CookieCache?.Mode ?? CookieCacheMode.Compact;
            var cookieValue = mode switch
            {
                CookieCacheMode.Encrypted => AegisCrypto.Encrypt(finalJson, _options.Secret),
                _ => AegisCrypto.ToBase64Url(finalJson), // Compact: signed but readable
            };
            context.Response.Cookies.Append(sessionDataCookieName, cookieValue, new CookieOptions
            {
                HttpOnly = true,
                Secure = !_isDevelopment,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = rememberMe ? session.ExpiresAt : null
            });

            return;
        }

        /// <summary>
        /// Reads the session token from the request cookie and verifies the HMAC signature.
        /// Returns the raw token if valid, null if missing or tampered.
        /// </summary>
        public string? GetSessionToken(HttpContext context)
        {
            if (!context.Request.Cookies.TryGetValue(SessionCookieName, out var signedValue))
                return null;

            if (string.IsNullOrWhiteSpace(signedValue))
                return null;

            // Format: "token.signature"
            var dotIndex = signedValue.LastIndexOf('.');
            if (dotIndex <= 0 || dotIndex >= signedValue.Length - 1)
                return null;

            var token = signedValue[..dotIndex];
            var signature = signedValue[(dotIndex + 1)..];

            return AegisSigner.VerifySignature(token, signature, _options.Secret)
                ? token
                : null;
        }

        /// <summary>
        /// Deletes all Aegis session cookies (session_token, session_data, dont_remember).
        /// </summary>
        public void ClearSessionCookies(HttpContext context)
        {
            var deleteOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = !_isDevelopment,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            };

            context.Response.Cookies.Delete(SessionCookieName, deleteOptions);
            context.Response.Cookies.Delete(SessionDataCookieName, deleteOptions);
            context.Response.Cookies.Delete(DontRememberCookieName, deleteOptions);
        }
    }
}