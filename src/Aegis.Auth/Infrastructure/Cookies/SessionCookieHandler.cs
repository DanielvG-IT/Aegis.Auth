using System.Text.Json;
using System.Text;

using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Extensions;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace Aegis.Auth.Infrastructure.Cookies
{
    public sealed class SessionCookieHandler(AegisAuthOptions options, bool isDevelopment = false)
    {
        private readonly AegisAuthOptions _options = options;
        private readonly bool _isDevelopment = isDevelopment;

        // TODO Cookie roadmap (better-auth parity, .NET-idiomatic):
        // [ ] Replace direct options object usage with IOptions/IOptionsSnapshot in DI registration
        // [ ] Add per-cookie config models (session_token, session_data, dont_remember)
        // [ ] Support per-cookie + default attribute overrides from configuration
        // [ ] Add secure prefix strategy (__Host-/__Secure-) and configurable cookie prefix
        // [ ] Add optional cross-subdomain domain support
        // [ ] Add chunking for oversized session_data cookies (>4093 bytes)
        // [ ] Add cookie read/verify helpers (session token + session cache)
        // [ ] Add delete/expire flow including chunk cleanup + dont_remember cleanup
        // [ ] Align remember-me behavior between sign-in and sign-up flows
        // [ ] Migrate signing/encryption to ASP.NET Core Data Protection

        public void SetSessionCookie(HttpContext context, Session session, User user, bool rememberMe)
        {
            var sessionCookieName = _isDevelopment ? "aegis.session" : "__Host-aegis.session";
            var dontRememberCookieName = _isDevelopment ? "aegis.dont_remember" : "__Host-aegis.dont_remember";

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

            var sessionDataCookieName = _isDevelopment ? "aegis.session_data" : "__Host-aegis.session_data";

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
            var payloadJson = JsonSerializer.Serialize(sessionPayload);
            var signature = AegisSigner.GenerateSignature(payloadJson, _options.Secret);

            var finalEnvelope = new SessionCachePayload
            {
                Signature = signature,
                Session = sessionPayload,
                ExpiresAt = cacheExpiry.ToUnixTimeMilliseconds(),
            };

            var finalJson = JsonSerializer.Serialize(finalEnvelope);
            var encodedData = Base64UrlTextEncoder.Encode(Encoding.UTF8.GetBytes(finalJson));
            context.Response.Cookies.Append(sessionDataCookieName, encodedData, new CookieOptions
            {
                HttpOnly = true,
                Secure = !_isDevelopment,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Expires = rememberMe ? session.ExpiresAt : null
            });

            return;
        }
    }
}