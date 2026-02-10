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
    public sealed class AegisCookieManager(AegisAuthOptions options, bool isDevelopment = false)
    {
        private readonly AegisAuthOptions _options = options;
        private readonly bool _isDevelopment = isDevelopment;

        public void SetSessionCookie(HttpContext context, Session session, User user, bool rememberMe)
        {
            // TODO Possibly custom cookienames like $"__Host-{_options.AppName}.session"
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

            if (!rememberMe)
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
            if (!_options.Session.CookieCache?.Enabled ?? false) return;

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
            context.Response.Cookies.Append("__Host-aegis.session_data", encodedData, new CookieOptions
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