using Aegis.Auth.Options;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Infrastructure.Cookies
{
    /// <summary>
    /// Manages authentication cookies for Aegis.Auth.
    /// </summary>
    public class AegisCookieManager
    {
        private readonly AegisAuthOptions _options;
        private const string SessionCookieName = "aegis_session";

        public AegisCookieManager(AegisAuthOptions options)
        {
            _options = options;
        }

        /// <summary>
        /// Sets the session cookie with the provided token.
        /// </summary>
        public void SetSessionCookie(HttpContext context, string sessionToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                MaxAge = TimeSpan.FromDays(30),
                Path = "/"
            };

            context.Response.Cookies.Append(SessionCookieName, sessionToken, cookieOptions);
        }

        /// <summary>
        /// Clears the session cookie.
        /// </summary>
        public void ClearSessionCookie(HttpContext context)
        {
            context.Response.Cookies.Delete(SessionCookieName);
        }

        /// <summary>
        /// Gets the session token from the cookie.
        /// </summary>
        public string? GetSessionToken(HttpContext context)
        {
            return context.Request.Cookies[SessionCookieName];
        }
    }
}