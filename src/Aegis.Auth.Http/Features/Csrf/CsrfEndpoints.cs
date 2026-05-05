using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Features.Csrf;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Features.Csrf;

public static class CsrfEndpoints
{
    /// <summary>
    /// GET /api/auth/csrf
    /// Returns a CSRF token that the client must include in X-CSRF-Token header on state-changing requests.
    /// Also sets a signed aegis.csrf cookie that the server validates.
    /// </summary>
    public static void MapCsrfEndpoint(this IEndpointRouteBuilder routes)
    {
        routes.MapGet("/api/auth/csrf", GetCsrfToken);
    }

    private static async Task<IResult> GetCsrfToken(HttpContext context, ICsrfTokenService csrfService, IOptions<AegisAuthOptions> optionsAccessor)
    {
        var options = optionsAccessor.Value;

        // Generate a new CSRF token
        var csrfToken = csrfService.GenerateToken();

        // Sign it like a session token
        var signedToken = AegisSigner.Sign(csrfToken, options.Secret);

        // Set it in a signed cookie (matching dev/prod cookie naming convention)
        var cookieName = context.Request.IsHttps ? "__Host-aegis.csrf" : "aegis.csrf";
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            MaxAge = TimeSpan.FromSeconds(options.Csrf.CookieMaxAge)
        };
        context.Response.Cookies.Append(cookieName, signedToken, cookieOptions);

        // Return the raw token to the client (client will send this in X-CSRF-Token header)
        return Results.Ok(new { token = csrfToken, cookieName });
    }
}

/// <summary>
/// Helpers for CSRF validation on endpoints.
/// </summary>
public static class CsrfValidationExtensions
{
    /// <summary>
    /// Validates CSRF token from the request. Returns true if valid; sets problem detail and returns false if invalid.
    /// Call this in your endpoint handler before processing state-changing operations.
    /// </summary>
    public static Task<bool> ValidateCsrfAsync(this HttpContext context, ICsrfTokenService csrfService, IOptions<AegisAuthOptions> optionsAccessor)
    {
        var options = optionsAccessor.Value;

        if (!options.Csrf.Enabled)
            return Task.FromResult(true);

        // Get CSRF token from header
        var headerToken = context.Request.Headers[options.Csrf.HeaderName].ToString();
        if (string.IsNullOrWhiteSpace(headerToken))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.FromResult(false);
        }

        // Get CSRF token from cookie
        var cookieName = context.Request.IsHttps ? "__Host-aegis.csrf" : "aegis.csrf";
        if (!context.Request.Cookies.TryGetValue(cookieName, out var cookieToken))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.FromResult(false);
        }

        // Validate
        if (!csrfService.ValidateToken(headerToken, cookieToken))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.FromResult(false);
        }

        return Task.FromResult(true);
    }
}
