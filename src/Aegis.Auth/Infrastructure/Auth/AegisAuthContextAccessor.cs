using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Infrastructure.Auth;

internal sealed class AegisAuthContextAccessor(SessionCookieHandler cookieHandler, IAuthDbContext dbContext) : IAegisAuthContextAccessor
{
    private readonly SessionCookieHandler _cookieHandler = cookieHandler;
    private readonly IAuthDbContext _db = dbContext;

    public async Task<AegisAuthContext?> GetCurrentAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var sessionToken = _cookieHandler.GetSessionToken(httpContext);
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return null;
        }

        // Fast path: prefer validated cookie cache when available.
        SessionCacheMetadata? cookieCache = _cookieHandler.GetCookieCache(httpContext);
        if (cookieCache is not null
            && string.Equals(cookieCache.Session.Token, sessionToken, StringComparison.Ordinal)
            && cookieCache.Session.ExpiresAt > DateTime.UtcNow
            && string.IsNullOrWhiteSpace(cookieCache.User.Id) is false)
        {
            return new AegisAuthContext
            {
                UserId = cookieCache.User.Id,
                SessionToken = sessionToken,
                ExpiresAt = cookieCache.Session.ExpiresAt,
                IsFromCookieCache = true,
            };
        }

        Session? session = await _db.Sessions
        .AsNoTracking()
        .FirstOrDefaultAsync(s => s.Token == sessionToken, cancellationToken);

        if (session is null || session.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return new AegisAuthContext
        {
            UserId = session.UserId,
            SessionToken = session.Token,
            ExpiresAt = session.ExpiresAt,
            IsFromCookieCache = false,
        };
    }
}
