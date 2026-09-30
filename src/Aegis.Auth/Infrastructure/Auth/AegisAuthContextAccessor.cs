using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Infrastructure.Auth;

internal sealed class AegisAuthContextAccessor(SessionCookieHandler cookieHandler, IAuthDbContext dbContext, TimeProvider timeProvider) : IAegisAuthContextAccessor
{
    private readonly SessionCookieHandler _cookieHandler = cookieHandler;
    private readonly IAuthDbContext _db = dbContext;
    private readonly TimeProvider _time = timeProvider;

    public async Task<AegisAuthContext?> GetCurrentAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        // Short-circuit: auth handler may have already resolved this request.
        if (httpContext.GetAegisAuthContext() is { } cached)
        {
            return cached;
        }

        var sessionToken = _cookieHandler.GetSessionToken(httpContext);
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return null;
        }

        // Fast path: prefer validated cookie cache when available.
        DateTime now = _time.GetUtcNow().UtcDateTime;
        SessionCacheMetadata? cookieCache = _cookieHandler.GetCookieCache(httpContext);
        if (cookieCache is not null
            && string.Equals(cookieCache.Session.Token, sessionToken, StringComparison.Ordinal)
            && cookieCache.Session.ExpiresAt > now
            && string.IsNullOrWhiteSpace(cookieCache.User.Id) is false)
        {
            return new AegisAuthContext
            {
                UserId = cookieCache.User.Id,
                SessionId = cookieCache.Session.Id,
                SessionToken = sessionToken,
                ExpiresAt = cookieCache.Session.ExpiresAt,
                IsFromCookieCache = true,
            };
        }

        // Hash the raw cookie token before querying the database.
        // The database only stores the hash; the raw token is never persisted.
        var tokenHash = AegisCrypto.HashToken(sessionToken);
        Session? session = await _db.Sessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.TokenHash == tokenHash, cancellationToken);

        if (session is null || session.ExpiresAt <= now)
        {
            return null;
        }

        return new AegisAuthContext
        {
            UserId = session.UserId,
            SessionId = session.Id,
            SessionToken = sessionToken, // return the raw cookie token, not the DB hash
            ExpiresAt = session.ExpiresAt,
            IsFromCookieCache = false,
        };
    }
}
