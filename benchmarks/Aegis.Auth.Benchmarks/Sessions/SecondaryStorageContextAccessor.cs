using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;

namespace Aegis.Auth.Benchmarks.Sessions;

/// <summary>
/// What session validation would cost if it read the <see cref="IDistributedCache"/> entry <c>SessionService</c>
/// already writes, instead of the database. Aegis does not read that entry today; this stands in for the
/// secondary-storage option #141 is weighing, and plugs into the real authentication handler.
/// </summary>
internal sealed class SecondaryStorageContextAccessor(SessionCookieHandler cookieHandler, IDistributedCache cache) : IAegisAuthContextAccessor
{
    public async Task<AegisAuthContext?> GetCurrentAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        var sessionToken = cookieHandler.GetSessionToken(httpContext);
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return null;
        }

        // SessionService keys the entry by the raw token.
        var json = await cache.GetStringAsync(sessionToken, cancellationToken);
        if (json is null)
        {
            return null;
        }

        SessionCacheJson? entry = JsonSerializer.Deserialize<SessionCacheJson>(json);
        if (entry is null || entry.Session.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return new AegisAuthContext
        {
            UserId = entry.User.Id,
            SessionId = entry.Session.Id,
            SessionToken = sessionToken,
            ExpiresAt = entry.Session.ExpiresAt,
        };
    }
}
