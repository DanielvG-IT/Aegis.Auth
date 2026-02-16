using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.Sessions
{
    public interface ISessionService
    {
        Task<Result<Session>> CreateSessionAsync(SessionCreateInput input);
        Task<Result> RevokeSessionAsync(SessionDeleteInput input);
        Task<Result> RevokeAllSessionsAsync(string userId);
    }

    internal sealed class SessionService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext, IDistributedCache? disCache) : ISessionService
    {
        private readonly AegisAuthOptions _options = options;
        private readonly IDistributedCache? _cache = disCache;
        private readonly IAuthDbContext _db = dbContext;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SessionService>();

        private const int DefaultSessionExpiration = 604800; // 7 days in seconds (60 * 60 * 24 * 7)
        private const string RegistryKeyPrefix = "active-sessions-";

        public async Task<Result<Session>> CreateSessionAsync(SessionCreateInput input)
        {
            _logger.SessionCreating(input.User.Id);

            var sessionExpiration = _options.Session.ExpiresIn is not 0 ? _options.Session.ExpiresIn : DefaultSessionExpiration;

            DateTime now = DateTime.UtcNow;
            var nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var data = new Session
            {
                Id = Guid.CreateVersion7().ToString(),
                IpAddress = input.IpAddress,
                UserAgent = input.UserAgent,

                // If the user doesn't want to be remembered, set the session to expire in 1 day. The cookie will be set to expire at the end of the session.
                // NOTE: User navigation property is intentionally NOT set to avoid EF Core tracking conflicts when the User instance is already tracked.
                // Callers should use input.User if they need the User object, or query by UserId separately.
                ExpiresAt = input.DontRememberMe ? now.AddDays(1) : now.AddSeconds(sessionExpiration),
                UserId = input.User.Id,
                Token = AegisCrypto.RandomStringGenerator(32, "a-z", "A-Z", "0-9"),
                CreatedAt = now,
                UpdatedAt = now,
                // Possible override values later here
            };

            // Save to database first if enabled (to ensure consistency before caching)
            if (_options.Session.StoreSessionInDatabase || _cache is null)
            {
                _db.Sessions.Add(data);
                try
                {
                    await _db.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    _logger.SessionCreationFailed(input.User.Id, ex);
                    return Result<Session>.Failure(Constants.AuthErrors.System.InternalError, "Failed to save session.");
                }
            }

            // Cache the session only after DB persistence succeeds
            // Use optimistic retry to mitigate race conditions in registry updates
            if (_cache is not null)
            {
                var registryKey = RegistryKeyPrefix + input.User.Id;
                var sessionExpiryUnixMs = new DateTimeOffset(data.ExpiresAt).ToUnixTimeMilliseconds();

                // Skip registry if session is already expired
                if (sessionExpiryUnixMs > nowUnixMs)
                {
                    const int maxRetries = 3;
                    var registryUpdated = false;

                    for (var attempt = 0; attempt < maxRetries && !registryUpdated; attempt++)
                    {
                        // 1. Fetch the current session list for the user
                        var currentListJson = await _cache.GetStringAsync(registryKey);

                        List<SessionReference> list = [];
                        if (string.IsNullOrWhiteSpace(currentListJson) is false)
                        {
                            List<SessionReference>? cachedList = JsonSerializer.Deserialize<List<SessionReference>>(currentListJson);
                            if (cachedList is not null)
                            {
                                // Filter: remove expired and duplicates
                                list = [.. cachedList.Where(s => s.ExpiresAt > nowUnixMs && s.Token != data.Token)];
                            }
                        }

                        // 2. Add new session and sort
                        list.Add(new SessionReference { Token = data.Token, ExpiresAt = sessionExpiryUnixMs });
                        list.Sort((a, b) => a.ExpiresAt.CompareTo(b.ExpiresAt));

                        // 3. Calculate TTL for the Registry (round up to prevent premature expiration)
                        var furthestSessionExp = list.LastOrDefault()?.ExpiresAt ?? nowUnixMs;
                        var furthestSessionTTL = (long)Math.Ceiling((furthestSessionExp - nowUnixMs) / 1000.0);

                        if (furthestSessionTTL > 0)
                        {
                            await _cache.SetStringAsync(registryKey, JsonSerializer.Serialize(list), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(furthestSessionTTL) });

                            // 4. Verify the registry update succeeded (optimistic check)
                            var verifyJson = await _cache.GetStringAsync(registryKey);
                            if (!string.IsNullOrWhiteSpace(verifyJson))
                            {
                                var verifyList = JsonSerializer.Deserialize<List<SessionReference>>(verifyJson);
                                if (verifyList?.Any(s => s.Token == data.Token) == true)
                                {
                                    registryUpdated = true;
                                }
                            }
                        }
                        else
                        {
                            // No valid TTL, don't retry
                            break;
                        }
                    }

                    if (!registryUpdated)
                    {
                        _logger.LogWarning("Failed to update session registry for user {UserId} after {MaxRetries} attempts. Session {SessionId} will function but may not appear in RevokeAllSessionsAsync.", input.User.Id, maxRetries, data.Id);
                    }
                }

                // 5. Cache the Full Session + User Data (always attempt, independent of registry)
                var sessionTTL = (long)Math.Ceiling((sessionExpiryUnixMs - nowUnixMs) / 1000.0);
                if (sessionTTL > 0)
                {
                    var sessionCacheData = JsonSerializer.Serialize(new SessionCacheJson { Session = data.ToDto(), User = input.User.ToDto() });
                    await _cache.SetStringAsync(
                      data.Token,
                      sessionCacheData,
                      new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(sessionTTL) }
                    );
                }
            }

            _logger.SessionCreated(data.Id, input.User.Id);
            return data;
        }

        public async Task<Result> RevokeSessionAsync(SessionDeleteInput input)
        {
            var token = input.Token;
            _logger.SessionRevoking(token);

            // 1. Remove session from cache (immediately de-authenticates for incoming requests)
            if (_cache is not null)
            {
                await _cache.RemoveAsync(token);

                // 2. Update the active-sessions registry
                var registryKey = RegistryKeyPrefix + input.User.Id;
                var registryJson = await _cache.GetStringAsync(registryKey);

                if (string.IsNullOrWhiteSpace(registryJson) is false)
                {
                    List<SessionReference>? list = JsonSerializer.Deserialize<List<SessionReference>>(registryJson);
                    if (list is not null)
                    {
                        var nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        // Remove the revoked session and any expired ones
                        list = [.. list.Where(s => s.Token != token && s.ExpiresAt > nowUnixMs)];

                        if (list.Count == 0)
                        {
                            // No sessions left — delete the key entirely (Redis-friendly)
                            await _cache.RemoveAsync(registryKey);
                        }
                        else
                        {
                            // Recalculate TTL based on the furthest-expiring remaining session (round up)
                            list.Sort((a, b) => a.ExpiresAt.CompareTo(b.ExpiresAt));
                            var furthestExp = list[^1].ExpiresAt;
                            var ttlSeconds = (long)Math.Ceiling((furthestExp - nowUnixMs) / 1000.0);

                            if (ttlSeconds > 0)
                            {
                                await _cache.SetStringAsync(registryKey, JsonSerializer.Serialize(list),
                                  new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttlSeconds) });
                            }
                            else
                            {
                                await _cache.RemoveAsync(registryKey);
                            }
                        }
                    }
                }
            }

            // 3. Remove from database (record-keeping; user is already functionally signed out)
            if (_options.Session.StoreSessionInDatabase || _cache is null)
            {
                Session? dbSession = await _db.Sessions.FirstOrDefaultAsync(s => s.Token == token && s.UserId == input.User.Id);
                if (dbSession is not null)
                {
                    _db.Sessions.Remove(dbSession);
                    try
                    {
                        await _db.SaveChangesAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.SessionRevocationFailed(token, ex);
                        return Result.Failure(Constants.AuthErrors.System.InternalError, "Failed to revoke session.");
                    }
                }
            }

            _logger.SessionRevoked(token, input.User.Id);
            return Result.Success();
        }

        public async Task<Result> RevokeAllSessionsAsync(string userId)
        {
            _logger.SessionRevokingAll(userId);

            // 1. Remove all cached sessions via the registry
            if (_cache is not null)
            {
                var registryKey = RegistryKeyPrefix + userId;
                var registryJson = await _cache.GetStringAsync(registryKey);

                if (string.IsNullOrWhiteSpace(registryJson) is false)
                {
                    List<SessionReference>? list = JsonSerializer.Deserialize<List<SessionReference>>(registryJson);
                    if (list is not null)
                    {
                        // Remove each cached session
                        foreach (SessionReference entry in list)
                        {
                            await _cache.RemoveAsync(entry.Token);
                        }
                    }

                    // Delete the registry key itself
                    await _cache.RemoveAsync(registryKey);
                }
            }

            // 2. Remove all from database
            if (_options.Session.StoreSessionInDatabase || _cache is null)
            {
                List<Session> dbSessions = await _db.Sessions.Where(s => s.UserId == userId).ToListAsync();
                if (dbSessions.Count > 0)
                {
                    _db.Sessions.RemoveRange(dbSessions);
                    try
                    {
                        await _db.SaveChangesAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.SessionRevocationFailed(userId, ex);
                        return Result.Failure(Constants.AuthErrors.System.InternalError, "Failed to revoke sessions.");
                    }
                }
            }

            _logger.SessionRevokedAll(userId);
            return Result.Success();
        }
    }
}