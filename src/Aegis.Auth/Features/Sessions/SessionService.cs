using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.Extensions.Caching.Distributed;
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

      var now = DateTime.UtcNow;
      var nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

      var data = new Session
      {
        Id = Guid.CreateVersion7().ToString(),
        IpAddress = input.IpAddress,
        UserAgent = input.UserAgent,

        // If the user doesn't want to be remembered, set the session to expire in 1 day.
        // The cookie will be set to expire at the end of the session
        ExpiresAt = input.DontRememberMe ? now.AddDays(1) : now.AddSeconds(sessionExpiration),
        UserId = input.User.Id,
        User = input.User,
        Token = RandomStringGenerator.Generate(32, "a-z", "A-Z", "0-9"),
        CreatedAt = now,
        UpdatedAt = now,
        // Possible override values later here
      };

      // Always store in SecondaryStorage when available, 
      if (_cache is not null)
      {
        // 1. Fetch the current session list for the user
        var registryKey = RegistryKeyPrefix + input.User.Id;
        var currentListJson = await _cache.GetStringAsync(registryKey);

        List<SessionReference> list = [];
        if (string.IsNullOrWhiteSpace(currentListJson) is false)
        {
          // Deserialize from cache
          List<SessionReference>? cachedList = JsonSerializer.Deserialize<List<SessionReference>>(currentListJson);
          if (cachedList is not null)
          {
            // Filter: remove expired and duplicates (in-place to avoid extra allocation)
            list = [.. cachedList.Where(s => s.ExpiresAt > nowUnixMs && s.Token != data.Token)];
          }
        }

        // 2. Add new session and Sort to find the furthest expiry
        list.Add(new SessionReference { Token = data.Token, ExpiresAt = new DateTimeOffset(data.ExpiresAt).ToUnixTimeMilliseconds() });
        list.Sort((a, b) => a.ExpiresAt.CompareTo(b.ExpiresAt)); // In-place sort, more efficient

        // 3. Calculate TTL for the Registry
        var furthestSessionExp = list.LastOrDefault()?.ExpiresAt ?? nowUnixMs;
        var furthestSessionTTL = (furthestSessionExp - nowUnixMs) / 1000; // Convert to seconds

        if (furthestSessionTTL > 0)
        {
          await _cache.SetStringAsync(registryKey, JsonSerializer.Serialize(list), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(furthestSessionTTL) });
        }

        // 4. Cache the Full Session + User Data
        var sessionTTL = (new DateTimeOffset(data.ExpiresAt).ToUnixTimeMilliseconds() - nowUnixMs) / 1000;
        if (sessionTTL > 0)
        {
          var sessionCacheData = JsonSerializer.Serialize(new SessionCacheJson { Session = data, User = input.User });
          await _cache.SetStringAsync(
            data.Token,
            sessionCacheData,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(sessionTTL) }
          );
        }
      }

      // if enabled or no SecondaryStorage (also) store in DB 
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

      _logger.SessionCreated(data.Id, input.User.Id);
      return data;
    }

    // After you remove a token from the list, check if the list is count == 0. 
    // If so, Remove the key instead of Set an empty array. Redis loves it when you delete keys; 
    // + it keeps the memory footprint tiny.

    /*
      Cache First: Kill the session in Redis. This immediately "de-authenticates" the user for any incoming requests hitting the middleware.
      Cookie Second: Tell the browser to nuke the cookie. TODO: Dont know how though
      Registry/DB Last: These are for "record keeping." If these fail, the user is still functionally logged out because the Cache and Cookie are gone.
    */
    /*
      Can you implement the Registry cleanup so that it recalculates the TTL of the Registry key based on the next expiring session? 
      If Session A expires in 1 hour and Session B in 7 days, and you delete Session B, the Redis Registry key for that user should automatically have its TTL reduced to 1 hour. 
    */
    public Task<Result> RevokeSessionAsync(SessionDeleteInput input)
    {
      var registryKey = RegistryKeyPrefix + input.User.Id;
      throw new NotImplementedException();
      // Result.Success()
    }

    public async Task<Result> RevokeAllSessionsAsync(string userId)
    {
      var registryKey = RegistryKeyPrefix + userId;
      throw new NotImplementedException();
      // Result.Success()
    }
  }
}