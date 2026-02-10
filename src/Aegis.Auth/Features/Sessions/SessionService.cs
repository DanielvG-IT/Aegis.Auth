using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.Extensions.Caching.Distributed;

namespace Aegis.Auth.Features.Sessions
{
  public interface ISessionService
  {
    Task<Result<Session>> CreateSessionAsync(SessionCreateInput input);
  }

  internal sealed class SessionService(AegisAuthOptions options, IAuthDbContext dbContext, IDistributedCache disCache) : ISessionService
  {
    private readonly AegisAuthOptions _options = options;
    private readonly IDistributedCache _cache = disCache;
    private readonly IAuthDbContext _db = dbContext;

    public async Task<Result<Session>> CreateSessionAsync(SessionCreateInput input)
    {
      var storeInDb = _options.Session.StoreSessionInDatabase;
      var sessionExpiration = _options.Session.ExpiresIn != 0 ? _options.Session.ExpiresIn : 60 * 60 * 24 * 7; // 7 days in seconds

      var data = new Session
      {
        IpAddress = input.IpAddress,
        UserAgent = input.UserAgent,

        // If the user doesn't want to be remembered, set the session to expire in 1 day.
        // The cookie will be set to expire at the end of the session
        ExpiresAt = input.DontRememberMe ? DateTime.UtcNow.AddDays(1) : DateTime.UtcNow.AddSeconds(sessionExpiration),
        UserId = input.User.Id,
        User = input.User,
        Token = RandomStringGenerator.Generate(32, "a-z", "A-Z", "0-9"),
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
        // Possible override values later here
      };
      var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

      // Always store in SecondaryStorage when available, 
      if (_options.SecondaryStorage is not null)
      {
        // 1. Fetch the current session list for the user
        var registryKey = $"active-sessions-{input.User.Id}";
        var currentListJson = await _cache.GetStringAsync(registryKey);

        List<SessionReference> list = [];
        if (!string.IsNullOrWhiteSpace(currentListJson))
        {
          // Deserialize from cache
          list = JsonSerializer.Deserialize<List<SessionReference>>(currentListJson) ?? [];
          // Filter: remove expired and duplicates
          list = [.. list.Where(s => s.ExpiresAt > now && s.Token != data.Token)];
        }

        // 2. Add new session and Sort to find the furthest expiry
        list.Add(new SessionReference { Token = data.Token, ExpiresAt = new DateTimeOffset(data.ExpiresAt).ToUnixTimeMilliseconds() });
        list = [.. list.OrderBy(s => s.ExpiresAt)];

        // 3. Calculate TTL for the Registry
        var furthestSessionExp = list.LastOrDefault()?.ExpiresAt ?? now;
        var furthestSessionTTL = (furthestSessionExp - now) / 1000; // Convert to seconds

        if (furthestSessionTTL > 0)
        {
          await _cache.SetStringAsync(registryKey, JsonSerializer.Serialize(list), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(furthestSessionTTL) });
        }

        // 4. Cache the Full Session + User Data
        var sessionTTL = (new DateTimeOffset(data.ExpiresAt).ToUnixTimeMilliseconds() - now) / 1000;
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
      if (_options.Session.StoreSessionInDatabase || _options.SecondaryStorage is null)
      {
        await _db.Sessions.AddAsync(data);
        await _db.SaveChangesAsync();
      }

      return data;
    }
  }
}