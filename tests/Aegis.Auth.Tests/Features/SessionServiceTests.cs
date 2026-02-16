using System.Text.Json;

using Aegis.Auth.Constants;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Options;
using Aegis.Auth.Tests.Helpers;

using FluentAssertions;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

using Moq;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// Adversarial test suite for SessionService.
/// Focus: cache/DB consistency, expiration boundary conditions,
/// registry integrity, concurrent session manipulation.
/// </summary>
public sealed class SessionServiceTests : IDisposable
{
  private readonly ServiceTestFixture _fixture;
  private readonly SessionService _sut;

  // Cache storage: simulates a real distributed cache for precise control
  private readonly Dictionary<string, (string Value, DateTimeOffset? Expiry)> _cacheStore = new();

  public SessionServiceTests()
  {
    _fixture = new ServiceTestFixture();
    SetupCacheMock();
    _sut = new SessionService(
        _fixture.Options,
        _fixture.LoggerFactory,
        _fixture.DbContext,
        _fixture.CacheMock.Object);
  }

  public void Dispose() => _fixture.Dispose();

  private User CreateTestUser(string? id = null) => new()
  {
    Id = id ?? Guid.CreateVersion7().ToString(),
    Name = "Session Test User",
    Email = "session@test.com",
    CreatedAt = DateTime.UtcNow,
    UpdatedAt = DateTime.UtcNow,
  };

  /// <summary>
  /// Clones a User to break EF Core navigation tracking.
  /// Prevents circular reference (User -> Sessions -> User) during JSON serialization
  /// in SessionService.CreateSessionAsync.
  /// </summary>
  private static User CloneUser(User user) => new()
  {
    Id = user.Id,
    Name = user.Name,
    Email = user.Email,
    EmailVerified = user.EmailVerified,
    Image = user.Image,
    CreatedAt = user.CreatedAt,
    UpdatedAt = user.UpdatedAt,
  };

  private static SessionCreateInput CreateInput(User user, bool dontRemember = false) => new()
  {
    User = CloneUser(user),
    DontRememberMe = dontRemember,
    IpAddress = "10.0.0.1",
    UserAgent = "TestAgent/1.0",
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION CREATION — Happy path
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_ValidInput_ReturnsSession()
  {
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    result.Value.Should().NotBeNull();
    result.Value!.Token.Should().NotBeNullOrWhiteSpace();
    result.Value.UserId.Should().Be(user.Id);
  }

  [Fact]
  public async Task CreateSession_TokenIsExactly32Chars()
  {
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    result.Value!.Token.Should().HaveLength(32);
  }

  [Fact]
  public async Task CreateSession_TokenContainsOnlyAlphanumericChars()
  {
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    result.Value!.Token.Should().MatchRegex("^[a-zA-Z0-9]+$");
  }

  [Fact]
  public async Task CreateSession_TwoSessionsGetDifferentTokens()
  {
    var user = CreateTestUser();

    var result1 = await _sut.CreateSessionAsync(CreateInput(user));
    var result2 = await _sut.CreateSessionAsync(CreateInput(user));

    result1.Value!.Token.Should().NotBe(result2.Value!.Token,
        "each session must get a unique token");
  }

  [Fact]
  public async Task CreateSession_TwoSessionsGetDifferentIds()
  {
    var user = CreateTestUser();

    var result1 = await _sut.CreateSessionAsync(CreateInput(user));
    var result2 = await _sut.CreateSessionAsync(CreateInput(user));

    result1.Value!.Id.Should().NotBe(result2.Value!.Id);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EXPIRATION BOUNDARIES — DontRememberMe logic
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_DontRememberMe_ExpiresInOneDay()
  {
    var user = CreateTestUser();
    var before = DateTime.UtcNow;

    var result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: true));

    result.IsSuccess.Should().BeTrue();
    var expectedExpiry = before.AddDays(1);
    result.Value!.ExpiresAt.Should().BeCloseTo(expectedExpiry, TimeSpan.FromSeconds(5));
  }

  [Fact]
  public async Task CreateSession_RememberMe_ExpiresAtConfiguredDuration()
  {
    _fixture.Options.Session.ExpiresIn = 3600; // 1 hour
    var user = CreateTestUser();
    var before = DateTime.UtcNow;

    var result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

    result.IsSuccess.Should().BeTrue();
    var expectedExpiry = before.AddSeconds(3600);
    result.Value!.ExpiresAt.Should().BeCloseTo(expectedExpiry, TimeSpan.FromSeconds(5));
  }

  [Fact]
  public async Task CreateSession_ExpiresInZero_UsesDefault7Days()
  {
    _fixture.Options.Session.ExpiresIn = 0;
    var user = CreateTestUser();
    var before = DateTime.UtcNow;

    var result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

    result.IsSuccess.Should().BeTrue();
    var expectedExpiry = before.AddSeconds(604800); // 7 days default
    result.Value!.ExpiresAt.Should().BeCloseTo(expectedExpiry, TimeSpan.FromSeconds(5));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DATABASE PERSISTENCE
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_StoreInDatabase_PersistsSession()
  {
    _fixture.Options.Session.StoreSessionInDatabase = true;
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    var dbSession = _fixture.DbContext.Sessions.SingleOrDefault(s => s.Id == result.Value!.Id);
    dbSession.Should().NotBeNull();
    dbSession!.Token.Should().Be(result.Value!.Token);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CACHE INTERACTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_WithCache_StoresSessionInCache()
  {
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    // The cache should have the session token as a key
    _cacheStore.Should().ContainKey(result.Value!.Token);
  }

  [Fact]
  public async Task CreateSession_WithCache_StoresRegistryForUser()
  {
    var user = CreateTestUser();

    await _sut.CreateSessionAsync(CreateInput(user));

    var registryKey = $"active-sessions-{user.Id}";
    _cacheStore.Should().ContainKey(registryKey);
  }

  [Fact]
  public async Task CreateSession_WithCache_RegistryContainsNewSession()
  {
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user));

    var registryKey = $"active-sessions-{user.Id}";
    _cacheStore.Should().ContainKey(registryKey);
    var registryJson = _cacheStore[registryKey].Value;
    registryJson.Should().Contain(result.Value!.Token);
  }

  [Fact]
  public async Task CreateSession_MultipleSessions_RegistryContainsAll()
  {
    var user = CreateTestUser();

    var r1 = await _sut.CreateSessionAsync(CreateInput(user));
    var r2 = await _sut.CreateSessionAsync(CreateInput(user));

    var registryKey = $"active-sessions-{user.Id}";
    var registryJson = _cacheStore[registryKey].Value;
    var registry = JsonSerializer.Deserialize<List<JsonElement>>(registryJson)!;
    registry.Count.Should().BeGreaterThanOrEqualTo(2);
    registryJson.Should().Contain(r1.Value!.Token);
    registryJson.Should().Contain(r2.Value!.Token);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // NO CACHE — Falls back to DB only
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_NullCache_StillPersistsToDatabase()
  {
    var noCacheSut = new SessionService(
        _fixture.Options,
        _fixture.LoggerFactory,
        _fixture.DbContext,
        disCache: null);

    var user = CreateTestUser();
    var result = await noCacheSut.CreateSessionAsync(CreateInput(user));

    result.IsSuccess.Should().BeTrue();
    _fixture.DbContext.Sessions.Should().Contain(s => s.Id == result.Value!.Id);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REVOKE SESSION
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task RevokeSession_ValidToken_ReturnsSuccess()
  {
    var user = CreateTestUser();
    var session = await CreateAndPersistSessionAsync(user);

    var result = await _sut.RevokeSessionAsync(new SessionDeleteInput
    {
      User = user,
      Token = session.Token,
    });

    result.IsSuccess.Should().BeTrue();
  }

  [Fact]
  public async Task RevokeSession_RemovesFromCache()
  {
    var user = CreateTestUser();
    var session = await CreateAndPersistSessionAsync(user);
    _cacheStore.Should().ContainKey(session.Token);

    await _sut.RevokeSessionAsync(new SessionDeleteInput
    {
      User = user,
      Token = session.Token,
    });

    _cacheStore.Should().NotContainKey(session.Token);
  }

  [Fact]
  public async Task RevokeSession_RemovesFromDatabase()
  {
    var user = CreateTestUser();
    var session = await CreateAndPersistSessionAsync(user);

    await _sut.RevokeSessionAsync(new SessionDeleteInput
    {
      User = user,
      Token = session.Token,
    });

    _fixture.DbContext.Sessions.Should().NotContain(s => s.Token == session.Token);
  }

  [Fact]
  public async Task RevokeSession_RemovesFromRegistry()
  {
    var user = CreateTestUser();
    var session = await CreateAndPersistSessionAsync(user);
    var registryKey = $"active-sessions-{user.Id}";
    _cacheStore.Should().ContainKey(registryKey);

    await _sut.RevokeSessionAsync(new SessionDeleteInput
    {
      User = user,
      Token = session.Token,
    });

    // Registry should be removed entirely when it's the only session
    if (_cacheStore.ContainsKey(registryKey))
    {
      var registryJson = _cacheStore[registryKey].Value;
      registryJson.Should().NotContain(session.Token);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REVOKE ALL SESSIONS
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task RevokeAllSessions_RemovesAllFromCacheAndDb()
  {
    var user = CreateTestUser();
    var s1 = await CreateAndPersistSessionAsync(user);
    var s2 = await CreateAndPersistSessionAsync(user);

    var result = await _sut.RevokeAllSessionsAsync(user.Id);

    result.IsSuccess.Should().BeTrue();

    // Cache should not contain either session token
    _cacheStore.Should().NotContainKey(s1.Token);
    _cacheStore.Should().NotContainKey(s2.Token);

    // Registry should be gone
    _cacheStore.Should().NotContainKey($"active-sessions-{user.Id}");

    // DB should be clean
    _fixture.DbContext.Sessions.Where(s => s.UserId == user.Id).Should().BeEmpty();
  }

  [Fact]
  public async Task RevokeAllSessions_NoSessions_StillReturnsSuccess()
  {
    var user = CreateTestUser();

    var result = await _sut.RevokeAllSessionsAsync(user.Id);

    result.IsSuccess.Should().BeTrue();
  }

  [Fact]
  public async Task RevokeAllSessions_DoesNotAffectOtherUsers()
  {
    var user1 = CreateTestUser("user-1");
    var user2 = CreateTestUser("user-2");

    var s1 = await CreateAndPersistSessionAsync(user1);
    var s2 = await CreateAndPersistSessionAsync(user2);

    await _sut.RevokeAllSessionsAsync(user1.Id);

    // User2's session should still exist
    _cacheStore.Should().ContainKey(s2.Token);
    _fixture.DbContext.Sessions.Should().Contain(s => s.UserId == user2.Id);

    // User1's should be gone
    _cacheStore.Should().NotContainKey(s1.Token);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TIMESTAMP INVARIANTS
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_TimestampsAreUtcNow()
  {
    var user = CreateTestUser();
    var before = DateTime.UtcNow.AddSeconds(-1);

    var result = await _sut.CreateSessionAsync(CreateInput(user));
    var after = DateTime.UtcNow.AddSeconds(1);

    result.Value!.CreatedAt.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
    result.Value.UpdatedAt.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
  }

  [Fact]
  public async Task CreateSession_IpAddressAndUserAgentStored()
  {
    var user = CreateTestUser();
    var input = new SessionCreateInput
    {
      User = user,
      DontRememberMe = false,
      IpAddress = "203.0.113.42",
      UserAgent = "CustomBot/2.0",
    };

    var result = await _sut.CreateSessionAsync(input);

    result.Value!.IpAddress.Should().Be("203.0.113.42");
    result.Value.UserAgent.Should().Be("CustomBot/2.0");
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EDGE: Extremely short ExpiresIn (1 second)
  // ═══════════════════════════════════════════════════════════════════════════

  [Fact]
  public async Task CreateSession_ExpiresInOneSecond_SessionStillCreated()
  {
    _fixture.Options.Session.ExpiresIn = 1;
    var user = CreateTestUser();

    var result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

    result.IsSuccess.Should().BeTrue();
    result.Value!.ExpiresAt.Should().BeCloseTo(DateTime.UtcNow.AddSeconds(1), TimeSpan.FromSeconds(3));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CACHE MOCK SETUP — In-memory dictionary simulating distributed cache
  // ═══════════════════════════════════════════════════════════════════════════

  private void SetupCacheMock()
  {
    _fixture.CacheMock
        .Setup(c => c.SetAsync(
            It.IsAny<string>(),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()))
        .Returns<string, byte[], DistributedCacheEntryOptions, CancellationToken>((key, value, options, _) =>
        {
          var str = System.Text.Encoding.UTF8.GetString(value);
          DateTimeOffset? expiry = options.AbsoluteExpirationRelativeToNow.HasValue
                  ? DateTimeOffset.UtcNow.Add(options.AbsoluteExpirationRelativeToNow.Value)
                  : options.AbsoluteExpiration;
          _cacheStore[key] = (str, expiry);
          return Task.CompletedTask;
        });

    _fixture.CacheMock
        .Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
        .Returns<string, CancellationToken>((key, _) =>
        {
          if (_cacheStore.TryGetValue(key, out var entry))
          {
            // Simulate expiry
            if (entry.Expiry.HasValue && entry.Expiry.Value <= DateTimeOffset.UtcNow)
            {
              _cacheStore.Remove(key);
              return Task.FromResult<byte[]?>(null);
            }
            return Task.FromResult<byte[]?>(System.Text.Encoding.UTF8.GetBytes(entry.Value));
          }
          return Task.FromResult<byte[]?>(null);
        });

    _fixture.CacheMock
        .Setup(c => c.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
        .Returns<string, CancellationToken>((key, _) =>
        {
          _cacheStore.Remove(key);
          return Task.CompletedTask;
        });
  }

  private async Task<Session> CreateAndPersistSessionAsync(User user)
  {
    // Ensure user is in the DB for FK constraints
    if (!_fixture.DbContext.Users.Any(u => u.Id == user.Id))
    {
      _fixture.DbContext.Users.Add(user);
      await _fixture.DbContext.SaveChangesAsync();
    }

    // Pass a cloned (untracked) user to avoid EF navigation cycles
    // that cause JsonSerializer circular reference errors
    var result = await _sut.CreateSessionAsync(CreateInput(user));
    result.IsSuccess.Should().BeTrue();
    return result.Value!;
  }
}
