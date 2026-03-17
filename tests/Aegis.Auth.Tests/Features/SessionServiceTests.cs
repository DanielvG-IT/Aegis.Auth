using System.Text.Json;

using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Extensions.Caching.Distributed;

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
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
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
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.False(string.IsNullOrWhiteSpace(result.Value!.Token));
        Assert.Equal(user.Id, result.Value.UserId);
    }

    [Fact]
    public async Task CreateSession_TokenIsExactly32Chars()
    {
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess);
        Assert.Equal(32, result.Value!.Token.Length);
    }

    [Fact]
    public async Task CreateSession_TokenContainsOnlyAlphanumericChars()
    {
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess);
        Assert.Matches("^[a-zA-Z0-9]+$", result.Value!.Token);
    }

    [Fact]
    public async Task CreateSession_TwoSessionsGetDifferentTokens()
    {
        User user = CreateTestUser();

        Result<Session> result1 = await _sut.CreateSessionAsync(CreateInput(user));
        Result<Session> result2 = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.NotEqual(result2.Value!.Token, result1.Value!.Token);
    }

    [Fact]
    public async Task CreateSession_TwoSessionsGetDifferentIds()
    {
        User user = CreateTestUser();

        Result<Session> result1 = await _sut.CreateSessionAsync(CreateInput(user));
        Result<Session> result2 = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.NotEqual(result2.Value!.Id, result1.Value!.Id);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EXPIRATION BOUNDARIES — DontRememberMe logic
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_DontRememberMe_ExpiresInOneDay()
    {
        User user = CreateTestUser();
        DateTime before = DateTime.UtcNow;

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: true));

        Assert.True(result.IsSuccess);
        DateTime expectedExpiry = before.AddDays(1);
        Assert.InRange(result.Value!.ExpiresAt, expectedExpiry - TimeSpan.FromSeconds(5), expectedExpiry + TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task CreateSession_RememberMe_ExpiresAtConfiguredDuration()
    {
        _fixture.Options.Session.ExpiresIn = 3600; // 1 hour
        User user = CreateTestUser();
        DateTime before = DateTime.UtcNow;

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

        Assert.True(result.IsSuccess);
        DateTime expectedExpiry = before.AddSeconds(3600);
        Assert.InRange(result.Value!.ExpiresAt, expectedExpiry - TimeSpan.FromSeconds(5), expectedExpiry + TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task CreateSession_ExpiresInZero_UsesDefault7Days()
    {
        _fixture.Options.Session.ExpiresIn = 0;
        User user = CreateTestUser();
        DateTime before = DateTime.UtcNow;

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

        Assert.True(result.IsSuccess);
        DateTime expectedExpiry = before.AddSeconds(604800); // 7 days default
        Assert.InRange(result.Value!.ExpiresAt, expectedExpiry - TimeSpan.FromSeconds(5), expectedExpiry + TimeSpan.FromSeconds(5));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DATABASE PERSISTENCE
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_StoreInDatabase_PersistsSession()
    {
        _fixture.Options.Session.StoreSessionInDatabase = true;
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess); Session? dbSession = _fixture.DbContext.Sessions.SingleOrDefault(s => s.Id == result.Value!.Id);
        Assert.NotNull(dbSession);
        Assert.Equal(result.Value!.Token, dbSession!.Token);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CACHE INTERACTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_WithCache_StoresSessionInCache()
    {
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess);        // The cache should have the session token as a key
        Assert.True(_cacheStore.ContainsKey(result.Value!.Token));
    }

    [Fact]
    public async Task CreateSession_WithCache_StoresRegistryForUser()
    {
        User user = CreateTestUser();

        await _sut.CreateSessionAsync(CreateInput(user));

        var registryKey = $"active-sessions-{user.Id}";
        Assert.True(_cacheStore.ContainsKey(registryKey));
    }

    [Fact]
    public async Task CreateSession_WithCache_RegistryContainsNewSession()
    {
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));

        var registryKey = $"active-sessions-{user.Id}";
        Assert.True(_cacheStore.ContainsKey(registryKey)); var registryJson = _cacheStore[registryKey].Value;
        Assert.Contains(result.Value!.Token, registryJson);
    }

    [Fact]
    public async Task CreateSession_MultipleSessions_RegistryContainsAll()
    {
        User user = CreateTestUser();

        Result<Session> r1 = await _sut.CreateSessionAsync(CreateInput(user));
        Result<Session> r2 = await _sut.CreateSessionAsync(CreateInput(user));

        var registryKey = $"active-sessions-{user.Id}";
        var registryJson = _cacheStore[registryKey].Value;
        List<JsonElement> registry = JsonSerializer.Deserialize<List<JsonElement>>(registryJson)!;
        Assert.True(registry.Count >= 2);
        Assert.Contains(r1.Value!.Token, registryJson);
        Assert.Contains(r2.Value!.Token, registryJson);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // NO CACHE — Falls back to DB only
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_NullCache_StillPersistsToDatabase()
    {
        var noCacheSut = new SessionService(
            Microsoft.Extensions.Options.Options.Create(_fixture.Options),
            _fixture.LoggerFactory,
            _fixture.DbContext,
            disCache: null);

        User user = CreateTestUser();
        Result<Session> result = await noCacheSut.CreateSessionAsync(CreateInput(user));

        Assert.True(result.IsSuccess);
        Assert.Contains(_fixture.DbContext.Sessions, s => s.Id == result.Value!.Id);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REVOKE SESSION
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RevokeSession_ValidToken_ReturnsSuccess()
    {
        User user = CreateTestUser();
        Session session = await CreateAndPersistSessionAsync(user);

        Result result = await _sut.RevokeSessionAsync(new SessionDeleteInput
        {
            User = user,
            Token = session.Token,
        });

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RevokeSession_RemovesFromCache()
    {
        User user = CreateTestUser();
        Session session = await CreateAndPersistSessionAsync(user);
        Assert.True(_cacheStore.ContainsKey(session.Token));
        await _sut.RevokeSessionAsync(new SessionDeleteInput
        {
            User = user,
            Token = session.Token,
        });

        Assert.False(_cacheStore.ContainsKey(session.Token));
    }

    [Fact]
    public async Task RevokeSession_RemovesFromDatabase()
    {
        User user = CreateTestUser();
        Session session = await CreateAndPersistSessionAsync(user);

        await _sut.RevokeSessionAsync(new SessionDeleteInput
        {
            User = user,
            Token = session.Token,
        });

        Assert.DoesNotContain(_fixture.DbContext.Sessions, s => s.Token == session.Token);
    }

    [Fact]
    public async Task RevokeSession_RemovesFromRegistry()
    {
        User user = CreateTestUser();
        Session session = await CreateAndPersistSessionAsync(user);
        var registryKey = $"active-sessions-{user.Id}";
        Assert.True(_cacheStore.ContainsKey(registryKey));
        await _sut.RevokeSessionAsync(new SessionDeleteInput
        {
            User = user,
            Token = session.Token,
        });

        // Registry should be removed entirely when it's the only session
        if (_cacheStore.TryGetValue(registryKey, out (string Value, DateTimeOffset? Expiry) value))
        {
            var registryJson = value.Value;
            Assert.DoesNotContain(session.Token, registryJson);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REVOKE ALL SESSIONS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task RevokeAllSessions_RemovesAllFromCacheAndDb()
    {
        User user = CreateTestUser();
        Session s1 = await CreateAndPersistSessionAsync(user);
        Session s2 = await CreateAndPersistSessionAsync(user);

        Result result = await _sut.RevokeAllSessionsAsync(user.Id);

        Assert.True(result.IsSuccess);
        // Cache should not contain either session token
        Assert.False(_cacheStore.ContainsKey(s1.Token));
        Assert.False(_cacheStore.ContainsKey(s2.Token));
        // Registry should be gone
        Assert.False(_cacheStore.ContainsKey($"active-sessions-{user.Id}"));
        // DB should be clean
        Assert.Empty(_fixture.DbContext.Sessions.Where(s => s.UserId == user.Id));
    }

    [Fact]
    public async Task RevokeAllSessions_NoSessions_StillReturnsSuccess()
    {
        User user = CreateTestUser();

        Result result = await _sut.RevokeAllSessionsAsync(user.Id);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task RevokeAllSessions_DoesNotAffectOtherUsers()
    {
        User user1 = CreateTestUser("user-1");
        User user2 = CreateTestUser("user-2");

        Session s1 = await CreateAndPersistSessionAsync(user1);
        Session s2 = await CreateAndPersistSessionAsync(user2);

        await _sut.RevokeAllSessionsAsync(user1.Id);

        // User2's session should still exist
        Assert.True(_cacheStore.ContainsKey(s2.Token));
        Assert.Contains(_fixture.DbContext.Sessions, s => s.UserId == user2.Id);
        // User1's should be gone
        Assert.False(_cacheStore.ContainsKey(s1.Token));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TIMESTAMP INVARIANTS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_TimestampsAreUtcNow()
    {
        User user = CreateTestUser();
        DateTime before = DateTime.UtcNow.AddSeconds(-1);

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));
        DateTime after = DateTime.UtcNow.AddSeconds(1);

        Assert.InRange(result.Value!.CreatedAt, before, after);
        Assert.InRange(result.Value.UpdatedAt, before, after);
    }

    [Fact]
    public async Task CreateSession_IpAddressAndUserAgentStored()
    {
        User user = CreateTestUser();
        var input = new SessionCreateInput
        {
            User = user,
            DontRememberMe = false,
            IpAddress = "203.0.113.42",
            UserAgent = "CustomBot/2.0",
        };

        Result<Session> result = await _sut.CreateSessionAsync(input);

        Assert.Equal("203.0.113.42", result.Value!.IpAddress);
        Assert.Equal("CustomBot/2.0", result.Value.UserAgent);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EDGE: Extremely short ExpiresIn (1 second)
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CreateSession_ExpiresInOneSecond_SessionStillCreated()
    {
        _fixture.Options.Session.ExpiresIn = 1;
        User user = CreateTestUser();

        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user, dontRemember: false));

        Assert.True(result.IsSuccess);
        DateTime expectedExpiry = DateTime.UtcNow.AddSeconds(1);
        Assert.InRange(result.Value!.ExpiresAt, expectedExpiry - TimeSpan.FromSeconds(3), expectedExpiry + TimeSpan.FromSeconds(3));
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
                if (_cacheStore.TryGetValue(key, out (string Value, DateTimeOffset? Expiry) entry))
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
        Result<Session> result = await _sut.CreateSessionAsync(CreateInput(user));
        Assert.True(result.IsSuccess); return result.Value!;
    }
}
