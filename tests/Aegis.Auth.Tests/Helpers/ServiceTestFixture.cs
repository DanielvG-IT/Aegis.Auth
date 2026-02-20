using Aegis.Auth.Entities;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

using Moq;

namespace Aegis.Auth.Tests.Helpers;

/// <summary>
/// Provides a consistent, pre-configured test fixture for service-level tests.
/// All mocks are STRICT by default to catch unexpected interactions.
/// </summary>
internal sealed class ServiceTestFixture : IDisposable
{
    public TestDbContext DbContext { get; }
    public Mock<IDistributedCache> CacheMock { get; }
    public ILoggerFactory LoggerFactory { get; }
    public AegisAuthOptions Options { get; }

    private static int _dbCounter;

    public ServiceTestFixture(Action<AegisAuthOptions>? configureOptions = null)
    {
        // Unique in-memory DB per fixture to avoid cross-test contamination
        var dbName = $"AegisTest_{Interlocked.Increment(ref _dbCounter)}_{Guid.NewGuid():N}";
        DbContextOptions<TestDbContext> dbOptions = new DbContextOptionsBuilder<TestDbContext>()
        .UseInMemoryDatabase(dbName)
        .Options;

        DbContext = new TestDbContext(dbOptions);
        DbContext.Database.EnsureCreated();

        CacheMock = new Mock<IDistributedCache>(MockBehavior.Strict);
        LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.None));

        Options = new AegisAuthOptions
        {
            AppName = "AegisTest",
            BaseURL = "https://test.example.com",
            Secret = "test-secret-that-is-long-enough-for-hmac-256-operations!!",
            EmailAndPassword = new EmailAndPasswordOptions
            {
                Enabled = true,
                AutoSignIn = true,
                MinPasswordLength = 8,
                MaxPasswordLength = 128,
                Password = new PasswordOptions
                {
                    Hash = password => Task.FromResult($"hashed:{password}"),
                    Verify = ctx => Task.FromResult(ctx.Hash == $"hashed:{ctx.Password}"),
                }
            },
            Session = new SessionOptions
            {
                ExpiresIn = 604800, // 7 days
                StoreSessionInDatabase = true,
            }
        };

        configureOptions?.Invoke(Options);
    }

    /// <summary>
    /// Seeds a user + credential account into the in-memory DB.
    /// Returns the (User, Account) pair.
    /// </summary>
    public async Task<(User user, Account account)> SeedUserAsync(
        string email = "existing@test.com",
        string password = "ValidPass123!",
        string? name = "Test User")
    {
        DateTime now = DateTime.UtcNow;
        var hashedPassword = await Options.EmailAndPassword.Password.Hash(password);

        var user = new User
        {
            Id = Guid.CreateVersion7().ToString(),
            Name = name ?? string.Empty,
            Email = email,
            CreatedAt = now,
            UpdatedAt = now,
        };

        var account = new Account
        {
            Id = Guid.CreateVersion7().ToString(),
            AccountId = email,
            UserId = user.Id,
            ProviderId = "credential",
            PasswordHash = hashedPassword,
            CreatedAt = now,
            UpdatedAt = now,
        };

        DbContext.Users.Add(user);
        DbContext.Accounts.Add(account);
        await DbContext.SaveChangesAsync();

        return (user, account);
    }

    /// <summary>
    /// Seeds a user with NO credential account (simulates OAuth-only user).
    /// </summary>
    public async Task<User> SeedOAuthOnlyUserAsync(string email = "oauth@test.com")
    {
        DateTime now = DateTime.UtcNow;
        var user = new User
        {
            Id = Guid.CreateVersion7().ToString(),
            Name = "OAuth User",
            Email = email,
            CreatedAt = now,
            UpdatedAt = now,
        };

        var account = new Account
        {
            Id = Guid.CreateVersion7().ToString(),
            AccountId = email,
            UserId = user.Id,
            ProviderId = "google", // OAuth, not "credential"
            CreatedAt = now,
            UpdatedAt = now,
        };

        DbContext.Users.Add(user);
        DbContext.Accounts.Add(account);
        await DbContext.SaveChangesAsync();

        return user;
    }

    /// <summary>
    /// Seeds a user whose credential account has a null/empty password hash.
    /// </summary>
    public async Task<User> SeedUserWithNullPasswordHashAsync(string email = "nohash@test.com")
    {
        DateTime now = DateTime.UtcNow;
        var user = new User
        {
            Id = Guid.CreateVersion7().ToString(),
            Name = "No Hash User",
            Email = email,
            CreatedAt = now,
            UpdatedAt = now,
        };

        var account = new Account
        {
            Id = Guid.CreateVersion7().ToString(),
            AccountId = email,
            UserId = user.Id,
            ProviderId = "credential",
            PasswordHash = null, // Explicitly null
            CreatedAt = now,
            UpdatedAt = now,
        };

        DbContext.Users.Add(user);
        DbContext.Accounts.Add(account);
        await DbContext.SaveChangesAsync();

        return user;
    }

    public void Dispose()
    {
        DbContext.Database.EnsureDeleted();
        DbContext.Dispose();
        LoggerFactory.Dispose();
    }
}
