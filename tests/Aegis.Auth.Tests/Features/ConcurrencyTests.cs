using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Features.PasswordReset;
using Aegis.Auth.Features.RateLimit;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Infrastructure.Tokens;
using Aegis.Auth.Tests.Helpers;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

using Moq;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// Parallel requests against a real database file, each with its own DbContext like separate HTTP requests.
/// Guards against read-check-write races on single-use tokens and the failed sign-in counter (#121).
/// </summary>
public sealed class ConcurrencyTests : IDisposable
{
    private const int Parallelism = 20;
    private const string Email = "race@test.com";

    private readonly SqliteFileDatabase _database = new();
    private readonly ServiceTestFixture _fixture = new();
    private readonly ServiceProvider _services = new ServiceCollection().BuildServiceProvider();
    private readonly Mock<ISessionService> _sessionMock = new(MockBehavior.Strict);

    public ConcurrencyTests()
    {
        _fixture.Options.EmailAndPassword.SendResetPassword = (_, _) => Task.CompletedTask;
        _fixture.Options.EmailVerification.SendVerificationEmail = (_, _) => Task.CompletedTask;
        _sessionMock
            .Setup(s => s.RevokeAllSessionsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
    }

    public void Dispose()
    {
        _services.Dispose();
        _fixture.Dispose();
        _database.Dispose();
    }

    [Fact]
    public async Task ResetPassword_ParallelRedemptionsOfOneToken_ExactlyOneWins()
    {
        var userId = await SeedUserAsync();
        string rawToken;
        await using (TestDbContext db = _database.CreateContext())
        {
            rawToken = await CreatePasswordResetService(db).GenerateResetTokenAsync(userId);
        }

        var results = await RunInParallelAsync(async (db, i) =>
            (Index: i, Result: await CreatePasswordResetService(db).ResetPasswordAsync(rawToken, $"RacePassword{i:D2}!")));

        var winner = Assert.Single(results, r => r.Result.IsSuccess);
        Assert.All(results.Where(r => r.Result.IsSuccess is false), r => Assert.Equal(AuthErrors.Token.InvalidToken, r.Result.ErrorCode));
        await using TestDbContext check = _database.CreateContext();
        Account account = await check.Accounts.SingleAsync(a => a.UserId == userId);
        Assert.Equal($"hashed:RacePassword{winner.Index:D2}!", account.PasswordHash);
        Assert.NotNull((await check.AuthTokens.SingleAsync(t => t.TokenHash == AegisCrypto.HashToken(rawToken))).ConsumedAt);
    }

    [Fact]
    public async Task VerifyEmail_ParallelRedemptionsOfOneToken_ExactlyOneWins()
    {
        var userId = await SeedUserAsync();
        string rawToken;
        await using (TestDbContext db = _database.CreateContext())
        {
            rawToken = await CreateEmailVerificationService(db).GenerateVerificationTokenAsync(userId);
        }

        var results = await RunInParallelAsync((db, _) => CreateEmailVerificationService(db).VerifyEmailAsync(rawToken));

        Assert.Single(results, r => r.IsSuccess);
        Assert.All(results.Where(r => r.IsSuccess is false), r => Assert.Equal(AuthErrors.Token.InvalidToken, r.ErrorCode));
        await using TestDbContext check = _database.CreateContext();
        Assert.True((await check.Users.SingleAsync(u => u.Id == userId)).EmailVerified);
    }

    [Fact]
    public async Task SignIn_ParallelWrongPasswords_ReachLockout()
    {
        _fixture.Options.AccountLockout.Enabled = true;
        _fixture.Options.AccountLockout.MaxFailedAttempts = 10;
        _fixture.Options.AccountLockout.LockoutDuration = TimeSpan.FromMinutes(15);
        // The per-email rate limit would otherwise stop most of these attempts before the lockout counts them.
        _fixture.Options.RateLimit.Enabled = false;
        using var rateLimit = new RateLimitService(Microsoft.Extensions.Options.Options.Create(_fixture.Options));
        var userId = await SeedUserAsync();

        var results = await RunInParallelAsync((db, _) =>
            CreateSignInService(db, rateLimit).SignInEmail(SignInInput("WrongPassword!")));

        Assert.All(results, r => Assert.False(r.IsSuccess));
        await using TestDbContext check = _database.CreateContext();
        Assert.NotNull((await check.Users.SingleAsync(u => u.Id == userId)).LockoutUntil);
        Result<SignInResult> correct = await CreateSignInService(check, rateLimit)
            .SignInEmail(SignInInput("ValidPass123!"));
        Assert.Equal(AuthErrors.Identity.AccountLocked, correct.ErrorCode);
    }

    [Fact]
    public async Task TryConsume_DependentWriteFails_LeavesTokenUnused()
    {
        var userId = await SeedUserAsync();
        string rawToken;
        await using (TestDbContext db = _database.CreateContext())
        {
            rawToken = await CreatePasswordResetService(db).GenerateResetTokenAsync(userId);
        }

        var tokenHash = AegisCrypto.HashToken(rawToken);
        await using (TestDbContext db = _database.CreateContext())
        {
            var store = new AuthTokenStore(db);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.TryConsumeAsync(
                tokenHash,
                PasswordResetService.TokenPurpose,
                _ => throw new InvalidOperationException("dependent write failed")));
        }

        await using (TestDbContext db = _database.CreateContext())
        {
            Assert.Null((await db.AuthTokens.SingleAsync(t => t.TokenHash == tokenHash)).ConsumedAt);
            Assert.True(await new AuthTokenStore(db).TryConsumeAsync(tokenHash, PasswordResetService.TokenPurpose, _ => Task.CompletedTask));
        }
    }

    /// <summary>Starts all requests together, each on its own DbContext.</summary>
    private async Task<T[]> RunInParallelAsync<T>(Func<TestDbContext, int, Task<T>> request)
    {
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<T>[] tasks = [.. Enumerable.Range(0, Parallelism).Select(i => Task.Run(async () =>
        {
            await using TestDbContext db = _database.CreateContext();
            await start.Task;
            return await request(db, i);
        }))];

        start.SetResult();
        return await Task.WhenAll(tasks);
    }

    private static SignInEmailInput SignInInput(string password) =>
        new() { Email = Email, Password = password, UserAgent = "TestAgent/1.0", IpAddress = "10.0.0.1" };

    private async Task<string> SeedUserAsync()
    {
        DateTime now = DateTime.UtcNow;
        var user = new User { Id = Guid.CreateVersion7().ToString(), Name = "Race", Email = Email, CreatedAt = now, UpdatedAt = now };
        await using TestDbContext db = _database.CreateContext();
        db.Users.Add(user);
        db.Accounts.Add(new Account
        {
            Id = Guid.CreateVersion7().ToString(),
            AccountId = Email,
            UserId = user.Id,
            ProviderId = "credential",
            PasswordHash = await _fixture.Options.EmailAndPassword.Password.Hash("ValidPass123!"),
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        return user.Id;
    }

    private PasswordResetService CreatePasswordResetService(TestDbContext db) => new(
        Microsoft.Extensions.Options.Options.Create(_fixture.Options),
        _fixture.LoggerFactory,
        db,
        _sessionMock.Object,
        new AuthTokenStore(db),
        _services);

    private EmailVerificationService CreateEmailVerificationService(TestDbContext db) => new(
        Microsoft.Extensions.Options.Options.Create(_fixture.Options),
        _fixture.LoggerFactory,
        db,
        new AuthTokenStore(db),
        _services);

    private SignInService CreateSignInService(TestDbContext db, IRateLimitService rateLimit) => new(
        Microsoft.Extensions.Options.Options.Create(_fixture.Options),
        _fixture.LoggerFactory,
        db,
        _sessionMock.Object,
        new Mock<IEmailVerificationService>(MockBehavior.Strict).Object,
        rateLimit);
}
